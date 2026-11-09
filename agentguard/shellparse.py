"""Static analysis of shell command lines. No execution; pure parsing + heuristics.

Known gaps (fuzz targets): variable indirection (a=cu; b=rl; $a$b), here-docs,
aliases/functions, encoded payloads. The fuzzer in fuzz/ measures these.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field

from .models import Verdict
from .secrets import SENSITIVE_PATH

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
FETCHERS = {"curl", "wget"}
NETWORK_CMDS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "sftp",
                "rsync", "ssh", "ftp", "telnet"}
INTERPRETERS = {"python", "python3", "node", "ruby", "perl", "php"}
PRIVILEGE = {"sudo", "su", "doas"}
WRAPPERS = {"env", "command", "nohup", "time", "exec", "nice", "xargs"}
INSTALLERS = {"pip", "pip3", "npm", "yarn", "pnpm", "cargo", "gem", "go", "uv", "poetry"}
INSTALL_VERBS = {"install", "add", "i", "get"}
INLINE_NET = re.compile(r"urllib|requests\.|socket|http\.client|fetch\(|XMLHttpRequest|net\.connect|https?://")
URL_HOST = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/@\s]+@)?([^/:\s]+)")


@dataclass
class ShellAnalysis:
    findings: list[tuple[Verdict, str]] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    has_network: bool = False
    has_sensitive_read: bool = False
    installs: bool = False             # installs a named package (supply-chain risk after untrusted content)

    def add(self, verdict: Verdict, reason: str) -> None:
        self.findings.append((verdict, reason))

    def merge(self, o: "ShellAnalysis") -> None:
        self.findings += o.findings
        self.paths += o.paths
        self.hosts += o.hosts
        self.commands += o.commands
        self.has_network |= o.has_network
        self.has_sensitive_read |= o.has_sensitive_read
        self.installs |= o.installs

    @property
    def risky(self) -> bool:
        return bool(self.findings) or self.has_network or self.has_sensitive_read or self.installs


def _substitutions(cmd: str) -> list[str]:
    """Bodies of $(...), <(...), >(...) (balanced, so nesting works) and `...`."""
    out: list[str] = []
    for m in re.finditer(r"`([^`]*)`", cmd):
        out.append(m.group(1))
    for m in re.finditer(r"(?:\$|<|>)\(", cmd):
        depth, i = 1, m.end()
        while i < len(cmd) and depth:
            depth += {"(": 1, ")": -1}.get(cmd[i], 0)
            i += 1
        out.append(cmd[m.end():i - 1] if depth == 0 else cmd[m.end():])
    return out


def split_segments(cmd: str) -> list[tuple[str, str]]:
    """Quote-aware split on ; | & && || newline. Returns (operator_before, text)."""
    segs: list[tuple[str, str]] = []
    buf: list[str] = []
    quote: str | None = None
    op = ""
    i, n = 0, len(cmd)

    def flush(new_op: str) -> None:
        nonlocal op
        text = "".join(buf).strip()
        buf.clear()
        if text:
            segs.append((op, text))
        op = new_op

    while i < n:
        c = cmd[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"' and i + 1 < n:
                buf.append(cmd[i + 1])
                i += 1
        elif c in "'\"":
            quote = c
            buf.append(c)
        elif c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(cmd[i + 1])
            i += 1
        elif cmd.startswith(("&&", "||"), i):
            flush(cmd[i:i + 2])
            i += 1
        elif c == "&" and ((i > 0 and cmd[i - 1] in "<>") or cmd[i + 1:i + 2] == ">"):
            buf.append(c)                      # 2>&1, &>file
        elif c in ";|&\n":
            flush(c)
        else:
            buf.append(c)
        i += 1
    flush("")
    return segs


def _strip_prefix(argv: list[str]) -> list[str]:
    while argv:
        if argv[0] in {"{", "(", "!", "then", "do", "else"}:
            argv = argv[1:]
        elif re.match(r"^[A-Za-z_]\w*=", argv[0]):
            argv = argv[1:]
        elif os.path.basename(argv[0]) in WRAPPERS:
            w = os.path.basename(argv[0])
            argv = argv[1:]
            while argv and argv[0].startswith("-"):
                argv = argv[1:]
            if w == "env" and not any(not re.match(r"^[A-Za-z_]\w*=", t) for t in argv):
                return ["printenv"]
        else:
            break
    return argv


def _looks_like_path(tok: str) -> bool:
    return tok.startswith(("/", "~", "./", "../", "$HOME", "${HOME}")) or tok == ".."


def analyze(cmdline: str, depth: int = 0) -> ShellAnalysis:
    a = ShellAnalysis()
    if depth > 3:
        a.add(Verdict.ASK, "command nesting too deep to analyze")
        return a
    if "/dev/tcp/" in cmdline or "/dev/udp/" in cmdline:
        a.has_network = True
        a.add(Verdict.BLOCK, "raw network socket via /dev/tcp")
    if re.search(r"<\(\s*(curl|wget)\b", cmdline):
        a.add(Verdict.BLOCK, "executes remote download via process substitution")
    if "${IFS" in cmdline or "$IFS" in cmdline:
        a.add(Verdict.ASK, "IFS-based obfuscation")
    if re.search(r"(?:^|[\s;&|(])(?:source|\.|bash|sh|zsh|dash|ksh)\s+<\(", cmdline):
        a.add(Verdict.ASK, "executes the output of a process substitution")
    # $(...), `...` and <(...) / >(...) all run their contents: analyze them as commands
    for inner in _substitutions(cmdline):
        a.merge(analyze(inner, depth + 1))

    # function definitions and brace groups just wrap commands: `f() { cmd; }; f`, `function f { cmd; }`
    cmdline = re.sub(r"(?:\bfunction\s+)?\b[\w.-]+\s*\(\)\s*\{|\bfunction\s+[\w.-]+\s*\{", " ", cmdline)
    prev_cmd = ""
    for op, seg in split_segments(cmdline):
        try:
            argv = shlex.split(seg, posix=True)
        except ValueError:
            a.add(Verdict.ASK, "unparseable command (unbalanced quotes)")
            continue
        argv = _strip_prefix(argv)
        if not argv:
            continue
        cmd, args = os.path.basename(argv[0]), argv[1:]
        a.commands.append(cmd)
        _classify(a, cmd, args, argv, op, prev_cmd, depth)
        _collect_tokens(a, cmd, args)
        prev_cmd = cmd
    return a


def _collect_tokens(a: ShellAnalysis, cmd: str, args: list[str]) -> None:
    is_net = cmd in NETWORK_CMDS
    for tok in args:
        tok = re.sub(r"^\d*[<>]+", "", tok)            # redirection prefix
        if tok.startswith("-") and "=" in tok:
            tok = tok.split("=", 1)[1]
        if is_net:
            m = URL_HOST.match(tok)
            if m:
                a.hosts.append(m.group(1).lower())
        if SENSITIVE_PATH.search(tok):
            a.has_sensitive_read = True
        if tok and _looks_like_path(tok):
            a.paths.append(tok)


def _classify(a: ShellAnalysis, cmd: str, args: list[str], argv: list[str],
              op: str, prev_cmd: str, depth: int) -> None:
    if cmd in NETWORK_CMDS or (cmd == "git" and args[:1] == ["push"]):
        a.has_network = True

    sub = next((t for t in args if not t.startswith("-")), "")
    if cmd == "python" or cmd == "python3":
        if args[:2] == ["-m", "pip"]:
            cmd, args = "pip", args[2:]
            sub = next((t for t in args if not t.startswith("-")), "")
    if cmd in INSTALLERS and sub in INSTALL_VERBS:
        pkgs = [t for t in args[args.index(sub) + 1:] if not t.startswith("-")]
        flags = [t for t in args if t.startswith("-")]
        local_only = not pkgs or all(t in {".", "./"} or t.startswith(("./", "../")) for t in pkgs)
        if any(f in {"-r", "--requirement", "-e", "--editable"} for f in flags) and local_only:
            local_only = True
        reqfile = any(f in {"-r", "--requirement"} for f in flags)
        if not (local_only or reqfile):
            a.installs = True
        for t in args:
            m = URL_HOST.match(t)
            if m:
                a.has_network = True
                a.hosts.append(m.group(1).lower())
                a.installs = True

    if op == "|" and cmd in SHELLS:
        if prev_cmd in FETCHERS:
            a.add(Verdict.BLOCK, "pipes a remote download straight into a shell")
        else:
            a.add(Verdict.ASK, "pipes data into a shell")

    if cmd in SHELLS | {"source", ".", "eval"} and "<<<" in args:      # here-string: the string is a script
        i = args.index("<<<")
        if i + 1 < len(args):
            a.merge(analyze(args[i + 1], depth + 1))
        a.add(Verdict.ASK, "script fed to a shell via here-string")

    if cmd in SHELLS and "-c" in args:
        i = args.index("-c")
        if i + 1 < len(args):
            a.merge(analyze(args[i + 1], depth + 1))

    if cmd in INTERPRETERS:
        for flag in ("-c", "-e", "-r"):
            if flag in args and args.index(flag) + 1 < len(args):
                code = args[args.index(flag) + 1]
                a.add(Verdict.ASK, f"inline code via {cmd} {flag}")
                if SENSITIVE_PATH.search(code):
                    a.has_sensitive_read = True
                if INLINE_NET.search(code):
                    a.has_network = True
                break

    if cmd in PRIVILEGE:
        a.add(Verdict.ASK, f"privilege escalation via {cmd}")
    if cmd == "eval":
        a.add(Verdict.ASK, "eval of dynamic string")
    if argv[0].startswith("$"):
        a.add(Verdict.ASK, "command name comes from a variable")

    if cmd in {"printenv", "env"} and not args:
        a.has_sensitive_read = True
        a.add(Verdict.ASK, "dumps the environment (may contain secrets)")

    if cmd == "rm" and any(re.match(r"^-[a-zA-Z]*[rR]", t) or t == "--recursive" for t in args):
        targets = [t for t in args if not t.startswith("-")]
        if any(t in {"/", "/*", "~", "~/", "$HOME", "${HOME}", "*"} for t in targets):
            a.add(Verdict.BLOCK, "recursive delete of root/home")
        else:
            a.add(Verdict.ASK, "recursive delete")
    if cmd.startswith("mkfs") or (cmd == "dd" and any(t.startswith("of=/dev/") for t in args)):
        a.add(Verdict.BLOCK, "writes directly to a block device")
    if cmd == "chmod" and "-R" in args and any(t in {"777", "a+rwx"} for t in args):
        a.add(Verdict.ASK, "recursive world-writable chmod")
