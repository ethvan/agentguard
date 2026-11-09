"""Policy engine: runs the four checks from the proposal and combines them.

  1. Does this action fit the user's task?      -> _check_task_fit
  2. Does this agent need this permission?      -> _check_permission
  3. Is sensitive data leaving?                 -> _check_egress
  4. Was this triggered by untrusted content?   -> _check_taint
"""
from __future__ import annotations

import os
import re
import time
import tomllib
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Callable, Optional

from . import secrets
from .models import Decision, Finding, SessionContext, ToolCall, Verdict, strictest
from .shellparse import ShellAnalysis, analyze
from .taskjudge import heuristic_task_judge

EGRESS_TOOL = re.compile(r"(?i)(send|post|upload|http|fetch|email|webhook|publish|comment|push|request)")

DEFAULT_TOML = '''\
[general]
workspace = "."          # directory the agent is allowed to touch
on_ask = "prompt"        # prompt | deny | allow
taint_ttl_seconds = 1800

[tools]                  # fnmatch patterns on MCP tool names; deny > ask > allow
allow = ["read_*", "list_*", "get_*", "search_*"]
ask = ["write_*", "edit_*", "create_*", "delete_*", "*send*", "*post*", "*upload*"]
deny = []
default = "ask"          # for tools matching nothing above
trusted_results = []     # tools whose output does NOT taint the session

[network]
allowed_hosts = ["github.com", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org"]

[paths]
allowed_outside_workspace = ["/tmp", "/dev/null", "/usr", "/bin"]

# Optional per-tool argument rules. Table name is an fnmatch pattern on the tool name.
#   allowed        = argument names the tool may receive (others -> ask)
#   required       = argument names that must be present (missing -> ask)
#   max_length     = per-argument max string length (longer -> ask; stops bulk exfiltration)
#   deny_patterns  = regexes; any string argument matching -> block
# [args."send_email"]
# allowed = ["to", "subject", "body"]
# max_length = { body = 2000 }
# deny_patterns = ["(?i)password"]
'''


@dataclass
class PolicyConfig:
    workspace: Path = field(default_factory=Path.cwd)
    on_ask: str = "prompt"
    taint_ttl: float = 1800.0
    allow: list[str] = field(default_factory=lambda: ["read_*", "list_*", "get_*", "search_*"])
    ask: list[str] = field(default_factory=lambda: ["write_*", "edit_*", "create_*", "delete_*", "*send*", "*post*", "*upload*"])
    deny: list[str] = field(default_factory=list)
    default: str = "ask"
    trusted_results: list[str] = field(default_factory=list)
    allowed_hosts: list[str] = field(default_factory=lambda: ["github.com", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org"])
    allowed_paths: list[str] = field(default_factory=lambda: ["/tmp", "/dev/null", "/usr", "/bin"])
    arg_rules: dict[str, dict] = field(default_factory=dict)     # fnmatch tool pattern -> rule (see _check_args)


def load_config(path: Optional[Path]) -> PolicyConfig:
    cfg = PolicyConfig()
    if path is None and Path("agentguard.toml").exists():
        path = Path("agentguard.toml")
    if path is None:
        return cfg
    data = tomllib.loads(Path(path).read_text())
    g, t, n, p = (data.get(k, {}) for k in ("general", "tools", "network", "paths"))
    cfg.workspace = (Path(path).parent / g.get("workspace", ".")).resolve()
    cfg.on_ask = g.get("on_ask", cfg.on_ask)
    cfg.taint_ttl = float(g.get("taint_ttl_seconds", cfg.taint_ttl))
    cfg.allow, cfg.ask, cfg.deny = t.get("allow", cfg.allow), t.get("ask", cfg.ask), t.get("deny", cfg.deny)
    cfg.default = t.get("default", cfg.default)
    cfg.trusted_results = t.get("trusted_results", [])
    cfg.allowed_hosts = n.get("allowed_hosts", cfg.allowed_hosts)
    cfg.allowed_paths = p.get("allowed_outside_workspace", cfg.allowed_paths)
    cfg.arg_rules = data.get("args", {})
    return cfg


def _match(tool: str, patterns: list[str]) -> bool:
    return any(fnmatch(tool, p) for p in patterns)


PATH_KEYS = {"path", "file", "filepath", "file_path", "filename", "dir", "directory",
             "cwd", "source", "destination", "target", "src", "dest"}

# Hook for the "fits the task" question. Plug in an LLM or embedding judge later:
#   judge(call, task) -> Finding | None
TaskJudge = Callable[[ToolCall, str], Optional[Finding]]


class PolicyEngine:
    def __init__(self, cfg: PolicyConfig, ctx: SessionContext, task_judge: TaskJudge | None = None):
        self.cfg, self.ctx = cfg, ctx
        self.task_judge = task_judge or heuristic_task_judge
        self.workspace = Path(os.path.realpath(cfg.workspace))
        self.env = secrets.EnvSecrets(self.workspace)

    # ---- public -------------------------------------------------------
    def evaluate(self, call: ToolCall) -> Decision:
        t0 = time.perf_counter()
        self.ctx.refresh()
        analysis = analyze(call.arguments.get("command", "")) if call.source == "shell" else None
        findings: list[Finding] = []
        for check in (self._check_permission, self._check_task_fit,
                      self._check_egress, self._check_taint):
            findings += check(call, analysis)
        verdict = strictest(f.verdict for f in findings)
        return Decision(verdict, findings, (time.perf_counter() - t0) * 1000)

    def observe_result(self, tool: str, text: str) -> bool:
        """Call when a tool result returns. Marks session tainted; returns True if it looks like an injection."""
        if not _match(tool, self.cfg.trusted_results):
            self.ctx.mark_untrusted(f"tool_result:{tool}")
        return secrets.looks_like_injection(text)

    # ---- checks -------------------------------------------------------
    def _check_permission(self, call, analysis) -> list[Finding]:
        if call.source == "shell":
            return [Finding("shell", v, r) for v, r in analysis.findings]
        if _match(call.tool, self.cfg.deny):
            return [Finding("permission", Verdict.BLOCK, f"tool '{call.tool}' is denied by policy")]
        out: list[Finding] = []
        if _match(call.tool, self.cfg.ask):
            out.append(Finding("permission", Verdict.ASK, f"tool '{call.tool}' needs approval"))
        elif not _match(call.tool, self.cfg.allow):
            v = Verdict(self.cfg.default)
            if v != Verdict.ALLOW:
                out.append(Finding("permission", v, f"tool '{call.tool}' is not in the allow list"))
        return out + self._check_args(call)

    def _check_args(self, call) -> list[Finding]:
        """Per-tool argument rules from [args.<pattern>] (a poor man's schema)."""
        out: list[Finding] = []
        args = call.arguments if isinstance(call.arguments, dict) else {}
        for pattern, rule in self.cfg.arg_rules.items():
            if not fnmatch(call.tool, pattern):
                continue
            if "allowed" in rule:
                extra = sorted(set(args) - set(rule["allowed"]))
                if extra:
                    out.append(Finding("schema", Verdict.ASK, f"unexpected argument(s) for {call.tool}: {', '.join(extra)}"))
            missing = [k for k in rule.get("required", []) if k not in args]
            if missing:
                out.append(Finding("schema", Verdict.ASK, f"missing required argument(s): {', '.join(missing)}"))
            for k, limit in (rule.get("max_length") or {}).items():
                v = args.get(k)
                if isinstance(v, str) and len(v) > int(limit):
                    out.append(Finding("schema", Verdict.ASK, f"argument '{k}' is {len(v)} chars (limit {limit})"))
            for pat in rule.get("deny_patterns", []):
                try:
                    rx = re.compile(pat)
                except re.error:
                    continue
                if any(rx.search(x) for x in secrets.iter_strings(args)):
                    out.append(Finding("schema", Verdict.BLOCK, f"argument matches denied pattern {pat!r}"))
        return out

    def _check_task_fit(self, call, analysis) -> list[Finding]:
        out: list[Finding] = []
        for raw in self._paths(call, analysis):
            p = self._resolve(raw)
            inside = p == self.workspace or self.workspace in p.parents
            if secrets.SENSITIVE_PATH.search(str(p)):
                v = Verdict.ASK if inside else Verdict.BLOCK
                out.append(Finding("task_fit", v, f"touches credential file {raw}"))
            elif not inside and not any(str(p) == a or str(p).startswith(a.rstrip("/") + "/")
                                        for a in self.cfg.allowed_paths):
                out.append(Finding("task_fit", Verdict.ASK, f"path outside workspace: {raw}"))
        if self.task_judge and self.ctx.task:
            f = self.task_judge(call, self.ctx.task)
            if f:
                out.append(f)
        return out

    def _check_egress(self, call, analysis) -> list[Finding]:
        out: list[Finding] = []
        egress = analysis.has_network if analysis else bool(EGRESS_TOOL.search(call.tool))
        hits = secrets.scan(call.arguments, self.env.values())
        if hits:
            kinds = ", ".join(sorted({h.kind for h in hits}))
            # Known formats and literal .env values are near-certain: block on egress. Entropy alone is a
            # guess (hashes, IDs, minified blobs), so it only ever asks.
            sure = any(h.kind != "high_entropy" for h in hits)
            v = Verdict.BLOCK if (egress and sure) else Verdict.ASK
            if not egress and not sure:
                v = None
            if v is not None:
                out.append(Finding("egress", v, f"secret material in arguments ({kinds})"))
        if analysis:
            if analysis.has_network and analysis.has_sensitive_read:
                out.append(Finding("egress", Verdict.BLOCK, "reads credentials and uses the network in one command"))
            if analysis.has_network:
                bad = [h for h in analysis.hosts if not self._host_ok(h)]
                if bad or not analysis.hosts:
                    out.append(Finding("egress", Verdict.ASK,
                                       f"network access to {', '.join(bad) or 'unknown destination'}"))
        return out

    def _check_taint(self, call, analysis) -> list[Finding]:
        if not self.ctx.untrusted_seen:
            return []
        if analysis is not None:
            sensitive = analysis.risky
        else:
            sensitive = bool(EGRESS_TOOL.search(call.tool)) or _match(call.tool, self.cfg.ask)
        if not sensitive:
            return []
        src = ", ".join(self.ctx.untrusted_sources[-3:]) or "untrusted content"
        return [Finding("taint", Verdict.ASK, f"sensitive action after untrusted content ({src})")]

    # ---- helpers ------------------------------------------------------
    def _paths(self, call, analysis) -> list[str]:
        if analysis is not None:
            return analysis.paths
        found: list[str] = []

        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k.lower() in PATH_KEYS and isinstance(v, str):
                        found.append(v)
                    else:
                        walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(call.arguments)
        return found

    def _resolve(self, raw: str) -> Path:
        s = os.path.expanduser(os.path.expandvars(raw))
        if not os.path.isabs(s):
            s = os.path.join(self.workspace, s)
        return Path(os.path.realpath(s))

    def _host_ok(self, host: str) -> bool:
        return any(host == a or host.endswith("." + a) for a in self.cfg.allowed_hosts)
