"""Secret detection: known token formats, high-entropy strings, and literal values from the workspace .env."""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "api_key_sk": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "generic_secret": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{16,}"),
}

# Files that usually hold credentials.
SENSITIVE_PATH = re.compile(
    r"(\.ssh(/|$)|\.aws(/|$)|\.gnupg(/|$)|\.kube/config|(^|/)\.env(\.[\w-]+)?$|(^|/)\.env\b|"
    r"\.npmrc|\.netrc|\.git-credentials|\bid_(rsa|ed25519|ecdsa)\b|/etc/shadow|\.pypirc|"
    r"\.docker/config\.json)")


@dataclass
class SecretHit:
    kind: str
    preview: str


def iter_strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from iter_strings(k)
            yield from iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from iter_strings(v)


# ---- entropy ------------------------------------------------------------
# Candidate tokens: long runs of base64/urlsafe characters. Paths and URLs are split by "/" and ":"
# before they get here, which keeps ordinary file paths from looking like keys.
_TOKEN = re.compile(r"[A-Za-z0-9_+=\-]{24,}")
ENTROPY_THRESHOLD = 4.2          # bits/char; random base64 ~5.5+, English/camelCase identifiers ~3.5-3.9


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _is_high_entropy(tok: str) -> bool:
    if re.fullmatch(r"[0-9a-fA-F]+", tok):                 # git SHAs, md5/sha256 digests: not credentials
        return False
    if re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", tok):   # UUIDs
        return False
    classes = (any(c.islower() for c in tok), any(c.isupper() for c in tok), any(c.isdigit() for c in tok))
    if sum(classes) < 2 or sum(c.isdigit() for c in tok) < 3:   # real keys mix letters with several digits
        return False
    return shannon_entropy(tok) >= ENTROPY_THRESHOLD


# ---- values from the workspace .env ------------------------------------
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_BORING_VALUES = {"true", "false", "null", "none", "localhost", "development", "production", "test", "debug", "info"}


def parse_env_values(text: str) -> set[str]:
    """Secret-looking values from KEY=VALUE lines. Skips short values, booleans, plain numbers, and URLs without credentials."""
    out: set[str] = set()
    for line in text.splitlines():
        m = _ENV_LINE.match(line)
        if not m or line.lstrip().startswith("#"):
            continue
        v = m.group(2)
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        elif " #" in v:
            v = v.split(" #", 1)[0].rstrip()
        if len(v) < 8 or v.lower() in _BORING_VALUES or re.fullmatch(r"[\d.:-]+", v):
            continue
        if re.match(r"^https?://[^/@\s]+(/[^@\s]*)?$", v):    # plain URL with no embedded credentials
            continue
        out.add(v)
    return out


class EnvSecrets:
    """Lazily loads secret values from <workspace>/.env and .env.* ; reloads when the files change."""

    def __init__(self, workspace: Path):
        self.workspace = Path(workspace)
        self._sig: tuple = ()
        self._values: set[str] = set()

    def values(self) -> set[str]:
        try:
            files = sorted(p for p in self.workspace.glob(".env*") if p.is_file()
                           and not p.name.endswith((".example", ".sample", ".template")))
            sig = tuple((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in files)
        except OSError:
            return self._values
        if sig != self._sig:
            vals: set[str] = set()
            for p in files:
                try:
                    vals |= parse_env_values(p.read_text(errors="ignore"))
                except OSError:
                    pass
            self._sig, self._values = sig, vals
        return self._values


def scan(obj: Any, env_values: Iterable[str] = (), entropy: bool = True) -> list[SecretHit]:
    """Find secrets in any JSON-ish structure. kinds: a PATTERNS key, 'env_value', or 'high_entropy'."""
    hits: list[SecretHit] = []
    env_values = list(env_values)
    for s in iter_strings(obj):
        covered = False
        for kind, pat in PATTERNS.items():
            for m in pat.finditer(s):
                hits.append(SecretHit(kind, m.group(0)[:4] + "…"))
                covered = True
        for v in env_values:
            if v in s:
                hits.append(SecretHit("env_value", v[:2] + "…"))
                covered = True
        if entropy and not covered:
            for m in _TOKEN.finditer(s):
                if _is_high_entropy(m.group(0)):
                    hits.append(SecretHit("high_entropy", m.group(0)[:4] + "…"))
    return hits


def redact(obj: Any, max_len: int = 500, env_values: Iterable[str] = ()) -> Any:
    """Deep copy with secrets masked and long strings truncated (for audit logs)."""
    if isinstance(obj, str):
        for kind, pat in PATTERNS.items():
            obj = pat.sub(f"[REDACTED:{kind}]", obj)
        for v in env_values:
            obj = obj.replace(v, "[REDACTED:env_value]")
        obj = _TOKEN.sub(lambda m: "[REDACTED:high_entropy]" if _is_high_entropy(m.group(0)) else m.group(0), obj)
        return obj if len(obj) <= max_len else obj[:max_len] + f"…(+{len(obj) - max_len})"
    if isinstance(obj, dict):
        return {k: redact(v, max_len, env_values) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v, max_len, env_values) for v in obj]
    return obj


INJECTION_HINTS = re.compile(
    r"(?i)(ignore (all |any )?(previous|prior|above) (instructions|prompts)|disregard (the )?(system|previous)|"
    r"you are now|new instructions:|do not (tell|inform) the user|send .{0,40}(to|at) https?://)")


def looks_like_injection(text: str) -> bool:
    return bool(INJECTION_HINTS.search(text))
