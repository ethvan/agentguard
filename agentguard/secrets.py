"""Secret detector (v0). Nov 5 milestone: add entropy scoring + .env value matching."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator

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


def scan(obj: Any) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for s in iter_strings(obj):
        for kind, pat in PATTERNS.items():
            for m in pat.finditer(s):
                hits.append(SecretHit(kind, m.group(0)[:4] + "…"))
    return hits


def redact(obj: Any, max_len: int = 500) -> Any:
    """Deep copy with secrets masked and long strings truncated (for audit logs)."""
    if isinstance(obj, str):
        for kind, pat in PATTERNS.items():
            obj = pat.sub(f"[REDACTED:{kind}]", obj)
        return obj if len(obj) <= max_len else obj[:max_len] + f"…(+{len(obj) - max_len})"
    if isinstance(obj, dict):
        return {k: redact(v, max_len) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v, max_len) for v in obj]
    return obj


INJECTION_HINTS = re.compile(
    r"(?i)(ignore (all |any )?(previous|prior|above) (instructions|prompts)|disregard (the )?(system|previous)|"
    r"you are now|new instructions:|do not (tell|inform) the user|send .{0,40}(to|at) https?://)")


def looks_like_injection(text: str) -> bool:
    return bool(INJECTION_HINTS.search(text))
