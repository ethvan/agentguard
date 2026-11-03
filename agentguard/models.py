"""Shared data types."""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Verdict(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return {"allow": 0, "ask": 1, "block": 2}[self.value]


def strictest(verdicts) -> Verdict:
    return max(verdicts, key=lambda v: v.rank, default=Verdict.ALLOW)


@dataclass
class ToolCall:
    source: str                 # "mcp" | "shell"
    tool: str                   # MCP tool name, or "shell.exec"
    arguments: dict
    server: str = ""
    call_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])


@dataclass
class Finding:
    check: str                  # permission | task_fit | egress | taint | shell
    verdict: Verdict
    reason: str


@dataclass
class Decision:
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    latency_ms: float = 0.0

    @property
    def reasons(self) -> list[str]:
        return [f"[{f.check}] {f.reason}" for f in self.findings]


@dataclass
class SessionContext:
    """State shared by the MCP proxy and shell guard via .agentguard/session.json.

    Lets the 'was this triggered by untrusted content?' question work across
    both interceptors: the proxy marks the session tainted when a tool result
    arrives, and the shell guard sees it.
    """
    state_dir: Path
    workspace: Path
    task: str = ""
    taint_ttl: float = 1800.0
    untrusted_at: float = 0.0
    untrusted_sources: list[str] = field(default_factory=list)

    @property
    def _file(self) -> Path:
        return self.state_dir / "session.json"

    @property
    def untrusted_seen(self) -> bool:
        return self.untrusted_at > 0 and (time.time() - self.untrusted_at) < self.taint_ttl

    def mark_untrusted(self, source: str) -> None:
        self.untrusted_at = time.time()
        if source not in self.untrusted_sources:
            self.untrusted_sources = (self.untrusted_sources + [source])[-10:]
        self._save()

    def refresh(self) -> None:
        try:
            data = json.loads(self._file.read_text())
            self.untrusted_at = max(self.untrusted_at, float(data.get("untrusted_at", 0)))
            for s in data.get("sources", []):
                if s not in self.untrusted_sources:
                    self.untrusted_sources.append(s)
        except (OSError, ValueError):
            pass

    def reset(self) -> None:
        self.untrusted_at = 0.0
        self.untrusted_sources = []
        self._save()

    def _save(self) -> None:
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            tmp = self._file.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps({"untrusted_at": self.untrusted_at,
                                       "sources": self.untrusted_sources}))
            tmp.replace(self._file)
        except OSError:
            pass
