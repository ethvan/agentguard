"""Append-only JSONL audit log. One line per decision."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from .models import Decision, ToolCall
from .secrets import redact


class Auditor:
    def __init__(self, state_dir: Path, session: str):
        self.path = state_dir / "audit.jsonl"
        self.session = session
        self._lock = threading.Lock()
        state_dir.mkdir(parents=True, exist_ok=True)

    def log(self, call: ToolCall, decision: Decision, final: str, user_response: str | None = None) -> None:
        self._write({
            "ts": time.time(), "session": self.session, "call_id": call.call_id,
            "source": call.source, "server": call.server, "tool": call.tool,
            "arguments": redact(call.arguments),
            "policy_verdict": decision.verdict.value, "final": final,
            "user_response": user_response,
            "findings": [{"check": f.check, "verdict": f.verdict.value, "reason": f.reason}
                         for f in decision.findings],
            "latency_ms": round(decision.latency_ms, 3),
        })

    def event(self, kind: str, **fields) -> None:
        self._write({"ts": time.time(), "session": self.session, "event": kind, **fields})

    def _write(self, rec: dict) -> None:
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
