"""Wires config, engine, auditor and approver together for both interceptors."""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .approvals import Approver
from .audit import Auditor
from .models import Decision, SessionContext, ToolCall, Verdict
from .policy import PolicyConfig, PolicyEngine, load_config


@dataclass
class Runtime:
    engine: PolicyEngine
    auditor: Auditor
    approver: Approver

    def decide(self, call: ToolCall) -> tuple[bool, Decision, str]:
        """Evaluate, ask the user if needed, log. Returns (allowed, decision, message_if_blocked)."""
        d = self.engine.evaluate(call)
        user = None
        if d.verdict == Verdict.ALLOW:
            allowed = True
        elif d.verdict == Verdict.BLOCK:
            allowed = False
        else:
            allowed, user = self.approver.ask(call, d)
        self.auditor.log(call, d, "allow" if allowed else "block", user)
        msg = ""
        if not allowed:
            why = "; ".join(d.reasons) or "policy"
            who = "denied by user" if d.verdict == Verdict.ASK else "blocked by policy"
            msg = (f"AgentGuard {who}: {why}. Do not retry this action; "
                   f"tell the user what you were trying to do and why.")
        return allowed, d, msg


def build_runtime(config: Optional[Path] = None, task: str = "", on_ask: Optional[str] = None) -> Runtime:
    cfg: PolicyConfig = load_config(config)
    state_dir = Path(os.environ.get("AGENTGUARD_STATE", cfg.workspace / ".agentguard"))
    ctx = SessionContext(state_dir=state_dir, workspace=cfg.workspace,
                         task=task or os.environ.get("AGENTGUARD_TASK", ""),
                         taint_ttl=cfg.taint_ttl)
    ctx.refresh()
    engine = PolicyEngine(cfg, ctx)
    mode = on_ask or os.environ.get("AGENTGUARD_ON_ASK") or cfg.on_ask
    return Runtime(engine, Auditor(state_dir, uuid.uuid4().hex[:8], engine.env.values), Approver(mode))
