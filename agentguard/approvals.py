"""Ask-the-user step. Reads from /dev/tty because stdin/stdout carry the MCP protocol."""
from __future__ import annotations

import sys

from .models import Decision, ToolCall
from .secrets import redact


class Approver:
    """mode: 'prompt' (ask on the terminal), 'deny' (fail closed), 'allow' (benchmarking only)."""

    def __init__(self, mode: str = "prompt"):
        self.mode = mode
        self.prompts = 0

    def ask(self, call: ToolCall, decision: Decision) -> tuple[bool, str]:
        if self.mode == "allow":
            return True, "auto-allow"
        if self.mode == "deny":
            return False, "auto-deny"
        self.prompts += 1
        try:
            with open("/dev/tty", "r+") as tty:
                tty.write("\n\u26a0  AgentGuard: approval needed\n")
                tty.write(f"   {call.source}:{call.tool}\n")
                for k, v in redact(call.arguments, 200).items():
                    tty.write(f"   {k}: {v}\n")
                for r in decision.reasons:
                    tty.write(f"   - {r}\n")
                tty.write("   Allow? [y/N] ")
                tty.flush()
                ans = tty.readline().strip().lower()
            ok = ans in {"y", "yes"}
            return ok, "user-allow" if ok else "user-deny"
        except OSError:
            print("AgentGuard: no terminal for approval, denying", file=sys.stderr)
            return False, "no-tty-deny"
