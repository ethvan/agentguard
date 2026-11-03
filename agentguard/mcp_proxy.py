"""MCP stdio proxy.

    agent  <--stdio-->  AgentGuard  <--stdio-->  real MCP server

MCP's stdio transport is newline-delimited JSON-RPC 2.0. We forward everything
untouched except `tools/call` requests, which go through the policy engine first.
Blocked calls get a normal tool result with isError=true, so the agent sees a
refusal it can reason about instead of a protocol failure.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from typing import Any

from .models import ToolCall
from .runtime import Runtime
from .secrets import iter_strings, looks_like_injection

LIST_MARK = "__tools_list__"


class McpProxy:
    def __init__(self, upstream_cmd: list[str], rt: Runtime, server_name: str = "mcp"):
        self.cmd, self.rt, self.server = upstream_cmd, rt, server_name
        self.proc: subprocess.Popen | None = None
        self._out_lock = threading.Lock()
        self._pending: dict[Any, str] = {}      # request id -> tool name | LIST_MARK
        self._pending_lock = threading.Lock()

    # ---- lifecycle ----------------------------------------------------
    def run(self) -> int:
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=None, text=True, encoding="utf-8", bufsize=1)
        threading.Thread(target=self._pump_upstream, daemon=True).start()
        try:
            for line in sys.stdin:
                self._on_client_line(line)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        return self.proc.wait()

    # ---- client -> upstream ------------------------------------------
    def _on_client_line(self, line: str) -> None:
        if not line.strip():
            return
        try:
            msg = json.loads(line)
        except ValueError:
            return self._to_upstream(line.rstrip("\n"))
        if isinstance(msg, list):                               # JSON-RPC batch
            kept = [m for m in (self._filter(x) for x in msg) if m is not None]
            if kept:
                self._to_upstream(json.dumps(kept))
            return
        out = self._filter(msg)
        if out is not None:
            self._to_upstream(json.dumps(out))

    def _filter(self, msg: Any) -> Any | None:
        """Return the message to forward, or None if it was handled/blocked here."""
        if not isinstance(msg, dict):
            return msg
        method, mid = msg.get("method"), msg.get("id")
        if method == "tools/list" and mid is not None:
            self._set_pending(mid, LIST_MARK)
        if method != "tools/call":
            return msg
        params = msg.get("params") or {}
        call = ToolCall("mcp", str(params.get("name", "")), params.get("arguments") or {}, self.server)
        allowed, _, blocked_msg = self.rt.decide(call)
        if allowed:
            if mid is not None:
                self._set_pending(mid, call.tool)
            return msg
        if mid is not None:
            self._to_client({"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": blocked_msg}], "isError": True}})
        return None

    # ---- upstream -> client ------------------------------------------
    def _pump_upstream(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
                for m in (msg if isinstance(msg, list) else [msg]):
                    self._observe(m)
            except ValueError:
                pass
            self._write_client(line if line.endswith("\n") else line + "\n")
        sys.stdout.flush()
        os._exit(self.proc.wait())          # upstream died: end the session

    def _observe(self, m: Any) -> None:
        if not isinstance(m, dict) or "method" in m or "id" not in m:
            return
        with self._pending_lock:
            kind = self._pending.pop(m["id"], None)
        if kind is None:
            return
        result = m.get("result") or {}
        text = "\n".join(iter_strings(result))
        if kind == LIST_MARK:
            # Tool descriptions are attacker-controllable ("tool poisoning").
            if looks_like_injection(text):
                self.rt.auditor.event("tool_description_suspicious", server=self.server)
                self.rt.engine.ctx.mark_untrusted("tools/list")
            return
        if self.rt.engine.observe_result(kind, text):
            self.rt.auditor.event("result_looks_like_injection", tool=kind)

    # ---- io -----------------------------------------------------------
    def _set_pending(self, mid: Any, kind: str) -> None:
        with self._pending_lock:
            self._pending[mid] = kind

    def _to_upstream(self, line: str) -> None:
        assert self.proc and self.proc.stdin
        try:
            self.proc.stdin.write(line + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    def _to_client(self, obj: Any) -> None:
        self._write_client(json.dumps(obj) + "\n")

    def _write_client(self, s: str) -> None:
        with self._out_lock:
            sys.stdout.write(s)
            sys.stdout.flush()
