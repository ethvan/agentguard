"""agentguard CLI: mcp-proxy | check | logs | viewer | init | reset"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .models import ToolCall
from .policy import DEFAULT_TOML
from .runtime import build_runtime


def cmd_proxy(a) -> int:
    from .mcp_proxy import McpProxy
    if not a.upstream:
        print("usage: agentguard mcp-proxy [opts] -- <server command...>", file=sys.stderr)
        return 2
    up = a.upstream[1:] if a.upstream[0] == "--" else a.upstream
    rt = build_runtime(a.config, a.task, a.on_ask)
    return McpProxy(up, rt, a.name).run()


def cmd_check(a) -> int:
    """Dry-run a shell command or MCP tool call through the policy (no execution)."""
    rt = build_runtime(a.config, a.task, "deny")
    if a.tool:
        call = ToolCall("mcp", a.tool, json.loads(a.command or "{}"))
    else:
        call = ToolCall("shell", "shell.exec", {"command": a.command})
    d = rt.engine.evaluate(call)
    print(d.verdict.value.upper(), f"({d.latency_ms:.2f} ms)")
    for r in d.reasons:
        print("  -", r)
    return 0 if d.verdict.value == "allow" else 1


def cmd_logs(a) -> int:
    rt = build_runtime(a.config)
    path = rt.auditor.path
    if not path.exists():
        print("no audit log yet:", path)
        return 0
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    calls = [r for r in rows if "final" in r]      # events (injection flags etc.) can carry a "tool" too
    for r in calls[-a.n:]:
        why = r["findings"][0]["reason"] if r["findings"] else ""
        print(f'{r["call_id"]} {r["source"]:5} {r["tool"][:24]:24} {r["final"]:5} {why}')
    c = Counter(r["final"] for r in calls)
    lat = sorted(r["latency_ms"] for r in calls) or [0]
    prompts = sum(1 for r in calls if r["policy_verdict"] == "ask")
    print(f"\n{len(calls)} calls | allow {c['allow']} block {c['block']} | prompts {prompts} "
          f"| median policy latency {lat[len(lat)//2]:.2f} ms")
    return 0


def cmd_viewer(a) -> int:
    from . import viewer
    src = Path(a.log) if a.log else build_runtime(a.config).auditor.path
    if not src.exists():
        print("no audit log yet:", src)
        return 1
    out = Path(a.output)
    n = viewer.write(src, out)
    print(f"wrote {out} ({n} decisions)")
    if a.open:
        import webbrowser
        webbrowser.open(out.resolve().as_uri())
    return 0


def cmd_init(a) -> int:
    p = Path("agentguard.toml")
    if p.exists():
        print("agentguard.toml already exists")
        return 1
    p.write_text(DEFAULT_TOML)
    print("wrote agentguard.toml")
    return 0


def cmd_reset(a) -> int:
    build_runtime(a.config).engine.ctx.reset()
    print("taint cleared")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="agentguard")
    ap.add_argument("--config", type=Path, default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("mcp-proxy", help="wrap an MCP server")
    p.add_argument("--task", default="")
    p.add_argument("--name", default="mcp")
    p.add_argument("--on-ask", choices=["prompt", "deny", "allow"])
    p.add_argument("upstream", nargs=argparse.REMAINDER)
    p.set_defaults(fn=cmd_proxy)

    p = sub.add_parser("check", help="dry-run a command (or --tool NAME with JSON args)")
    p.add_argument("command", nargs="?")
    p.add_argument("--tool")
    p.add_argument("--task", default="")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("logs", help="show recent decisions and summary")
    p.add_argument("-n", type=int, default=20)
    p.set_defaults(fn=cmd_logs)
    p = sub.add_parser("viewer", help="render the audit log as a static HTML page")
    p.add_argument("-o", "--output", default="agentguard-log.html")
    p.add_argument("--log", help="audit.jsonl to read (default: this workspace's)")
    p.add_argument("--open", action="store_true", help="open in the browser")
    p.set_defaults(fn=cmd_viewer)
    sub.add_parser("init", help="write a starter agentguard.toml").set_defaults(fn=cmd_init)
    sub.add_parser("reset", help="clear taint state").set_defaults(fn=cmd_reset)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
