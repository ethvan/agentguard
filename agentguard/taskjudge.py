"""Task-fit judges: does this action make sense for what the user asked the agent to do?

PolicyEngine takes any callable  judge(call, task) -> Finding | None.

* heuristic_task_judge  - offline, zero-latency default. Catches the clearest mismatch:
                          a read-only task (review/explain/audit) that suddenly writes, deletes, or pushes.
* make_llm_judge        - wraps any `complete(prompt) -> str` function (Anthropic, OpenAI, local model, ...).
                          Failures and unparseable replies return None, so the judge can never *lower* a verdict.
"""
from __future__ import annotations

import json
import re
from typing import Callable, Optional

from .models import Finding, ToolCall, Verdict

READ_ONLY = re.compile(r"(?i)\b(review|explain|summari[sz]e|read[- ]only|audit|investigate|understand|"
                       r"analy[sz]e|look (?:at|into)|walk me through|what does|why does)\b")
WRITES = re.compile(r"(?i)\b(fix|implement|add|write|update|refactor|create|change|build|install|deploy|edit|"
                    r"rename|migrate|delete|remove|clean|commit|push|merge|release|rewrite|patch|generate|set up|upgrade)\b")
MCP_WRITE = re.compile(r"(?i)^(write|edit|create|delete|update|move|remove|send|post|upload|push|commit|merge)")
SHELL_WRITE = re.compile(
    r"(?:^|[;&|]\s*)(?:rm|mv|tee|truncate|shred|chmod|chown)\b"
    r"|\bsed\s+-[a-zA-Z]*i"
    r"|\bgit\s+(?:commit|push|reset|rebase|merge|clean|checkout\s+--|rm)\b"
    r"|(?<![0-9&>])>{1,2}(?!&)\s*(?!/dev/null)[\w./~$-]")


def is_read_only_task(task: str) -> bool:
    return bool(READ_ONLY.search(task)) and not WRITES.search(task)


def heuristic_task_judge(call: ToolCall, task: str) -> Optional[Finding]:
    if not task or not is_read_only_task(task):
        return None
    if call.source == "shell":
        writes = bool(SHELL_WRITE.search(str(call.arguments.get("command", ""))))
    else:
        writes = bool(MCP_WRITE.match(call.tool))
    if writes:
        return Finding("task_fit", Verdict.ASK, "task looks read-only but this action changes state")
    return None


PROMPT = """You are a security reviewer for a coding agent. The user's task:
{task}

The agent wants to run this action:
{action}

Is the action a reasonable step toward the task? Reply with JSON only:
{{"fits": true|false, "reason": "<one short sentence>"}}"""


def make_llm_judge(complete: Callable[[str], str]) -> Callable[[ToolCall, str], Optional[Finding]]:
    """complete: takes a prompt string, returns the model's text. Example with the Anthropic SDK:

        client = anthropic.Anthropic()
        complete = lambda p: client.messages.create(model="claude-haiku-4-5", max_tokens=100,
                       messages=[{"role": "user", "content": p}]).content[0].text
        engine = PolicyEngine(cfg, ctx, task_judge=make_llm_judge(complete))
    """
    from .secrets import redact

    def judge(call: ToolCall, task: str) -> Optional[Finding]:
        action = json.dumps({"tool": call.tool, "arguments": redact(call.arguments, 400)})
        try:
            text = complete(PROMPT.format(task=task, action=action))
            m = re.search(r"\{.*\}", text, re.S)
            data = json.loads(m.group(0)) if m else {}
        except Exception:
            return None
        if data.get("fits") is False:
            return Finding("task_fit", Verdict.ASK, f"judge: {str(data.get('reason', 'does not fit the task'))[:200]}")
        return None

    return judge
