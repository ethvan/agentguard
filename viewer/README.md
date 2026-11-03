# Log viewer (Nov 5)
Reads `.agentguard/audit.jsonl` (one JSON object per decision; fields: ts, session, call_id,
source, server, tool, arguments [redacted], policy_verdict, final, user_response, findings[], latency_ms).
`agentguard logs` already prints a terminal summary. TODO: a small static HTML page
(filter by verdict/check, timeline, per-tool block rate) for the demo.
