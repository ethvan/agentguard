# Log viewer
`agentguard viewer [-o out.html] [--log audit.jsonl] [--open]` renders `.agentguard/audit.jsonl` into one self-contained
HTML file (no server, no network): summary cards, a decision timeline, filters (final verdict, policy verdict, check,
source, free text), click-to-expand rows with redacted arguments and all findings, per-tool block rates, and injection events.

`python viewer/make_demo.py` regenerates `demo.html` from the attack suite for the demo.
Log text is attacker-influenced, so the page builds the DOM with `textContent` only.
