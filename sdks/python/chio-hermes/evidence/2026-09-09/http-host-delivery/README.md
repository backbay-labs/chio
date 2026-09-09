# Hermes HTTP delivery candidate

Status: unaccepted. Attempt 6 completed the actual Hermes/OpenAI write, edit,
read and list workflow using a cold-installed wheel and current kernel. The
independent resource observer confirmed the final bytes and four matching
resource dispatches. The private launcher confirmed four deliveries.

Attempts 1-5 retain concrete failures: the macOS Python framework bootstrap
was initially denied; the clean Python runtime had no usable CA roots; Hermes
wrapped MCP text in a result envelope and an untrusted-data delimiter; and
multiple tools in one model turn outran delivery acknowledgement. None is
counted as a complete useful workflow. The fixed relay requests one tool call
per model turn and verifies the host-received outcome before acknowledging.
A blocked sibling call in attempt 5 also exposed a terminal-status gap; the
current launcher retains host-observed non-dispatch failures in its outcome.

The gateway and its journal remain outside the agent process. A private Node
child runs the installed HTTP gateway; its stdin is the parent lifeline. The
guest receives only ephemeral gateway/model authority. The agent has no direct
kernel port, kernel bearer or journal access. Python framework descendants
retain the same file and network boundary. No unrestricted Node child is
allowed. These boundaries still require final adversarial process probes.

Further real-host denials, response loss/restart, approvals, aggregate budgets,
revocation, lifecycle qualification and publication remain required.
