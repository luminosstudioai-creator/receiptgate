# Adapter evidence and limits

Checked 2026-10-05 against the installed runtimes:

- `codex --version`: codex-cli 0.159.2
- `claude --version`: 2.1.201 (Claude Code)

Official references:

- [Claude hook reference](https://code.claude.com/docs/en/hooks)
- [Codex hook reference](https://learn.chatgpt.com/docs/hooks)

Claude's PostToolUse example uses `tool_response`, whose shape depends on the tool.
The handoff's generic `tool_output.exit_code` assumption was not verified. The Codex
reference did not establish a shared `exit_code` contract. Consequently neither post
adapter mints green evidence. No paid model session was launched and no live payload was
captured. Tests use synthetic input and are not represented as golden live fixtures.

The pre handler checks a strict PreToolUse event, repository cwd and Bash/Read/Edit/Write
input. Unknown tools and malformed input return exit 2. Denials include a PreToolUse
permissionDecision JSON; allows emit only `{}`. Stop checks a current green test receipt.
Other event shapes are unsupported. Neither agent installer is implemented, and no local
or global agent configuration was changed.

Before claiming support for a particular runtime, capture real Pre/Post/Stop payloads in
an isolated toy repository, redact them, verify that exit 2 truly blocks, test every file
edit mechanism and tool name, and check a failed command whose shell exit is masked.
