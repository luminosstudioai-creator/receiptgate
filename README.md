# receiptgate

[![Checks](https://github.com/luminosstudioai-creator/receiptgate/actions/workflows/ci.yml/badge.svg)](https://github.com/luminosstudioai-creator/receiptgate/actions/workflows/ci.yml)

**Your agent says the tests passed. Keep evidence for the code it actually tested.**

A small local command runner and policy checker. Successful allowlisted commands become receipts bound to
Git HEAD, the index, tracked changes, untracked files and the policy. Change that state and
a deploy gate closes again. Python 3.11+, zero runtime dependencies, no telemetry.

**Alpha, version 0.0.1.** This is a working core, not a security boundary or a completed
Claude/Codex integration. The [acceptance record](docs/acceptance.md) separates tested
features from the original handoff's remaining release requirements.

## Try it

Install from this checkout in a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
# In your own Git repository (with at least one commit):
receiptgate init
# Review the generated receiptgate.toml, set your test command, and commit it.
git add receiptgate.toml .gitignore
git commit -m "Add local receipt policy"
receiptgate check -- './deploy.sh'        # R1: missing current green test receipt
receiptgate run -- pytest                # real process exit code; receipt appended
receiptgate check -- './deploy.sh'        # allowed if tests passed and state stayed clean
receiptgate verify
receiptgate status
```

`check` never executes the command and interprets its input as restricted POSIX/Bash shell
text, including on Windows. It does not interpret PowerShell or cmd syntax. `run` checks
and executes the original argument vector directly, without a shell. Backslashes and
operator-like argument strings remain literal data; they are never reparsed as shell code.
Known wrappers, leading option aliases and protected operations use the same rule checks
in both interfaces. Git's own wildcard/magic pathspecs, directories and implicit file
selection also require manual review. `git add`, `rm` and `restore` accept only explicit
existing regular files and supported options; ordinary `git add app.txt` remains usable. Windows `.exe` names share the corresponding executable checks.
Batch `.bat`/`.cmd` files and shell interpreters require manual review and are denied. A passing process is eligible evidence only when the before/after snapshots
match and the starting tree is clean. Test commands that generate untracked files must
ignore those outputs deliberately. Commit the policy before collecting release evidence.

## What closes a gate

| Rule | Behavior |
|---|---|
| R0 | Protect policy, ledger and agent/Git metadata paths from direct file and command access |
| R1 | Require recent green receipts of each configured kind for the exact clean state |
| R2 | Reject operators in receipt/gate commands: pipelines and chained success can mask errors |
| R3 | Protect branch destinations, refspecs, destructive operations and merge mode |
| R4 | Block common secret reads and environment dumps |
| SHELL | Reject indirect execution, substitutions, variables, heredocs and compound syntax |

Rules are deterministic. Shell support is deliberately restricted and can reject safe
commands. Operator-only quoted arguments can also be conservatively rejected. Ordinary quoted text such as `echo "|| true"` remains data. Python programs,
scripts, aliases and executables can do arbitrary things; this tool does not inspect their
code. Configure exact commands and use your existing sandbox and agent permissions.

## Inspect and test your policy

```toml
[gates.deploy]
match = ["./deploy.sh*", "npm publish*"]
requires = ["test", "build"]
max_age_minutes = 120

[[test]]
command = "git push --force origin main"
expect = "deny"
rule = "R3"
```

See the [reference policy](examples/receiptgate.toml). Unknown keys, unknown required
receipt kinds, wrong types and malformed TOML fail closed. `receiptgate test` checks
embedded policy examples; it does not run those commands. `fail_open=true` is intentionally
unsupported in this alpha. Errors always return 2; successful commands/checks return 0;
a failed wrapped process preserves its nonnegative exit code.

## Integration status

- **Direct runner:** tested with real subprocess success, failure and state invalidation.
- **Git:** `receiptgate install git` adds pre-push and commit-msg hooks, idempotently.
  Existing hooks are preserved by refusing replacement. Run from an installed environment;
  the hook uses its Python executable. No pre-commit hook is installed.
- **Claude/Codex:** experimental `hook <adapter> pre|stop` schema handlers. No automatic
  agent installation, no real-session compatibility claim, no live golden fixtures.
- **Post hooks:** rejected. A successful tool event is not proof of shell exit code zero.
  Use `receiptgate run` for evidence. Unsupported tools (including apply_patch) fail closed.

Allowed pre-hooks output `{}` so they do not bypass the agent's own approval controls.
See [adapter evidence](docs/adapters.md) before connecting an agent.

## Trust model

The ledger is OS-locked and fsync'd. Its hash chain detects accidental edits and reordering.
It is **not signed**: the same user can rewrite the chain, truncate its tail, delete it or
bypass the hooks. It cannot prove that a configured test meaningfully tested anything.
Command text, arguments and process output are not retained; no command text is recorded, including executable names.
Output still goes to the terminal, so underlying commands may expose secrets there.

Receipt kinds use exact argument vectors, not prefix globs. A successful version/help or
collection-only invocation cannot inherit the default test classification. Owners can still
configure meaningless commands; receipts prove an observed exit code, not test semantics.

Snapshots exclude Git-ignored paths, the evidence directory and environmental dependencies.
Assume-unchanged/skip-worktree index flags and submodules are rejected rather than
accepted as clean evidence. Existing protected-file hardlink aliases are checked by inode.
They detect lasting changes, not a transient change followed by restoration between
snapshots. The checker also cannot make the interval between checking and deployment
atomic. Hostile concurrent writers require a stronger sandbox/trust model.
See [SECURITY.md](SECURITY.md).

## Development

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/coverage run -m unittest discover -s tests
.venv/bin/coverage combine
.venv/bin/coverage report --include="*/rules.py,*/ledger.py,*/shell.py" --fail-under=90
```

The CI matrix covers Python 3.11–3.13 across Linux, macOS and Windows. Its first run at
`124eb7d` passed six Linux/macOS jobs and failed all three Windows jobs. The argv fix at
`2483e62` subsequently [passed all nine jobs](https://github.com/luminosstudioai-creator/receiptgate/actions/runs/37282071299).
The current Git-pathspec guard still awaits its own remote verification. The measured 1,000-process hook benchmark failed the p95 <50ms target
(p95 130.3ms on that earlier commit). Details and raw benchmark data are recorded in
[docs/acceptance.md](docs/acceptance.md).

Apache-2.0 · Copyright 2026 Mika Mischke
