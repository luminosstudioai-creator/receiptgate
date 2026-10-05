# Acceptance record

Local candidate: **0.0.1 alpha**, checked 2026-10-05 on macOS / Python 3.13.11.
This is not the original handoff's completed 0.1 release.

## Passed locally

- 33 unittest methods, including 30 explicit behavior cases for each R0–R4 rule.
- Direct subprocess exit-code preservation and no green receipt for version/help probes.
- Gate closes without evidence, opens after exact successful allowlisted command, closes
  after tracked/untracked/index changes, and refuses evidence if the runner changes state.
- Snapshot rejects assume-unchanged/skip-worktree flags, hashes actual tracked bytes,
  and rejects submodules; both hidden index flags have real Git/CLI regressions.
- SHA/tree/expiry/eligibility receipt matching; corrupted/incomplete ledger rejection;
  12 concurrent OS-locked appenders retain a valid chain.
- Synthetic pre/file/stop JSON decisions, post-hook receipt refusal and unknown-tool refusal.
- Git destination ref checks, commit trailer denial, idempotent installer and preservation
  of pre-existing hooks.
- Independent adversarial findings have regression tests: implicit configured push targets,
  executable path aliases, broad directory removal, git clean, redirection, wrappers,
  leading command options, shell globs/control constructs, secret executable names,
  hidden index flags, empty push destinations, metadata mutation and hardlink aliases.
- Ruff 0.16.10 lint and formatting; mypy 2.4.0 strict, 8 source modules.
- Coverage 7.16.2: aggregate rules/ledger/shell core ≥90% (locally 96%, rounded).
- Build 1.6.1 / Hatchling 1.32.4: wheel and source distribution build successfully.

The unittest method count is separate from the 150 rule-table subcases. No live fixture is
counted as a synthetic test, and no test establishes semantic completeness of an arbitrary
allowlisted command.

## Not run / unsupported

- Real Claude and Codex sessions, Pre/Post/Stop golden captures and blocking proof: NOT RUN.
- Agent auto-install and automatic post-event receipts: UNSUPPORTED in this alpha.
- Nine remote OS/Python CI matrix jobs: NOT RUN locally; workflow source is included.
- 1,000 real hook process invocations with p95 <50ms: NOT RUN.
- Windows locking behavior: NOT RUN locally.
- Stop warn mode, report/SARIF, external signatures/anchors: UNSUPPORTED.
- Fail-open mode: UNSUPPORTED; `fail_open=true` is a policy error, never silently ignored.
- 30-second GIF and comparison/market claims: not included; no fabricated evidence.
- PyPI publishing, version 0.1, blog announcement: NOT DONE.

Git hooks are opt-in and bypassable. The root policy is included for dogfooding; install
hooks only in your own clone using `receiptgate install git`. There is no hidden global
agent configuration change. See README and SECURITY for fingerprint/trust limitations.
