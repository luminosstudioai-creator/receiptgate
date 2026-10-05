# Acceptance record

Local candidate: **0.0.1 alpha**, checked 2026-10-05 on macOS / Python 3.13.11.
This is not the original handoff's completed 0.1 release.

## Passed locally

- 40 unittest methods, including 30 explicit behavior cases for each R0–R4 rule.
- Direct subprocess exit-code preservation and no green receipt for version/help probes.
- Gate closes without evidence, opens after exact successful allowlisted command, closes
  after tracked/untracked/index changes, and refuses evidence if the runner changes state.
- Snapshot rejects assume-unchanged/skip-worktree flags, hashes actual tracked bytes,
  and rejects submodules; both hidden index flags have real Git/CLI regressions.
- SHA/tree/expiry/eligibility receipt matching; corrupted/incomplete ledger rejection;
  12 concurrent OS-locked appenders retain a valid chain.
- Synthetic pre/file/stop JSON decisions, post-hook receipt refusal and unknown-tool refusal.
- Git destination ref checks, commit trailer denial, idempotent installer and preservation
  of pre-existing hooks. Actual installed pre-push hook execution against a local bare
  remote blocks `main` and permits `topic`; this does not use a network or an agent session.
- Actual Git-effect regressions block `git rm '*'` and `git rm -r .` before deleting the
  policy or tracked app file. `git add` wildcard/magic/directory/implicit forms leave root
  `.env` and nested protected token files unstaged; explicit regular `app.txt` staging works.
- 90 Git pathspec table cases cover ten operations and nine wildcard/magic selections.
- Direct argv preserves backslash paths and literal operator/expansion-looking arguments;
  they cannot inherit test receipt classification. Shared wrappers/protected executable
  checks still deny indirect execution and protected Git pushes, including `.exe` names.
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

## Remote checks and performance

The first real CI matrix at `124eb7dc85aed5270d4f20528186698d8b3dfbe1` completed:
Linux/macOS × Python 3.11–3.13: **6 PASS**; Windows × Python 3.11–3.13: **3 FAIL**.
The Windows log shows five direct-run tests returning 2 instead of observed process exit
codes and one POSIX-shell table path reporting SHELL instead of R0. Native backslash paths
were accidentally round-tripped through the restricted Bash parser.

The current branch keeps direct argv separate from shell text, uses shared executable/rule
checks, writes portable Git-Bash hook paths and quotes POSIX table paths. The argv fix at
`2483e62b22b2912287db927c8d3576d1dbe124fa` then
[passed all nine matrix jobs](https://github.com/luminosstudioai-creator/receiptgate/actions/runs/37282071299).
The current Git-pathspec selection guard remains **pending its own remote CI verification**;
local passing checks are not substituted for that new-head result.

The [raw hook benchmark](benchmarks/hook-latency-2026-10-05.json) at `124eb7d`
ran 1,000 standalone hook processes on macOS / Python 3.13.11 with synthetic PreToolUse
input and a three-file repository. Median 123.84ms, p95 130.27ms: **FAIL** against p95
<50ms. This was a real subprocess benchmark, not a live agent session. It does not describe
large-repository performance. This fix does not attempt a latency optimization.

## Not run / unsupported

- Real Claude and Codex sessions, Pre/Post/Stop golden captures and blocking proof: NOT RUN.
- Agent auto-install and automatic post-event receipts: UNSUPPORTED in this alpha.
- Remote CI verification of the current Git-pathspec guard: PENDING.
- Windows locking unit tests passed in the follow-up matrix at `2483e62`; live-agent and
  production use remain NOT RUN.
- Stop warn mode, report/SARIF, external signatures/anchors: UNSUPPORTED.
- Fail-open mode: UNSUPPORTED; `fail_open=true` is a policy error, never silently ignored.
- 30-second GIF and comparison/market claims: not included; no fabricated evidence.
- PyPI publishing, version 0.1, blog announcement: NOT DONE.

Git hooks are opt-in and bypassable. The root policy is included for dogfooding; install
hooks only in your own clone using `receiptgate install git`. There is no hidden global
agent configuration change. See README and SECURITY for fingerprint/trust limitations.
