# Contributing

Use Python 3.11+ and an isolated virtual environment. Install `.[dev]` and run the commands
in README before submitting a change. Add a failing regression test first for stale evidence,
policy ambiguity or a shell bypass. Keep the runtime dependency-free.

Do not call synthetic JSON a captured agent fixture. Do not promote an agent adapter until
its real payload and blocking behavior are tested. Never weaken fail-closed handling to
make a demo look green. Explain what an evidence claim does and does not establish.

Only stage the files you own. No generated caches, ledger data, secrets or attribution
trailers in commits. Pull requests should state the behavior change and exact checks run.
