# Security policy

Receiptgate is an alpha workflow aid, not a sandbox, authentication system or hostile-agent
security boundary. Do not use it as the sole control for production deployment or secrets.

For vulnerabilities, use the repository owner's GitHub profile contact or private security
reporting when enabled. Do not publish credentials, real secret files or exploit payloads
containing private data. A security contact email is not invented here.

## Boundaries

- A user who can write the ledger can regenerate its hashes or truncate it. There is no
  external anchor, signature, HMAC or trusted service.
- Fingerprints cover HEAD, the index, tracked diffs, nonignored untracked content and policy
  bytes. They exclude ignored files, dependencies, external files and process environment.
- Before/after snapshots cannot detect a temporary change and revert or lock the tested
  state against changes after the gate is checked.
- Shell checks are conservative heuristics for a restricted grammar, not semantic analysis
  of arbitrary programs. Scripts and interpreters can perform hidden actions.
- Rule checks and runner execution are not atomic. Git hooks can be bypassed or replaced.
- All command text (including executable names) is omitted from receipts. Process output is never stored, but is
  visible to the invoking terminal. The runner cannot redact another program's live output.
- Symlink evidence paths are rejected, but this is not protection against a same-user race
  replacing paths between the check and filesystem operation.

Report reproducible false-negative checks, stale receipt acceptance, concurrency corruption
or sensitive-data retention with a minimal toy repository. Never attach production secrets.
