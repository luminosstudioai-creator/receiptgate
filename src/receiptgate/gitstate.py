"""Git plumbing and byte fingerprints; no parsing of human-readable status."""

from pathlib import Path
import hashlib
import subprocess
from typing import Any


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL)


def repository(cwd: Path) -> Path:
    return Path(git(cwd, "rev-parse", "--show-toplevel").decode().strip()).resolve()


def snapshot(root: Path) -> dict[str, Any]:
    flags = git(root, "ls-files", "-v", "-z").split(b"\0")
    if any(entry[:1] != b"H" for entry in flags if entry):
        raise ValueError(
            "nonstandard index visibility flags: clear assume-unchanged/skip-worktree before testing"
        )
    head = git(root, "rev-parse", "HEAD").decode().strip()
    branch = subprocess.run(
        ["git", "symbolic-ref", "--short", "HEAD"], cwd=root, capture_output=True, text=True
    ).stdout.strip()
    staged = git(root, "diff", "--cached", "--binary", "--no-ext-diff", "HEAD")
    unstaged = git(root, "diff", "--binary", "--no-ext-diff")
    untracked = git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    h = hashlib.sha256()
    for data in [staged, unstaged, git(root, "ls-files", "--stage", "-z")]:
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    # Bind actual tracked bytes too; cached Git stat information is not evidence.
    for entry in flags:
        if not entry:
            continue
        name = entry[2:]
        path = root / name.decode(errors="surrogateescape")
        if path.is_dir():
            raise ValueError("submodules are unsupported for state-bound receipts")
        data = str(path.readlink()).encode() if path.is_symlink() else path.read_bytes()
        h.update(len(name).to_bytes(8, "big"))
        h.update(name)
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    extra = False
    for name in sorted(filter(None, untracked)):
        # The evidence directory is intentionally outside the tested state.
        if name.startswith(b".receiptgate/"):
            continue
        extra = True
        p = root / name.decode(errors="surrogateescape")
        data = str(p.readlink()).encode() if p.is_symlink() else p.read_bytes()
        h.update(len(name).to_bytes(8, "big"))
        h.update(name)
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    # Binding policy bytes prevents stale evidence when an ignored policy changes.
    h.update((root / "receiptgate.toml").read_bytes())
    return {
        "head_sha": head,
        "branch": branch,
        "tree_hash": h.hexdigest(),
        "clean": not (staged or unstaged or extra),
    }
