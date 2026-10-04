"""Fsync'd, OS-locked append-only JSON lines with a SHA-256 hash chain.

The chain detects edits/reordering, not rewriting or truncation by its owner.
"""

from contextlib import contextmanager
from pathlib import Path
import hashlib
import json
import os
import sys
import time
from typing import Any, Iterator


class LedgerError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


@contextmanager
def lock(root: Path) -> Iterator[None]:
    directory = root / ".receiptgate"
    directory.mkdir(exist_ok=True)
    if directory.is_symlink():
        raise LedgerError("ledger directory must not be a symlink")
    target = directory / "lock"
    if target.is_symlink():
        raise LedgerError("ledger lock must not be a symlink")
    with target.open("a+b") as f:
        if sys.platform == "win32":
            import msvcrt

            f.seek(0)
            f.write(b"0")
            f.flush()
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if sys.platform == "win32":
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def read(root: Path) -> list[dict[str, Any]]:
    path = root / ".receiptgate/ledger.jsonl"
    if path.is_symlink():
        raise LedgerError("ledger must not be a symlink")
    if not path.exists():
        return []
    data = path.read_bytes()
    if data and not data.endswith(b"\n"):
        raise LedgerError("incomplete final ledger record")
    previous = "0" * 64
    records = []
    for i, line in enumerate(data.splitlines(), 1):
        try:
            row = json.loads(line)
            digest = row.pop("hash")
            if row["prev_hash"] != previous or hashlib.sha256(canonical(row)).hexdigest() != digest:
                raise ValueError("hash mismatch")
            if (
                type(row["exit_code"]) is not int
                or type(row["eligible"]) is not bool
                or not isinstance(row["state"], dict)
                or not isinstance(row["ts"], (float, int))
            ):
                raise ValueError("invalid record schema")
            row["hash"] = digest
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise LedgerError(f"ledger verification failed at line {i}") from exc
        records.append(row)
        previous = digest
    return records


def append(root: Path, record: dict[str, Any]) -> None:
    with lock(root):
        rows = read(root)
        row = {**record, "prev_hash": rows[-1]["hash"] if rows else "0" * 64}
        row["hash"] = hashlib.sha256(canonical(row)).hexdigest()
        path = root / ".receiptgate/ledger.jsonl"
        with path.open("ab") as stream:
            stream.write(canonical(row) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())


def green(rows: list[dict[str, Any]], kind: str, state: dict[str, Any], age: int) -> bool:
    now = time.time()
    return state["clean"] and any(
        row["kind"] == kind
        and row["exit_code"] == 0
        and row["eligible"]
        and row["state"] == state
        and 0 <= now - row["ts"] <= age * 60
        for row in rows
    )
