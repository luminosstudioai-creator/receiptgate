"""Deterministic R0-R4 policy decisions."""

from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
from . import shell
from .ledger import green

PROTECTED = [
    "receiptgate.toml",
    ".receiptgate/**",
    ".claude/settings*.json",
    ".codex/hooks.json",
    ".codex/config.toml",
    ".git/**",
]


def matches(value: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(value, pattern) for pattern in patterns)


def relative(root: Path, value: str) -> str:
    path = Path(value)
    resolved = (root / path).resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def protected_path(root: Path, value: str) -> bool:
    normalized = relative(root, value)
    if matches(normalized, PROTECTED) or normalized in [
        ".receiptgate",
        ".claude",
        ".codex",
        ".git",
    ]:
        return True
    candidate = root / value
    if not candidate.is_file():
        return False
    patterns = [
        "receiptgate.toml",
        ".receiptgate/**/*",
        ".claude/settings*.json",
        ".codex/hooks.json",
        ".codex/config.toml",
        ".git/config",
        ".git/index",
        ".git/HEAD",
        ".git/hooks/*",
        ".git/refs/**/*",
    ]
    for pattern in patterns:
        for target in root.glob(pattern):
            if target.is_file() and candidate.samefile(target):
                return True
    return False


def decision(allow: bool, rule: str, reason: str) -> dict[str, str]:
    return {"decision": "allow" if allow else "deny", "rule": rule, "reason": reason}


def path_check(root: Path, path: str, policy: dict[str, Any], write: bool) -> dict[str, str]:
    value = relative(root, path)
    if protected_path(root, path):
        return decision(False, "R0", "Policy, evidence and hook configuration are protected")
    if not write and secret(value, policy):
        return decision(False, "R4", "Protected secret path")
    return decision(True, "OK", "No matching rule")


def secret(path: str, policy: dict[str, Any]) -> bool:
    return matches(path, policy["secrets"]["paths"]) or matches(
        Path(path).name, policy["secrets"]["paths"]
    )


def evaluate(
    root: Path,
    command: str,
    policy: dict[str, Any],
    state: dict[str, Any],
    rows: list[dict[str, Any]],
) -> dict[str, str]:
    try:
        words = shell.tokens(command)
    except shell.ShellError as exc:
        return decision(False, "SHELL", str(exc))
    parts = shell.segments(words)
    normalized = []
    for part in parts:
        executable = Path(part[0]).name
        gate_executable = (
            "./" + executable
            if any(
                pattern.startswith("./" + executable)
                for gate in policy.get("gates", {}).values()
                for pattern in gate["match"]
            )
            else executable
        )
        normalized.append(" ".join([gate_executable, *part[1:]]))
    for word in words:
        if not word or all(c in ";&|<>" for c in word):
            continue
        if protected_path(root, word):
            return decision(False, "R0", "Policy, evidence and hook configuration are protected")
    gated = [
        gate
        for gate in policy.get("gates", {}).values()
        if any(matches(value, gate["match"]) for value in normalized)
    ]
    tested = any(
        value == cmd or value.startswith(cmd + " ")
        for value in normalized
        for commands in policy["receipts"].values()
        for cmd in commands
    )
    operators = [w for w in words if w and all(c in ";&|<>" for c in w)]
    if (gated or tested) and operators:
        return decision(
            False,
            "R2",
            "Receipt commands and gates must be direct: shell operators can mask exit codes",
        )
    for part in parts:
        executable = Path(part[0]).name
        if executable in ["rm", "mv"]:
            for arg in part[1:]:
                target = (root / arg).resolve()
                if not arg.startswith("-") and (
                    target == root.resolve() or target in root.resolve().parents
                ):
                    return decision(
                        False, "R0", "Cannot remove or move a directory containing protected state"
                    )
        if executable in ["printenv", "env"]:
            return decision(False, "R4", "Environment dumps can expose secrets")
        for arg in part[1:]:
            if protected_path(root, arg):
                return decision(
                    False, "R0", "Policy, evidence and hook configuration are protected"
                )
            if executable in [
                "cat",
                "less",
                "more",
                "head",
                "tail",
                "sed",
                "grep",
                "rg",
                "awk",
                "cp",
                "tar",
                "zip",
                "base64",
            ] and secret(relative(root, arg), policy):
                return decision(False, "R4", "Protected secret path")
        if executable == "git":
            # Global git options change the repository/ref context; do not guess it.
            if len(part) < 2 or part[1].startswith("-"):
                return decision(False, "R3", "Git global options require manual review")
            op = part[1]
            protected = policy["branches"]["protected"]
            if op in ["config", "update-index"]:
                return decision(
                    False, "R0", "Git configuration and index visibility require manual review"
                )
            if op in ["show", "cat-file", "grep"]:
                return decision(
                    False, "R4", "Git object reads may expose protected secret contents"
                )
            if op == "clean":
                return decision(False, "R0", "Git clean can remove evidence and policy files")
            current = matches(state["branch"], protected)
            if op == "push":
                refs = [w for w in part[2:] if not w.startswith("-")]
                if any(
                    w.startswith("-") and w not in ["--dry-run", "--porcelain"] for w in part[2:]
                ):
                    return decision(False, "R3", "Push options require manual review")
                if len(refs) < 2:
                    return decision(
                        False,
                        "R3",
                        "Push requires an explicit destination ref; configured defaults are not trusted",
                    )
                destinations = [r.split(":")[-1].removeprefix("refs/heads/") for r in refs[1:]]
                if (len(refs) < 2 and current) or any(
                    not r or matches(r, protected) or r == "HEAD" and current or "*" in r
                    for r in destinations
                ):
                    return decision(False, "R3", "Push to protected branch")
            if op == "reset" and "--hard" in part and current:
                return decision(False, "R3", "Hard reset on protected branch")
            if op == "branch" and any(w in ["-D", "-d", "--delete"] for w in part):
                if any(matches(w, protected) for w in part[2:] if not w.startswith("-")):
                    return decision(False, "R3", "Deleting protected branch")
            if op == "merge" and current and "--ff-only" not in part:
                return decision(False, "R3", "Protected branch merges require --ff-only")
    for gate in gated:
        if not state["clean"]:
            return decision(False, "R1", "Gate requires a clean working tree and index")
        for kind in gate["requires"]:
            if not green(rows, kind, state, gate.get("max_age_minutes", 120)):
                return decision(False, "R1", f"Missing current green {kind} receipt")
    return decision(True, "OK", "No matching denial; original agent permissions still apply")


def kind_for(command: str, policy: dict[str, Any]) -> str:
    for kind, patterns in policy["receipts"].items():
        if command in patterns:
            return str(kind)
    return "command"


def redact(command: str) -> str:
    # Executable names may also contain secrets. Retain no command text at all.
    return "[command redacted]"
