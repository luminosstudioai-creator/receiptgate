"""Strict versioned TOML policy. Unknown keys are errors, never ignored."""

from pathlib import Path
import tomllib
from typing import Any

DEFAULT = """version = 1
fail_open = false
[branches]
protected = ["main", "release/*"]
[secrets]
paths = [".env", ".env.*", "*.pem", "id_*", "secrets/**"]
[receipts]
test = ["pytest", "npm test", "make test", "python -m unittest discover -s tests -v"]
build = ["npm run build"]
[gates.deploy]
match = ["./deploy.sh*", "npm publish*", "kubectl apply*"]
requires = ["test"]
max_age_minutes = 120
[gates.merge]
match = ["git merge*"]
requires = ["test"]
max_age_minutes = 120
[[test]]
command = "git push --force origin main"
expect = "deny"
rule = "R3"
[[test]]
command = "./deploy.sh | tail -20"
expect = "deny"
rule = "R2"
[[test]]
command = "cat .env"
expect = "deny"
rule = "R4"
"""


class PolicyError(ValueError):
    pass


def keys(obj: Any, allowed: set[str], context: str) -> dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) - allowed:
        raise PolicyError(f"{context}: expected table with keys {sorted(allowed)}")
    return obj


def strings(value: Any, context: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(v, str) or not v for v in value)
    ):
        raise PolicyError(f"{context}: expected nonempty list of nonempty strings")
    return value


def load(root: Path) -> dict[str, Any]:
    p = keys(
        tomllib.loads((root / "receiptgate.toml").read_text()),
        {"version", "fail_open", "branches", "secrets", "receipts", "gates", "test", "agents"},
        "policy",
    )
    if type(p.get("version")) is not int or p["version"] != 1:
        raise PolicyError("version must be 1")
    if type(p.get("fail_open", False)) is not bool:
        raise PolicyError("fail_open must be a boolean")
    if p.get("fail_open") is True:
        raise PolicyError("fail_open=true is unsupported in this alpha")
    for section, field in [("branches", "protected"), ("secrets", "paths")]:
        table = keys(p.get(section, {}), {field}, section)
        strings(table.get(field), f"{section}.{field}")
    receipts = keys(p.get("receipts", {}), {"test", "build"}, "receipts")
    for name, patterns in receipts.items():
        strings(patterns, f"receipts.{name}")
        if any(any(c in command for c in "*?[]") for command in patterns):
            raise PolicyError("receipt commands must be exact, without glob patterns")
    if not isinstance(p.get("gates", {}), dict):
        raise PolicyError("gates must be a table")
    for name, gate in p.get("gates", {}).items():
        keys(gate, {"match", "requires", "max_age_minutes"}, f"gates.{name}")
        strings(gate.get("match"), f"gates.{name}.match")
        for kind in strings(gate.get("requires"), f"gates.{name}.requires"):
            if kind not in receipts:
                raise PolicyError(f"gates.{name}: unknown receipt kind {kind}")
        age = gate.get("max_age_minutes", 120)
        if type(age) is not int or age <= 0:
            raise PolicyError("max_age_minutes must be a positive integer")
    if not isinstance(p.get("test", []), list):
        raise PolicyError("test must be an array")
    for case in p.get("test", []):
        keys(case, {"command", "expect", "rule"}, "test")
        if (
            not isinstance(case.get("command"), str)
            or case.get("expect") not in ["allow", "deny"]
            or not isinstance(case.get("rule"), str)
        ):
            raise PolicyError("invalid policy test")
    for name, value in keys(p.get("agents", {}), {"claude", "codex"}, "agents").items():
        if type(value) is not bool:
            raise PolicyError(f"agents.{name} must be boolean")
    return p
