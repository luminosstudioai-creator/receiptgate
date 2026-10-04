"""CLI and experimental hook translation. All errors use blocking exit code 2."""

import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time
from typing import Any
from . import gitstate, ledger, policy, rules


def emit(value: Any) -> None:
    print(json.dumps(value, sort_keys=True))


def clean_args(args: list[str]) -> list[str]:
    return args[1:] if args[:1] == ["--"] else args


def install_git(root: Path) -> None:
    hooks = Path(gitstate.git(root, "rev-parse", "--git-path", "hooks").decode().strip())
    if not hooks.is_absolute():
        hooks = root / hooks
    hooks.mkdir(exist_ok=True)
    executable = shlex.quote(sys.executable)
    for name in ["pre-push", "commit-msg"]:
        path = hooks / name
        text = f'#!/bin/sh\n# receiptgate managed hook\nexec {executable} -m receiptgate hook git {name} "$@"\n'
        if path.exists() and path.read_text() != text:
            raise ValueError(f"{name} already exists; refusing to replace an existing hook")
        path.write_text(text)
        path.chmod(0o755)


def hook(
    root: Path, adapter: str, event: str, extra: list[str], p: dict[str, Any], state: dict[str, Any]
) -> int:
    if adapter == "git":
        if event == "commit-msg":
            if len(extra) != 1:
                raise ValueError("commit-msg requires message path")
            if "co-authored-by:" in Path(extra[0]).read_text().lower():
                raise ValueError("Co-authored-by trailers are forbidden by this hook")
            return 0
        if event != "pre-push":
            raise ValueError("unknown git event")
        # Git supplies exact destination refs on stdin, not a shell command.
        for line in sys.stdin:
            fields = line.split()
            if len(fields) != 4:
                raise ValueError("invalid pre-push input")
            destination = fields[2].removeprefix("refs/heads/")
            if rules.matches(destination, p["branches"]["protected"]):
                raise ValueError("R3: push to protected branch")
        return 0
    if adapter not in ["claude", "codex"]:
        raise ValueError("unsupported adapter")
    if p.get("agents", {}).get(adapter, True) is False:
        raise ValueError("adapter disabled by policy")
    payload = json.load(sys.stdin)
    if not isinstance(payload, dict) or not isinstance(payload.get("cwd"), str):
        raise ValueError("hook requires cwd")
    if gitstate.repository(Path(payload["cwd"])) != root:
        raise ValueError("hook repository differs from invocation repository")
    if event == "post":
        raise ValueError("PostToolUse is not verified exit-code evidence; use receiptgate run")
    if event == "stop":
        if payload.get("hook_event_name") != "Stop":
            raise ValueError("wrong hook event")
        if not ledger.green(ledger.read(root), "test", state, 120):
            emit(
                {
                    "decision": "block",
                    "reason": "Missing current green test receipt; run tests through receiptgate run",
                }
            )
            return 2
        return 0
    if event != "pre" or payload.get("hook_event_name") != "PreToolUse":
        raise ValueError("unsupported or mismatched event")
    name = payload.get("tool_name")
    tool = payload.get("tool_input")
    if not isinstance(tool, dict) or not isinstance(name, str):
        raise ValueError("invalid tool input")
    if name == "Bash":
        if not isinstance(tool.get("command"), str):
            raise ValueError("Bash requires command")
        d = rules.evaluate(root, tool["command"], p, state, ledger.read(root))
    elif name in ["Read", "Edit", "Write"]:
        if not isinstance(tool.get("file_path"), str):
            raise ValueError("file tool requires file_path")
        d = rules.path_check(root, tool["file_path"], p, name != "Read")
    else:
        # In particular apply_patch has agent/version dependent schemas.
        raise ValueError("unverified tool schema; use direct CLI checks")
    if d["decision"] == "deny":
        emit(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": d["rule"] + ": " + d["reason"],
                }
            }
        )
        print(d["rule"] + ": " + d["reason"], file=sys.stderr)
        return 2
    # Do not emit permissionDecision=allow, which bypasses native approval prompts.
    emit({})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="State-bound command receipts. No telemetry. No runtime dependencies."
    )
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("init")
    for name in ["check", "run"]:
        item = sub.add_parser(name)
        item.add_argument("command", nargs=argparse.REMAINDER)
    for name in ["verify", "test", "status"]:
        sub.add_parser(name)
    item = sub.add_parser("install")
    item.add_argument("adapter", choices=["git", "claude", "codex"])
    item = sub.add_parser("hook")
    item.add_argument("adapter")
    item.add_argument("event")
    item.add_argument("extra", nargs="*")
    args = parser.parse_args(argv)
    try:
        root = gitstate.repository(Path.cwd())
        if args.action == "init":
            target = root / "receiptgate.toml"
            if target.exists():
                raise ValueError("receiptgate.toml already exists")
            target.write_text(policy.DEFAULT)
            ignore = root / ".gitignore"
            text = ignore.read_text() if ignore.exists() else ""
            if ".receiptgate/" not in text.splitlines():
                ignore.write_text(
                    text + ("" if not text or text.endswith("\n") else "\n") + ".receiptgate/\n"
                )
            emit({"initialized": str(target)})
            return 0
        p = policy.load(root)
        state = gitstate.snapshot(root)
        if args.action == "verify":
            with ledger.lock(root):
                rows = ledger.read(root)
            emit(
                {
                    "verified_records": len(rows),
                    "integrity": "hash-chain only; truncation and full rewrite need an external anchor",
                }
            )
            return 0
        if args.action == "status":
            rows = ledger.read(root)
            emit(
                {
                    "state": state,
                    "green_test": ledger.green(rows, "test", state, 120),
                    "receipts": len(rows),
                    "pushed": "unknown",
                    "deployed": "unknown",
                }
            )
            return 0
        if args.action == "test":
            failures = []
            for case in p.get("test", []):
                d = rules.evaluate(root, case["command"], p, state, [])
                if d["decision"] != case["expect"] or d["rule"] != case["rule"]:
                    failures.append({"expected": case, "actual": d})
            emit({"cases": len(p.get("test", [])), "failures": failures})
            return 2 if failures else 0
        if args.action == "install":
            if args.adapter != "git":
                raise ValueError(
                    "agent installation unavailable until live payload capture; see docs/adapters.md"
                )
            install_git(root)
            emit({"installed": "git", "hooks": ["pre-push", "commit-msg"]})
            return 0
        if args.action == "hook":
            return hook(root, args.adapter, args.event, args.extra, p, state)
        command_args = clean_args(args.command)
        if not command_args:
            raise ValueError("command required after --")
        command = (
            command_args[0]
            if args.action == "check" and len(command_args) == 1
            else shlex.join(command_args)
        )
        d = rules.evaluate(root, command, p, state, ledger.read(root))
        if args.action == "check":
            emit(d)
            return 0 if d["decision"] == "allow" else 2
        if d["decision"] == "deny":
            emit(d)
            return 2
        start = time.monotonic()
        result = subprocess.run(command_args, cwd=root, check=False)
        after = gitstate.snapshot(root)
        canonical_command = shlex.join(command_args)
        ledger.append(
            root,
            {
                "ts": time.time(),
                "agent": "runner",
                "command": rules.redact(command),
                "kind": rules.kind_for(canonical_command, p),
                "exit_code": result.returncode,
                "duration_ms": round((time.monotonic() - start) * 1000),
                "state": state,
                "eligible": state == after and state["clean"],
            },
        )
        return result.returncode if result.returncode >= 0 else 128 - result.returncode
    except (Exception, KeyboardInterrupt) as exc:
        # No raw command/payload or exception value: those can contain secrets.
        print(
            f"receiptgate blocked: {type(exc).__name__}; check policy, repository and evidence integrity",
            file=sys.stderr,
        )
        return 2
