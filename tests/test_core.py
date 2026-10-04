import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from receiptgate import gitstate
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}


class CLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        result = self.runcli("init")
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.repo / "app.txt").write_text("hello")
        self.git("add", "app.txt", "receiptgate.toml", ".gitignore")
        self.git("commit", "-m", "initial")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, stderr=subprocess.DEVNULL)

    def runcli(self, *args, stdin=None):
        return subprocess.run(
            [sys.executable, "-m", "receiptgate", *args],
            cwd=self.repo,
            env=ENV,
            input=stdin,
            text=True,
            capture_output=True,
        )

    def decision(self, command):
        return json.loads(self.runcli("check", "--", command).stdout)

    def test_init_and_rule_cases(self):
        for command, rule in [
            ("git push -f origin main", "R3"),
            ("git push origin HEAD:main", "R3"),
            ("git reset --hard", "R3"),
            ("cat .env", "R4"),
            ("env", "R4"),
            ("rm receiptgate.toml", "R0"),
            ("./deploy.sh | tail -20", "R2"),
            ("pytest || true", "R2"),
            ('bash -c "$CMD"', "SHELL"),
            ('eval "$CMD"', "SHELL"),
        ]:
            with self.subTest(command=command):
                d = self.decision(command)
                self.assertEqual(d["decision"], "deny")
                self.assertEqual(d["rule"], rule)
        for command in [
            "git push origin main-feature",
            'echo "|| true"',
            "cat app.txt",
            "git status",
        ]:
            with self.subTest(command=command):
                self.assertEqual(self.decision(command)["decision"], "allow")

    def test_receipt_invalidated_by_dirty_tree_and_index(self):
        self.assertEqual(self.decision("./deploy.sh")["decision"], "deny")
        p = self.repo / "receiptgate.toml"
        p.write_text(
            p.read_text().replace(
                '"pytest"', json.dumps(shlex.join([sys.executable, "-c", "pass"])) + ', "pytest"'
            )
        )
        self.git("add", "receiptgate.toml")
        self.git("commit", "-m", "policy")
        r = self.runcli("run", "--", sys.executable, "-c", "pass")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.decision("./deploy.sh")["decision"], "allow")
        (self.repo / "app.txt").write_text("changed")
        self.assertEqual(self.decision("./deploy.sh")["decision"], "deny")
        self.git("add", "app.txt")
        self.assertEqual(self.decision("./deploy.sh")["decision"], "deny")

    def test_untracked_fingerprints_and_state_changed_during_runner(self):
        before = gitstate.snapshot(self.repo)
        (self.repo / "new.txt").write_text("first")
        first = gitstate.snapshot(self.repo)
        self.assertFalse(first["clean"])
        self.assertNotEqual(before["tree_hash"], first["tree_hash"])
        (self.repo / "new.txt").write_text("second")
        self.assertNotEqual(first["tree_hash"], gitstate.snapshot(self.repo)["tree_hash"])
        (self.repo / "new.txt").unlink()
        result = self.runcli(
            "run", "--", sys.executable, "-c", "open('app.txt','w').write('changed')"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        row = json.loads((self.repo / ".receiptgate/ledger.jsonl").read_text())
        self.assertFalse(row["eligible"])

    def test_synthetic_pre_stop_and_file_hooks(self):
        payload = {
            "cwd": str(self.repo),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
        }
        for adapter in ["claude", "codex"]:
            r = self.runcli("hook", adapter, "pre", stdin=json.dumps(payload))
            self.assertEqual((r.returncode, json.loads(r.stdout)), (0, {}))
            denied = {**payload, "tool_input": {"command": "cat .env"}}
            r = self.runcli("hook", adapter, "pre", stdin=json.dumps(denied))
            self.assertEqual(r.returncode, 2)
            self.assertEqual(
                json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "deny"
            )
        for name, path in [
            ("Read", ".env"),
            ("Edit", "receiptgate.toml"),
            ("Write", ".codex/hooks.json"),
        ]:
            r = self.runcli(
                "hook",
                "claude",
                "pre",
                stdin=json.dumps(
                    {
                        **payload,
                        "tool_name": name,
                        "tool_input": {"file_path": str(self.repo / path)},
                    }
                ),
            )
            self.assertEqual(r.returncode, 2)
        r = self.runcli(
            "hook",
            "claude",
            "pre",
            stdin=json.dumps(
                {
                    **payload,
                    "tool_name": "Read",
                    "tool_input": {"file_path": str(self.repo / "app.txt")},
                }
            ),
        )
        self.assertEqual(r.returncode, 0)
        r = self.runcli(
            "hook", "codex", "pre", stdin=json.dumps({**payload, "tool_name": "apply_patch"})
        )
        self.assertEqual(r.returncode, 2)
        r = self.runcli(
            "hook",
            "claude",
            "stop",
            stdin=json.dumps({"cwd": str(self.repo), "hook_event_name": "Stop"}),
        )
        self.assertEqual(r.returncode, 2)
        self.assertEqual(json.loads(r.stdout)["decision"], "block")

    def test_git_hook_decisions_and_existing_hook_preserved(self):
        r = self.runcli(
            "hook",
            "git",
            "pre-push",
            stdin="refs/heads/topic " + ("a" * 40) + " refs/heads/main " + ("b" * 40) + "\n",
        )
        self.assertEqual(r.returncode, 2)
        r = self.runcli(
            "hook",
            "git",
            "pre-push",
            stdin="refs/heads/topic " + ("a" * 40) + " refs/heads/topic " + ("b" * 40) + "\n",
        )
        self.assertEqual(r.returncode, 0)
        message = self.repo / ".git/COMMIT_EDITMSG"
        message.write_text("Change\n\nCo-authored-by: Someone\n")
        self.assertEqual(self.runcli("hook", "git", "commit-msg", str(message)).returncode, 2)
        message.write_text("Change\n")
        self.assertEqual(self.runcli("hook", "git", "commit-msg", str(message)).returncode, 0)
        hooks = self.repo / ".git/hooks/pre-push"
        hooks.write_text("#!/bin/sh\nexit 1\n")
        self.assertEqual(self.runcli("install", "git").returncode, 2)
        self.assertEqual(hooks.read_text(), "#!/bin/sh\nexit 1\n")
        self.assertEqual(self.runcli("install", "claude").returncode, 2)
        status = self.runcli("status")
        self.assertEqual(status.returncode, 0)
        self.assertEqual(json.loads(status.stdout)["pushed"], "unknown")

    def test_version_probe_is_not_test_evidence(self):
        result = self.runcli("run", "--", sys.executable, "--version")
        self.assertEqual(result.returncode, 0)
        row = json.loads((self.repo / ".receiptgate/ledger.jsonl").read_text())
        self.assertEqual(row["kind"], "command")
        self.assertEqual(self.decision("./deploy.sh")["decision"], "deny")

    def test_failure_receipt_and_tampering(self):
        self.assertEqual(
            self.runcli("run", "--", sys.executable, "-c", "raise SystemExit(7)").returncode, 7
        )
        ledger = self.repo / ".receiptgate/ledger.jsonl"
        record = json.loads(ledger.read_text())
        self.assertEqual(record["exit_code"], 7)
        self.assertEqual(self.runcli("verify").returncode, 0)
        ledger.write_text(ledger.read_text().replace('"exit_code":7', '"exit_code":0'))
        self.assertEqual(self.runcli("verify").returncode, 2)

    def test_malformed_policy_and_unknown_hook_fail_closed(self):
        (self.repo / "receiptgate.toml").write_text('version = 1\nfail_open = "yes"\n')
        self.assertEqual(self.runcli("check", "--", "echo hi").returncode, 2)
        self.assertEqual(self.runcli("hook", "claude", "pre", stdin="{}").returncode, 2)

    def test_post_hook_never_invents_receipt(self):
        payload = {
            "cwd": str(self.repo),
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "pytest"},
            "tool_response": {"stdout": "passed"},
        }
        r = self.runcli("hook", "claude", "post", stdin=json.dumps(payload))
        self.assertEqual(r.returncode, 2)
        self.assertFalse((self.repo / ".receiptgate/ledger.jsonl").exists())

    def test_policy_tests_and_git_install_idempotence(self):
        self.assertEqual(self.runcli("test").returncode, 0)
        self.assertEqual(self.runcli("install", "git").returncode, 0)
        first = (self.repo / ".git/hooks/pre-push").read_bytes()
        self.assertEqual(self.runcli("install", "git").returncode, 0)
        self.assertEqual((self.repo / ".git/hooks/pre-push").read_bytes(), first)


if __name__ == "__main__":
    unittest.main()
