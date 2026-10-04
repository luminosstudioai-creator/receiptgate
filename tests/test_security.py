import multiprocessing
import tempfile
import time
import unittest
from pathlib import Path
from receiptgate import ledger, policy, rules, shell

STATE = {"head_sha": "a" * 40, "branch": "main", "tree_hash": "b" * 64, "clean": True}


def writer(directory, index):
    ledger.append(
        Path(directory),
        {
            "ts": time.time(),
            "exit_code": 0,
            "eligible": True,
            "state": STATE,
            "kind": "test",
            "index": index,
        },
    )


class Security(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "receiptgate.toml").write_text(policy.DEFAULT)
        self.policy = policy.load(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, command):
        return rules.evaluate(self.root, command, self.policy, STATE, [])

    def test_shell_bypasses_deny(self):
        cases = [
            'true; bash -c "./deploy.sh"',
            "X=1 ./deploy.sh",
            "( ./deploy.sh )",
            "{ ./deploy.sh; }",
            'true && eval "./deploy.sh"',
            "true; source deploy.sh",
            "true; env X=y ./deploy.sh",
            "git -C /tmp push origin main",
            "git push origin +HEAD:main",
            "git push origin :main",
            "git push origin refs/heads/topic:refs/heads/main",
            "git push --all",
            "git push --mirror",
            "git push --delete origin main",
            "git push origin HEAD",
            "git branch --delete main",
            "git merge topic",
            "git push origin main:release/next",
            "cat secrets/key",
            "head keys/service.pem",
            "cat ./.env",
            "cat " + str(self.root / ".env"),
        ]
        for command in cases:
            with self.subTest(command=command):
                self.assertEqual(self.check(command)["decision"], "deny")

    def test_invalid_shell_grammar(self):
        for command in [
            "",
            "   ",
            "echo x\ncat .env",
            "echo \x00",
            'echo "unterminated',
            "cat <<EOF",
            "echo `id`",
            "echo $HOME",
            "echo \\x",
        ]:
            with self.subTest(command=command):
                with self.assertRaises(shell.ShellError):
                    shell.tokens(command)

    def test_ledger_rejects_malformed_and_symlink_lock(self):
        directory = self.root / ".receiptgate"
        directory.mkdir()
        (directory / "ledger.jsonl").write_text("not JSON\n")
        with self.assertRaises(ledger.LedgerError):
            ledger.read(self.root)
        (directory / "lock").symlink_to(self.root / "receiptgate.toml")
        with self.assertRaises(ledger.LedgerError):
            ledger.append(self.root, {})
        (directory / "lock").unlink()
        (directory / "ledger.jsonl").unlink()
        directory.rmdir()
        directory.symlink_to(self.root / "other", target_is_directory=True)
        (self.root / "other").mkdir()
        with self.assertRaises(ledger.LedgerError):
            ledger.append(self.root, {})

    def test_glob_and_control_prefixes_fail_closed(self):
        for command in [
            "rm -rf *",
            "rm -rf ./?",
            "rm -rf [a-z]*",
            "if true; then ./deploy.sh; fi",
            "! ./deploy.sh",
            "for x in deploy.sh; do $x; done",
        ]:
            with self.subTest(command=command):
                self.assertEqual(self.check(command)["decision"], "deny")

    def test_wrapped_and_option_shifted_commands_deny(self):
        for command in [
            "nice git push origin HEAD:main",
            "nice ./deploy.sh",
            "timeout 10 ./deploy.sh",
            "/usr/bin/time ./deploy.sh",
            "npm --prefix /tmp publish",
            "kubectl --context prod apply -f x",
            "nohup ./deploy.sh",
            "stdbuf -oL ./deploy.sh",
        ]:
            with self.subTest(command=command):
                self.assertEqual(self.check(command)["decision"], "deny")

    def test_review_regressions(self):
        for command in [
            "rm -rf .",
            "rm -rf ..",
            "git clean -fdx",
            "git push origin",
            str(self.root / "deploy.sh"),
            "/usr/bin/npm publish",
            "git merge --ff-only topic",
        ]:
            with self.subTest(command=command):
                self.assertEqual(self.check(command)["decision"], "deny")
        self.assertNotIn("FAKE_SECRET", rules.redact("/tmp/customer_FAKE_SECRET run"))

    def test_implicit_push_on_topic_is_denied(self):
        self.assertEqual(
            rules.evaluate(
                self.root, "git push origin", self.policy, {**STATE, "branch": "topic"}, []
            )["decision"],
            "deny",
        )

    def test_receipt_classification_exact_only(self):
        for command in [
            "pytest --version",
            "pytest --help",
            "pytest --collect-only",
            "pytest -k nonexistent",
            "npm test -- --help",
            "make test --dry-run",
        ]:
            with self.subTest(command=command):
                self.assertEqual(rules.kind_for(command, self.policy), "command")
        self.assertEqual(rules.kind_for("pytest", self.policy), "test")

    def test_fail_open_true_is_rejected_not_ignored(self):
        (self.root / "receiptgate.toml").write_text(
            policy.DEFAULT.replace("fail_open = false", "fail_open = true")
        )
        with self.assertRaises(policy.PolicyError):
            policy.load(self.root)

    def test_redaction_discards_arbitrary_secret_arguments(self):
        self.assertNotIn("FAKE_SECRET", rules.redact("echo FAKE_SECRET"))

    def test_age_and_sha_and_eligibility(self):
        row = {
            "ts": time.time(),
            "kind": "test",
            "exit_code": 0,
            "eligible": True,
            "state": dict(STATE),
        }
        self.assertTrue(ledger.green([row], "test", STATE, 120))
        for change in [
            {"ts": time.time() - 8000},
            {"ts": time.time() + 100},
            {"exit_code": 1},
            {"eligible": False},
            {"state": {**STATE, "head_sha": "c" * 40}},
            {"state": {**STATE, "tree_hash": "d" * 64}},
        ]:
            with self.subTest(change=change):
                self.assertFalse(ledger.green([{**row, **change}], "test", STATE, 120))
        self.assertFalse(ledger.green([row], "test", {**STATE, "clean": False}, 120))

    def test_concurrent_writers_keep_chain(self):
        context = multiprocessing.get_context("spawn")
        processes = [context.Process(target=writer, args=(str(self.root), i)) for i in range(12)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(15)
            self.assertEqual(process.exitcode, 0)
        rows = ledger.read(self.root)
        self.assertEqual({r["index"] for r in rows}, set(range(12)))

    def test_truncated_record_and_symlink_rejected(self):
        writer(str(self.root), 0)
        p = self.root / ".receiptgate/ledger.jsonl"
        p.write_bytes(p.read_bytes()[:-1])
        with self.assertRaises(ledger.LedgerError):
            ledger.read(self.root)
        p.unlink()
        p.symlink_to(self.root / "receiptgate.toml")
        with self.assertRaises(ledger.LedgerError):
            ledger.read(self.root)

    def test_unknown_policy_and_bad_values_rejected(self):
        for suffix in [
            "\nunknown = true\n",
            '\n[gates.bad]\nmatch = ["x"]\nrequires=["missing"]\n',
            '\n[gates.bad]\nmatch=["x"]\nrequires=["test"]\nmax_age_minutes=0\n',
        ]:
            (self.root / "receiptgate.toml").write_text(policy.DEFAULT + suffix)
            with self.assertRaises(policy.PolicyError):
                policy.load(self.root)


if __name__ == "__main__":
    unittest.main()
