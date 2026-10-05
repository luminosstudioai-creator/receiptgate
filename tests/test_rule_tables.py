"""Thirty explicit behavior cases per built-in rule, including allowed commands."""

import tempfile
import time
import unittest
from pathlib import Path
from receiptgate import policy, rules

STATE = {"head_sha": "a" * 40, "branch": "main", "tree_hash": "b" * 64, "clean": True}


class RuleTables(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "receiptgate.toml").write_text(policy.DEFAULT)
        self.p = policy.load(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def table(self, rule, deny, allow):
        self.assertGreaterEqual(len(deny) + len(allow), 30)
        for command, expected in [(x, "deny") for x in deny] + [(x, "allow") for x in allow]:
            with self.subTest(command=command):
                d = rules.evaluate(self.root, command, self.p, STATE, [])
                self.assertEqual(d["decision"], expected)
                if expected == "deny":
                    self.assertEqual(d["rule"], rule)

    def test_r0_thirty_cases(self):
        self.table(
            "R0",
            [
                "rm receiptgate.toml",
                "mv receiptgate.toml old",
                "cp x receiptgate.toml",
                "sed -i x receiptgate.toml",
                "cat receiptgate.toml",
                "echo x > receiptgate.toml",
                "rm .receiptgate/ledger.jsonl",
                "mv .receiptgate old",
                "cat .receiptgate/lock",
                "rm .claude/settings.json",
                "cp x .claude/settings.local.json",
                "rm .codex/hooks.json",
                "rm .codex/config.toml",
                "rm .git/hooks/pre-push",
                "cat " + str(self.root / "receiptgate.toml"),
                "rm ./receiptgate.toml",
                "rm ./nested/../receiptgate.toml",
                "cp .codex/hooks.json x",
                "rm .claude",
                "rm .codex",
            ],
            [
                "echo hello",
                "cat app.txt",
                "rm old.txt",
                "cp input.txt output.txt",
                "git status",
                "git diff",
                "cat docs/receiptgate.toml",
                "echo receiptgate",
                "cat .claude/notes.md",
                "cat .codex/README.md",
            ],
        )

    def test_r2_thirty_cases(self):
        self.table(
            "R2",
            [
                "pytest | tail",
                "pytest | head",
                "pytest | tee log",
                "pytest || true",
                "pytest; true",
                "pytest; exit 0",
                "pytest && echo done",
                "pytest > result.txt",
                "pytest 2> errors.txt",
                "pytest < input.txt",
                "pytest &",
                "npm test | tail",
                "make test || true",
                "npm run build | head",
                "./deploy.sh | tail",
                "./deploy.sh || true",
                "./deploy.sh; true",
                "npm publish | tee log",
                "kubectl apply | head",
                "true && pytest",
            ],
            [
                "pytest",
                "npm test",
                "make test",
                "npm run build",
                'echo "|| true"',
                'echo "| tail"',
                'echo "exit 0"',
                "git status",
                "cat app.txt",
                "echo tests",
            ],
        )

    def test_r3_thirty_cases(self):
        self.table(
            "R3",
            [
                "git push origin main",
                "git push origin HEAD:main",
                "git push origin +HEAD:main",
                "git push origin topic:refs/heads/main",
                "git push origin :main",
                "git push origin main:release/next",
                "git push origin HEAD",
                "git push",
                "git push -f origin main",
                "git push --force origin topic",
                "git push --force-with-lease origin main",
                "git push --all",
                "git push --mirror",
                "git push --delete origin main",
                "git reset --hard",
                "git branch -D main",
                "git branch -d release/next",
                "git branch --delete main",
                "git merge topic",
                "git -C /tmp push origin main",
            ],
            [
                "git status",
                "git diff",
                "git log",
                "git rev-parse HEAD",
                "git push origin topic",
                "git push origin main-feature",
                "git push origin topic:other",
                "git push --dry-run origin topic",
                "git branch -D topic",
                "git reset --soft HEAD",
            ],
        )

    def test_r4_thirty_cases(self):
        self.table(
            "R4",
            [
                "cat .env",
                "less .env",
                "head .env",
                "tail .env",
                "sed x .env",
                "grep x .env",
                "rg x .env",
                "awk x .env",
                "cp .env copy",
                "tar .env",
                "zip .env",
                "base64 .env",
                "cat .env.local",
                "cat .env.production",
                "cat key.pem",
                "cat id_rsa",
                "cat secrets/token",
                "cat ./secrets/nested/key",
                "env",
                "printenv",
            ],
            [
                "cat app.txt",
                "cat .envrc.example",
                "cat env.example",
                "head README.md",
                "grep x app.txt",
                "rg x docs",
                "cat public.key",
                "cat identifier.txt",
                "echo environment",
                "git status",
            ],
        )

    def test_r1_thirty_state_cases(self):
        commands = [
            "./deploy.sh",
            "./deploy.sh staging",
            "npm publish",
            "npm publish --dry-run",
            "kubectl apply",
        ]
        base = {
            "ts": time.time(),
            "kind": "test",
            "exit_code": 0,
            "eligible": True,
            "state": dict(STATE),
        }
        variants = [
            ("missing", []),
            ("failed", [{**base, "exit_code": 1}]),
            ("expired", [{**base, "ts": time.time() - 8000}]),
            ("different-head", [{**base, "state": {**STATE, "head_sha": "c" * 40}}]),
            ("different-tree", [{**base, "state": {**STATE, "tree_hash": "d" * 64}}]),
        ]
        # 25 distinct absent/failed/stale state combinations and 5 current-green cases.
        count = 0
        for command in commands:
            for label, rows in variants:
                with self.subTest(command=command, evidence=label):
                    d = rules.evaluate(self.root, command, self.p, STATE, rows)
                    self.assertEqual((d["decision"], d["rule"]), ("deny", "R1"))
                    count += 1
            with self.subTest(command=command, evidence="current-green"):
                self.assertEqual(
                    rules.evaluate(self.root, command, self.p, STATE, [base])["decision"], "allow"
                )
                count += 1
        self.assertEqual(count, 30)
