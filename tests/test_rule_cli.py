"""Custom rule selection through the public CLI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class TestRuleCLI(unittest.TestCase):
    def run_hook(self, directory, *args, command='my-custom-cli status'):
        env = dict(os.environ, SECURE_HANDLER_BACKEND='off',
                   SECURE_HANDLER_AI_FALLBACK='0',
                   SECURE_HANDLER_AUDIT_LOG=str(directory / 'audit.jsonl'))
        data = {'hook_event_name': 'PermissionRequest', 'tool_name': 'Bash',
                'cwd': str(directory), 'tool_input': {'command': command}}
        return subprocess.run([sys.executable, str(ROOT / 'secure_handler.py'),
                               '--agent', 'codex', *args], cwd=directory,
                              input=json.dumps(data), text=True, capture_output=True,
                              env=env, timeout=20)

    def test_custom_relative_absolute_and_equals_paths(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            rule = directory / 'my rules.py'
            rule.write_text("def approved_programs(command, cwd):\n"
                            "    return {'my-custom-cli'} if command == 'my-custom-cli status' else None\n"
                            "def redirect_rules(command):\n    return []\n")
            for args in [('--rule', str(rule)), ('--rule', rule.name),
                         ('--rule=' + str(rule),)]:
                with self.subTest(args=args):
                    result = self.run_hook(directory, *args)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('"behavior": "allow"', result.stdout)

    def test_missing_broken_and_missing_argument_do_not_allow(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            (directory / 'broken.py').write_text('raise RuntimeError("broken")\n')
            for args in [('--rule', 'absent.py'), ('--rule', 'broken.py'), ('--rule',)]:
                with self.subTest(args=args):
                    self.assertEqual(self.run_hook(directory, *args).stdout, '')

    def test_working_directory_rule_is_not_automatically_loaded(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            (directory / 'personal_rules.py').write_text('raise RuntimeError("wrong file")\n')
            result = self.run_hook(directory, command='gh run list > /tmp/custom-rule-cli-test.log')
            self.assertIn('"behavior": "allow"', result.stdout)

    def test_help_describes_rule(self):
        result = subprocess.run([sys.executable, str(ROOT / 'secure_handler.py'), '--help'],
                                input='', text=True, capture_output=True)
        self.assertIn('--rule', result.stdout)
