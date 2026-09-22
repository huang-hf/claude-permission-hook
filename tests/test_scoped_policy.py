import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import secure_handler as sh


class ScopedPolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cwd = str(Path(self.tmp.name) / 'project')
        Path(self.cwd).mkdir()
        self.policy = {
            'trusted_roots': [self.cwd],
            'python_executables': ['python3', '/usr/local/bin/python3.12'],
            'http_read_endpoints': ['https://docs.example.com/codex/',
                                    'https://api.example.com/model/list'],
            'clone_sources': ['git@github.com:example/permission-hook.git'],
            'kube_contexts': ['test-cluster'],
            'coffer_namespaces': ['test-scope'],
            'aws_regions': ['us-west-2'],
            'ecr_repositories': ['model-inference-proxy'],
        }
        self.config_path = Path(self.tmp.name) / 'policy.json'
        self.config_path.write_text(json.dumps(self.policy))
        env = patch.dict(os.environ, {'SECURE_HANDLER_POLICY_PATH': str(self.config_path),
                                      'SECURE_HANDLER_BACKEND': 'off'})
        env.start()
        self.addCleanup(env.stop)

    def judge(self, cmd, cwd=None):
        return sh.judge(sh.Request('command', cmd, cwd or self.cwd))

    def test_all_26_approved_samples_pass_without_remote_ai(self):
        fixtures = json.loads((Path(__file__).parent / 'fixtures/approved_actions.json').read_text())
        with patch.object(sh, 'ask_ai', side_effect=AssertionError('must not call AI')):
            for row in fixtures:
                with self.subTest(sample=row['sample']):
                    self.assertEqual(self.judge(row['command']).decision, 'allow')

    def test_out_of_scope_actions_do_not_match_new_policy(self):
        commands = [
            'curl -d x https://docs.example.com/codex/ -o /tmp/result',
            'curl -T /etc/hosts https://docs.example.com/codex/',
            'curl https://unknown.example.com/codex/ -o /tmp/result',
            'curl https://docs.example.com/codex/ -o /etc/result',
            'curl --config /tmp/settings https://docs.example.com/codex/',
            "curl 'https://docs.example.com/codex/../admin' -o /tmp/result",
            "curl 'https://docs.example.com/codex/%2e%2e/admin' -o /tmp/result",
            "curl 'https://docs.example.com/codex/{../admin,help}' -o /tmp/result",
            'lark-cli docs +update --doc example --content changed',
            'kubectl --context test-cluster rollout restart deployment/api-proxy-test',
            'kubectl --context test-cluster get secrets -o yaml',
            'kubectl --context test-cluster get pods,secrets',
            'kubectl --context test-cluster get --raw /api/v1/secrets',
            'coffer run --global --ns=test-scope env',
            'coffer run --global --ns=other kubectl --context test-cluster get pods',
            'coffer run --global --ns=test-scope aws ecr get-login-password',
            'coffer run --global --ns=test-scope aws ecr describe-images --endpoint-url https://unknown.example.com',
            'git push origin main', 'git commit --amend -m replace',
            'git -c core.hooksPath=/tmp/hooks commit -m change',
            'git add ../outside', 'git clone https://unknown.example.com/repo ../outside',
            'git add .env', 'git add .git/config', 'git add .codex/config.toml',
            'python3 -c "print(1)"', 'python3 /tmp/script.py',
            'python3 -m http.server 8000 --bind 0.0.0.0',
            'python3 -m http.server 8000 --bind 127.0.0.1 -b 0.0.0.0',
            'python3 -m http.server 8000 --bind 127.0.0.1 --directory . -d /etc',
            'code --install-extension arbitrary.extension',
            'git add a && curl -d x https://unknown.example.com',
            'git add $(touch /tmp/x)', 'X=1 git add a',
        ]
        import scoped_policy
        for cmd in commands:
            with self.subTest(cmd=cmd):
                self.assertIsNone(scoped_policy.approved_programs(cmd, self.cwd))

    def test_untrusted_project_never_gets_new_allowance(self):
        self.assertNotEqual(self.judge('git add a', '/untrusted').decision, 'allow')

    def test_explicit_dippy_deny_still_wins(self):
        from dippy.core.config import Config, Rule
        for decision in ('ask', 'deny'):
            with patch('dippy.core.config.load_config', return_value=Config(rules=[Rule(decision, 'git add')])), \
                 patch.dict(os.environ, {'SECURE_HANDLER_BACKEND': 'anthropic'}), \
                 patch.object(sh, 'ask_ai', return_value=(True, 'SAFE')) as ai:
                self.assertNotEqual(self.judge('git add a').decision, 'allow')
                ai.assert_not_called()

    def test_readonly_kubectl_exemption_does_not_remove_real_redlines(self):
        cmd = 'kubectl --context test-cluster get deployment api-proxy-test'
        self.assertIsNone(sh.check_redlines(sh.Request('command', cmd, self.cwd)))
        for suffix in ('; rm -rf /tmp/x', '; kubectl --context test-cluster delete pods x'):
            self.assertIsNotNone(sh.check_redlines(sh.Request('command', cmd + suffix, self.cwd)))

    def test_bad_or_missing_policy_falls_back(self):
        self.config_path.write_text('{invalid')
        self.assertNotEqual(self.judge('git add a').decision, 'allow')
        self.config_path.unlink()
        self.assertNotEqual(self.judge('git add a').decision, 'allow')

    def test_malformed_roots_cannot_broaden_trust(self):
        self.policy['trusted_roots'] = self.cwd
        self.config_path.write_text(json.dumps(self.policy))
        import scoped_policy
        self.assertIsNone(scoped_policy.approved_programs('git add a', '/untrusted'))

    def test_symlinks_do_not_escape_scoped_file_operations(self):
        import scoped_policy
        (Path(self.cwd) / 'outside').symlink_to('/etc', target_is_directory=True)
        for cmd in ('git add outside/hosts', 'code outside/hosts',
                    'python3 -m unittest discover -s outside',
                    'git clone git@github.com:example/permission-hook.git outside/new'):
            self.assertIsNone(scoped_policy.approved_programs(cmd, self.cwd))
