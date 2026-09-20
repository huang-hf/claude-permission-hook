import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secure_handler as sh


def hit(cmd):
    return sh.check_redlines(sh.Request("command", cmd, "/w"))


class TestRedlineHits(unittest.TestCase):
    def test_prod_infra_writes(self):
        for cmd in ["kubectl --context xyz-prod apply -f a.yaml",
                    "kubectl --context arena-eks rollout restart deploy/x",
                    "kubectl -n prod delete pod foo"]:
            self.assertEqual(hit(cmd), "prod_infra", cmd)

    def test_credentials(self):
        for cmd in ["coffer run --global env",
                    "cat ~/.ssh/id_rsa",
                    "aws secretsmanager get-secret-value --secret-id x"]:
            self.assertEqual(hit(cmd), "credentials", cmd)

    def test_destructive(self):
        for cmd in ["rm -rf /tmp/x", "rm -f /tmp.txt",
                    "git push --force origin main", "dd if=/dev/zero of=/dev/sda"]:
            self.assertEqual(hit(cmd), "destructive", cmd)


class TestRedlineMisses(unittest.TestCase):
    """只读操作必须不被红线拦截,否则通过率会被打死。"""

    def test_kubectl_readonly_not_blocked(self):
        for cmd in ["kubectl --context xyz-prod get pods",
                    "kubectl --context netmind-inference describe pod foo",
                    "kubectl --context arena-eks logs deploy/bar"]:
            self.assertIsNone(hit(cmd), cmd)

    def test_ordinary_commands_not_blocked(self):
        for cmd in ["ls -la", "git status", "pytest tests/", "npm install"]:
            self.assertIsNone(hit(cmd), cmd)


class TestRedlineWiredIntoJudge(unittest.TestCase):
    def test_redline_short_circuits_before_network(self):
        called = []
        original = sh.remote_judge
        sh.remote_judge = lambda req: called.append(req) or sh.Verdict("allow", "x", "ai")
        try:
            v = sh.judge(sh.Request("command", "rm -rf /tmp/x", "/w"))
            self.assertEqual(v.decision, "ask")
            self.assertEqual(v.layer, "redline")
            self.assertEqual(called, [], "redline must short-circuit before any network call")
        finally:
            sh.remote_judge = original


if __name__ == "__main__":
    unittest.main()
