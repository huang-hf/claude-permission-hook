import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secure_handler as sh


def hit(cmd):
    return sh.check_redlines(sh.Request("command", cmd, "/w"))


def hit_path(kind, path):
    return sh.check_redlines(sh.Request(kind, path, "/w"))


class TestRedlineHits(unittest.TestCase):
    def test_prod_infra_writes(self):
        for cmd in ["kubectl --context xyz-prod apply -f a.yaml",
                    "kubectl --context arena-eks rollout restart deploy/x",
                    "kubectl -n prod delete pod foo"]:
            self.assertEqual(hit(cmd), "prod_infra", cmd)

    def test_prod_infra_verb_table_gaps(self):
        """漏报:create/uncordon/config use-context 等原动词表没覆盖的写操作。"""
        for cmd in ["kubectl create -f x.yaml",
                    "kubectl config use-context xyz-prod",
                    "kubectl uncordon n1",
                    "kubectl attach pod/foo",
                    "kubectl expose deploy/foo --port=80",
                    "kubectl autoscale deploy/foo --min=1 --max=3",
                    "kubectl rollout undo deploy/foo"]:
            self.assertEqual(hit(cmd), "prod_infra", cmd)

    def test_prod_infra_non_kubectl(self):
        """非 kubectl 的生产基建写操作面。"""
        for cmd in ["terraform apply",
                    "terraform destroy -auto-approve",
                    "helm upgrade myrelease ./chart",
                    "helm install myrelease ./chart",
                    "helm delete myrelease",
                    "helm rollback myrelease 1",
                    "eksctl create cluster --name foo",
                    "eksctl delete cluster --name foo",
                    "aws s3 rm s3://bucket/key"]:
            self.assertEqual(hit(cmd), "prod_infra", cmd)

    def test_credentials(self):
        for cmd in ["coffer run --global env",
                    "cat ~/.ssh/id_rsa",
                    "aws secretsmanager get-secret-value --secret-id x"]:
            self.assertEqual(hit(cmd), "credentials", cmd)

    def test_credentials_underscore_env_vars(self):
        """下划线环境变量名漏报:\\bsecret\\b 的词边界被下划线吃掉。"""
        for cmd in ["export AWS_SECRET_ACCESS_KEY=x",
                    "export GITHUB_TOKEN=ghp_xxx",
                    "echo $DB_PASSWORD_HASH"]:
            self.assertEqual(hit(cmd), "credentials", cmd)

    def test_credentials_paths(self):
        for cmd in ["cat ~/.kube/config",
                    "cat ~/.gnupg/secring.gpg",
                    "cp ~/.netrc /tmp/x",
                    "cat ~/.docker/config.json"]:
            self.assertEqual(hit(cmd), "credentials", cmd)

    def test_destructive(self):
        for cmd in ["rm -rf /tmp/x", "rm -f /tmp.txt",
                    "git push --force origin main", "dd if=/dev/zero of=/dev/sda"]:
            self.assertEqual(hit(cmd), "destructive", cmd)

    def test_destructive_rm_flag_position(self):
        """漏报:rm 的 -r/-f 不是紧跟 rm 的第一个 token。"""
        for cmd in ["rm -i -rf /tmp/x",
                    "rm -v -rf /tmp/x",
                    "rm --recursive --force /tmp/x"]:
            self.assertEqual(hit(cmd), "destructive", cmd)

    def test_destructive_git_push_short_flag(self):
        """漏报:git push 只覆盖 --force,漏了更常用的 -f。"""
        self.assertEqual(hit("git push -f origin main"), "destructive")

    def test_destructive_git_push_force_with_lease_still_hits(self):
        """收紧 -f 匹配时不能把 --force-with-lease 丢掉。"""
        self.assertEqual(hit("git push --force-with-lease origin main"), "destructive")

    def test_destructive_git_reset_hard_and_clean(self):
        for cmd in ["git reset --hard", "git reset --hard HEAD~1",
                    "git clean -fd", "git clean -df"]:
            self.assertEqual(hit(cmd), "destructive", cmd)


class TestRedlineFileHits(unittest.TestCase):
    """file_read/file_write 类型的红线(现有用例全是 kind='command')。"""

    def test_ssh_key_file_read_hits_credentials(self):
        self.assertEqual(hit_path("file_read", "/Users/x/.ssh/id_rsa"), "credentials")

    def test_ordinary_source_file_not_blocked(self):
        self.assertIsNone(hit_path("file_read", "/Users/x/proj/main.py"))


class TestRedlineMisses(unittest.TestCase):
    """只读操作必须不被红线拦截,否则通过率会被打死。"""

    def test_kubectl_readonly_not_blocked(self):
        for cmd in ["kubectl --context xyz-prod get pods",
                    "kubectl --context netmind-inference describe pod foo",
                    "kubectl --context arena-eks logs deploy/bar",
                    "kubectl --context arena-eks top pods"]:
            self.assertIsNone(hit(cmd), cmd)

    def test_ordinary_commands_not_blocked(self):
        for cmd in ["ls -la", "git status", "git log", "git diff",
                    "pytest tests/", "npm install", "docker ps", "make test"]:
            self.assertIsNone(hit(cmd), cmd)


class TestRedlineWiredIntoJudge(unittest.TestCase):
    def test_redline_short_circuits_before_network(self):
        """短路必须覆盖 remote_judge 调用链上的每一跳,不只是最外层。"""
        called = []
        original_remote_judge = sh.remote_judge
        original_dippy_analyze = sh.dippy_analyze
        original_ask_ai = sh.ask_ai
        sh.remote_judge = lambda req: called.append(('remote_judge', req)) or sh.Verdict("allow", "x", "ai")
        sh.dippy_analyze = lambda *a, **k: called.append(('dippy_analyze', a, k)) or ('allow', 'x')
        sh.ask_ai = lambda *a, **k: called.append(('ask_ai', a, k)) or (True, 'SAFE')
        try:
            v = sh.judge(sh.Request("command", "rm -rf /tmp/x", "/w"))
            self.assertEqual(v.decision, "ask")
            self.assertEqual(v.layer, "redline")
            self.assertEqual(called, [], "redline must short-circuit before remote_judge/dippy_analyze/ask_ai")
        finally:
            sh.remote_judge = original_remote_judge
            sh.dippy_analyze = original_dippy_analyze
            sh.ask_ai = original_ask_ai

    def test_empty_payload_early_return(self):
        v = sh.judge(sh.Request("command", "", "/w"))
        self.assertEqual(v.decision, "no_opinion")


if __name__ == "__main__":
    unittest.main()
