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
        """下划线环境变量名漏报:\\bSECRET\\b 的词边界被下划线吃掉。

        `echo $DB_PASSWORD_HASH` 不在此列 —— 只是引用变量名,不是往环境里塞
        凭证,动作版故意不拦(这正是要修的高误报类型)。
        """
        for cmd in ["export AWS_SECRET_ACCESS_KEY=x",
                    "export GITHUB_TOKEN=ghp_xxx"]:
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


class TestCredentialWordsAreCommandOnly(unittest.TestCase):
    """凭证动作只对命令生效,不对文件路径生效。

    这条约束是量出来的,不是设计偏好:按路径匹配 token/secret/password 时,
    owner 的一个仓库有 8348/25687(32%)的源文件名命中,等于每三次文件编辑
    弹一次窗。位置(在 ~/.ssh 下)和命名(叫 token_utils.py)是强度完全不同
    的证据。若有人把动作分支改回对路径生效,下面第二组会变红。
    """

    def test_keywords_still_flag_commands(self):
        for cmd in ["export AWS_SECRET_ACCESS_KEY=x",
                    "export GITHUB_TOKEN=ghp_xxx",
                    "aws secretsmanager get-secret-value --secret-id x"]:
            self.assertEqual(hit(cmd), "credentials", cmd)

    def test_keywords_do_not_flag_file_paths(self):
        for path in ["/Users/x/repo/token_utils.py",
                     "/Users/x/repo/erc20_token_config.ts",
                     "/Users/x/repo/password_reset.tsx",
                     "/Users/x/repo/secret_handoff.py"]:
            for kind in ("file_read", "file_write"):
                self.assertIsNone(hit_path(kind, path), f"{kind} {path}")


class TestCredentialActionsNotJustMentions(unittest.TestCase):
    """_CREDENTIAL_ACTIONS 匹配「在操作凭证」的动作,不匹配「提到了这个词」。

    关键词版(_CREDENTIAL_WORDS)命中 owner 22,896 条历史 Bash 命令的 14.5%,
    绝大多数是误报:词来自文件名、内联假值、分支名,而不是真的在摆弄凭证。
    动作版把命中率压到 2.6%,且下面这组真凭证操作一条不漏。
    """

    def test_still_blocks_real_credential_actions(self):
        for cmd in [
            "export GITHUB_TOKEN=ghp_xxx",
            "export AWS_SECRET_ACCESS_KEY=abc",
            "aws secretsmanager get-secret-value --secret-id x",
            "vault read secret/foo",
            "mysql -u root --password=hunter2",
            "aws ecr get-login-password | docker login --username AWS --password-stdin x",
            "gh auth token",
            "kubectl --context prod get secret db -o yaml",
        ]:
            self.assertEqual(hit(cmd), "credentials", cmd)

    def test_still_blocks_credential_file_by_path(self):
        # 靠 _REDLINES['credentials'] 的路径分支命中,不是靠动作分支。
        self.assertEqual(hit("cat ~/.aws/credentials"), "credentials")

    def test_allows_real_false_positive_cases(self):
        for cmd in [
            "sed -n 1,60p tests/unit/test_trading_no_credential_ns.py",
            "python -c 'AKSK={\"okx_api_key\":\"k\",\"okx_secret\":\"s\"}'",
            "gh pr create --head feat/x-api-key-from-secret-manager",
            "pytest tests/test_token_counter.py",
            "grep -r secret src/",
            "git commit -m 'add password reset form'",
        ]:
            self.assertIsNone(hit(cmd), cmd)

    def test_source_dotenv_not_blocked(self):
        """`.env` 只在文件名分支里保护『文件本身』,不该让 source .env 被拦。"""
        self.assertIsNone(hit("set -a && source .env && set +a && pytest"))


class TestCredentialFilesByName(unittest.TestCase):
    """凭证文件按文件名拦截 —— 窄白名单,不是泛关键词。

    这些文件放在项目目录内时会被 local_rules 的 within_cwd 放行,所以必须由
    红线兜住。实测该白名单在 owner 三个仓库的命中率均 <0.2%。
    """

    def test_credential_files_are_blocked(self):
        for path in ["/Users/x/repo/.env", "/Users/x/repo/.env.prod",
                     "/Users/x/repo/.git-credentials", "/Users/x/repo/.npmrc",
                     "/Users/x/repo/k8s/secret.yaml", "/Users/x/repo/certs/server.key",
                     "/Users/x/repo/kubeconfig"]:
            self.assertEqual(hit_path("file_write", path), "credentials", path)

    def test_ordinary_files_are_not_blocked(self):
        for path in ["/Users/x/repo/main.py", "/Users/x/repo/keys.ts",
                     "/Users/x/repo/monkey.py", "/Users/x/repo/environment.ts"]:
            self.assertIsNone(hit_path("file_write", path), path)


class TestDockerRmIsNotDestructive(unittest.TestCase):
    """`--rm` 里的 rm 不得触发 destructive。

    前瞻里的 `[a-z]*[rf]` 会匹配任何以 r/f 结尾的 flag(--user、--filter、
    --platform…),所以少了 (?<!-) 时 `docker run --rm --user 1000` 会被判危。
    docker --rm 是日常高频写法,误报代价很高。
    """

    def test_docker_rm_flag_is_ignored(self):
        for cmd in ["docker run --rm alpine echo hi",
                    "docker build --rm -f Dockerfile -t app .",
                    "docker run --rm --user 1000 alpine id",
                    "docker run --rm -v $PWD:/app node npm test"]:
            self.assertIsNone(hit(cmd), cmd)

    def test_real_rm_still_caught(self):
        for cmd in ["rm -rf /tmp/x", "/bin/rm -rf x", "sudo rm -rf /",
                    "ls | xargs rm -rf", "git rm -r src/"]:
            self.assertEqual(hit(cmd), "destructive", cmd)


class TestIrreversibleGitWorkLoss(unittest.TestCase):
    """丢弃未提交工作成果的 git 命令。

    这些 git 自己也救不回来,而且大多落在 owner 的 allow 规则里
    (`Bash(git checkout*)`、`Bash(git stash*)`),因此只有 PreToolUse 上的
    红线能覆盖到它们。
    """

    def test_discarding_commands_are_blocked(self):
        for cmd in ["git checkout -- .", "git checkout -- src/", "git checkout .",
                    "git restore .", "git restore --staged --worktree .",
                    "git stash clear", "git stash drop", "git stash drop stash@{0}",
                    "git branch -D feat/x", "git worktree remove --force /tmp/wt"]:
            self.assertEqual(hit(cmd), "destructive", cmd)

    def test_everyday_git_usage_is_not_blocked(self):
        for cmd in ["git checkout main", "git checkout -b feat/x", "git checkout feat/x",
                    "git stash", "git stash pop", "git stash list", "git stash show",
                    "git branch -a", "git branch", "git worktree list",
                    "git worktree add /tmp/wt -b x"]:
            self.assertIsNone(hit(cmd), cmd)

    def test_lowercase_d_deletes_merged_branches_safely(self):
        """`-D` 强删要拦,`-d` 只删已合并分支、是安全的 —— 别被 re.I 混为一谈。"""
        self.assertEqual(hit("git branch -D feat/x"), "destructive")
        self.assertIsNone(hit("git branch -d merged-branch"))
        self.assertIsNone(hit("git branch --delete merged-branch"))


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
