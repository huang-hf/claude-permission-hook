"""方案 B:PreToolUse 对 Bash 只跑红线检查。

背景:PreToolUse 对每次工具调用都触发,PermissionRequest 只在 Claude Code
判定"需要权限决策"时才触发。owner 的 allow 规则(如 `Bash(git reset*)`)命中
时,被放行的命令根本走不到 PermissionRequest,红线层对它们完全失效。

这里验证:main() 在 hook_event_name == 'PreToolUse' 且 req.kind == 'command'
时只跑 check_redlines(),不进入 judge() 的完整判断链(dippy/AI/typesafe),
且红线未命中必须静默(no_opinion),不能输出 ask 覆盖 owner 的 allow 规则。
"""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secure_handler as sh


def run_main_inprocess(payload: dict, argv=None):
    """在进程内调用 sh.main(),便于 monkeypatch dippy_analyze/ask_ai 并统计调用次数。"""
    with tempfile.TemporaryDirectory() as td:
        old_argv = sys.argv
        old_stdin = sys.stdin
        old_audit_path = sh.AUDIT_LOG_PATH
        try:
            sys.argv = ['secure_handler.py'] + (argv or [])
            sys.stdin = io.StringIO(json.dumps(payload))
            sh.AUDIT_LOG_PATH = Path(td) / 'audit.jsonl'
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    sh.main()
                except SystemExit:
                    pass
            entries = []
            if sh.AUDIT_LOG_PATH.exists():
                entries = [json.loads(l) for l in
                          sh.AUDIT_LOG_PATH.read_text(encoding='utf-8').splitlines() if l.strip()]
            return buf.getvalue().strip(), entries
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
            sh.AUDIT_LOG_PATH = old_audit_path


def decision_of(stdout: str):
    if not stdout:
        return None
    return json.loads(stdout)['hookSpecificOutput']['permissionDecision']


class TestPreToolUseBashRedlineOnly(unittest.TestCase):
    def test_pretooluse_bash_redline_hit_asks(self):
        out, audit = run_main_inprocess({
            'tool_name': 'Bash', 'cwd': '/tmp',
            'tool_input': {'command': 'git reset --hard origin/main'},
            'hook_event_name': 'PreToolUse',
        })
        self.assertEqual(decision_of(out), 'ask')
        self.assertEqual(audit[0]['layer'], 'redline')
        self.assertEqual(audit[0]['decision'], 'ask')

    def test_pretooluse_bash_redline_miss_is_silent_and_skips_full_chain(self):
        """核心性能承诺:未命中红线时静默,且不调用 dippy_analyze / ask_ai。"""
        called = []
        original_dippy_analyze = sh.dippy_analyze
        original_ask_ai = sh.ask_ai
        sh.dippy_analyze = lambda *a, **k: called.append('dippy_analyze') or ('allow', 'x')
        sh.ask_ai = lambda *a, **k: called.append('ask_ai') or (True, 'SAFE')
        try:
            out, audit = run_main_inprocess({
                'tool_name': 'Bash', 'cwd': '/tmp',
                'tool_input': {'command': 'npm install --foo'},
                'hook_event_name': 'PreToolUse',
            })
            self.assertEqual(out, '')
            self.assertEqual(called, [], "PreToolUse 红线未命中不应触发 dippy/ask_ai")
            self.assertEqual(audit[0]['decision'], 'no_opinion')
            self.assertEqual(audit[0]['layer'], 'rule')
            self.assertEqual(audit[0]['reason'], 'redline_pass')
        finally:
            sh.dippy_analyze = original_dippy_analyze
            sh.ask_ai = original_ask_ai

    def test_permission_request_bash_still_runs_full_chain(self):
        """PermissionRequest 路径完全不变:未命中红线仍走 dippy。"""
        called = []
        original_dippy_analyze = sh.dippy_analyze
        sh.dippy_analyze = lambda *a, **k: called.append('dippy_analyze') or ('allow', 'x')
        try:
            out, audit = run_main_inprocess({
                'tool_name': 'Bash', 'cwd': '/tmp',
                'tool_input': {'command': 'npm install --foo'},
                'hook_event_name': 'PermissionRequest',
            })
            self.assertEqual(called, ['dippy_analyze'])
            self.assertEqual(decision_of(out), 'allow')
            self.assertEqual(audit[0]['layer'], 'dippy')
        finally:
            sh.dippy_analyze = original_dippy_analyze

    def test_pretooluse_file_op_unaffected(self):
        """文件操作不受影响:PreToolUse + file_write 仍走完整 judge()(within_cwd)。"""
        with tempfile.TemporaryDirectory() as cwd:
            fp = str(Path(cwd) / 'x.txt')
            out, audit = run_main_inprocess({
                'tool_name': 'Write', 'cwd': cwd,
                'tool_input': {'file_path': fp, 'content': 'x'},
                'hook_event_name': 'PreToolUse',
            })
            self.assertEqual(decision_of(out), 'allow')
            self.assertEqual(audit[0]['layer'], 'rule')
            self.assertEqual(audit[0]['reason'], 'within_cwd')


if __name__ == '__main__':
    unittest.main()
