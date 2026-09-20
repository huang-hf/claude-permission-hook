import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secure_handler as sh


class TestJudgeFileOps(unittest.TestCase):
    def test_inside_cwd_allows(self):
        with tempfile.TemporaryDirectory() as cwd:
            f = Path(cwd) / "a.txt"; f.write_text("x")
            v = sh.judge(sh.Request("file_write", str(f), cwd))
            self.assertEqual(v.decision, "allow")
            self.assertEqual(v.reason, "within_cwd")

    def test_outside_cwd_returns_no_opinion(self):
        """文件操作落空 → no_opinion(静默),不进入 dippy,也不出网。"""
        with tempfile.TemporaryDirectory() as cwd, tempfile.TemporaryDirectory() as other:
            f = Path(other) / "b.txt"; f.write_text("x")
            v = sh.judge(sh.Request("file_read", str(f), cwd))
            self.assertEqual(v.decision, "no_opinion")
            self.assertEqual(v.reason, "outside_cwd")

    def test_file_ops_never_reach_remote(self):
        """守卫:文件操作绝不调用远程后端。"""
        called = []
        original = sh.remote_judge
        sh.remote_judge = lambda req: called.append(req) or sh.Verdict("ask", "x", "ai")
        try:
            with tempfile.TemporaryDirectory() as cwd, tempfile.TemporaryDirectory() as other:
                f = Path(other) / "c.txt"; f.write_text("x")
                sh.judge(sh.Request("file_write", str(f), cwd))
            self.assertEqual(called, [], "file ops must not hit the network")
        finally:
            sh.remote_judge = original


class TestJudgeIsPure(unittest.TestCase):
    def test_judge_writes_nothing_to_stdout(self):
        import io
        import contextlib
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as cwd:
            f = Path(cwd) / "a.txt"; f.write_text("x")
            with contextlib.redirect_stdout(buf):
                sh.judge(sh.Request("file_write", str(f), cwd))
        self.assertEqual(buf.getvalue(), "", "judge() must not print")


if __name__ == "__main__":
    unittest.main()
