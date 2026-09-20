import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests.test_regression import run_hook


class TestNoOpinionAudit(unittest.TestCase):
    def test_outside_cwd_logged_as_no_opinion(self):
        with tempfile.TemporaryDirectory() as cwd, tempfile.TemporaryDirectory() as other:
            f = Path(other) / "x.txt"; f.write_text("x")
            out, audit = run_hook({"tool_name": "Edit", "cwd": cwd,
                                   "tool_input": {"file_path": str(f)}})
            self.assertEqual(out, "", "behavior must stay silent")
            self.assertEqual(audit[0]["decision"], "no_opinion")


if __name__ == "__main__":
    unittest.main()
