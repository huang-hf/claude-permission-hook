import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secure_handler as sh


class TestParse(unittest.TestCase):
    def test_bash_becomes_command(self):
        req = sh.parse_claude_code({
            "tool_name": "Bash", "cwd": "/w",
            "tool_input": {"command": "ls -la"}})
        self.assertEqual(req.kind, "command")
        self.assertEqual(req.payload, "ls -la")
        self.assertEqual(req.cwd, "/w")

    def test_read_becomes_file_read(self):
        req = sh.parse_claude_code({
            "tool_name": "Read", "cwd": "/w",
            "tool_input": {"file_path": "/w/a.txt"}})
        self.assertEqual(req.kind, "file_read")
        self.assertEqual(req.payload, "/w/a.txt")

    def test_edit_write_notebook_all_become_file_write(self):
        for tool in ("Edit", "Write", "NotebookEdit"):
            req = sh.parse_claude_code({
                "tool_name": tool, "cwd": "/w",
                "tool_input": {"file_path": "/w/a.txt"}})
            self.assertEqual(req.kind, "file_write", f"{tool} should map to file_write")

    def test_unknown_tool_returns_none(self):
        self.assertIsNone(sh.parse_claude_code({
            "tool_name": "WebFetch", "cwd": "/w", "tool_input": {}}))

    def test_empty_command_returns_none(self):
        self.assertIsNone(sh.parse_claude_code({
            "tool_name": "Bash", "cwd": "/w", "tool_input": {"command": ""}}))


class TestEmit(unittest.TestCase):
    def test_allow_emits_allow_json(self):
        import json
        out = sh.emit_claude_code(sh.Verdict("allow", "within cwd", "rule"))
        self.assertEqual(
            json.loads(out)["hookSpecificOutput"]["permissionDecision"], "allow")

    def test_ask_emits_ask_json(self):
        import json
        out = sh.emit_claude_code(sh.Verdict("ask", "dangerous", "redline"))
        self.assertEqual(
            json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_no_opinion_emits_nothing(self):
        self.assertIsNone(sh.emit_claude_code(sh.Verdict("no_opinion", "outside_cwd", "rule")))


if __name__ == "__main__":
    unittest.main()
