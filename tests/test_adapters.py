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


class TestDisplayMappingIsLayerKeyed(unittest.TestCase):
    """展示层映射必须按 layer 取键,不能按 reason 文本匹配。

    dippy 对未识别命令会把命令原文当 reason 返回,若按文本匹配,
    一条恰好叫 within_cwd 的命令就会被套上 rule 层的展示文案。
    Task 6/7 引入 redline reason 码后,这类冲突只会更多。
    """

    def _shown(self, verdict):
        import json
        out = sh.emit_claude_code(verdict)
        return json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]

    def test_rule_layer_gets_display_text(self):
        self.assertEqual(self._shown(sh.Verdict("allow", "within_cwd", "rule")), "within cwd")
        self.assertEqual(self._shown(sh.Verdict("allow", "git_metadata", "rule")), "git metadata dir")

    def test_non_rule_layers_keep_raw_reason(self):
        self.assertEqual(self._shown(sh.Verdict("ask", "within_cwd", "ai")), "🔍 within_cwd")
        self.assertEqual(self._shown(sh.Verdict("ask", "git_metadata", "ai")), "🔍 git_metadata")
        self.assertEqual(self._shown(sh.Verdict("allow", "within_cwd", "dippy")), "within_cwd")

    def test_ai_allow_still_gets_prefix(self):
        self.assertEqual(self._shown(sh.Verdict("allow", "sh interactive", "ai")),
                         "ai:SAFE (sh interactive)")


if __name__ == "__main__":
    unittest.main()
