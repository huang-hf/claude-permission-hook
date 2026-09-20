import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secure_handler as sh


class TestAiEndpoint(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in (
            "SECURE_HANDLER_AI_BASE_URL", "SECURE_HANDLER_AI_KEY",
            "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN")}
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_falls_back_to_anthropic_vars(self):
        os.environ["ANTHROPIC_BASE_URL"] = "http://old.example"
        os.environ["ANTHROPIC_AUTH_TOKEN"] = "tok-old"
        self.assertEqual(sh._ai_endpoint(), ("http://old.example", "tok-old"))

    def test_dedicated_vars_take_precedence(self):
        os.environ["ANTHROPIC_BASE_URL"] = "http://old.example"
        os.environ["ANTHROPIC_AUTH_TOKEN"] = "tok-old"
        os.environ["SECURE_HANDLER_AI_BASE_URL"] = "http://new.example"
        os.environ["SECURE_HANDLER_AI_KEY"] = "tok-new"
        self.assertEqual(sh._ai_endpoint(), ("http://new.example", "tok-new"))

    def test_trailing_slash_stripped(self):
        os.environ["SECURE_HANDLER_AI_BASE_URL"] = "http://x.example/"
        os.environ["SECURE_HANDLER_AI_KEY"] = "t"
        self.assertEqual(sh._ai_endpoint()[0], "http://x.example")


if __name__ == "__main__":
    unittest.main()
