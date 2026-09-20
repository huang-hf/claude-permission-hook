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

    def test_anthropic_token_never_leaks_to_a_custom_base_url(self):
        """设了专属 URL 却忘了专属 KEY 时,不得把 Anthropic 的 token 发出去。

        这是本函数存在的场景下最可能的误配置。宁可让 AI 兜底静默失效
        (token 为空 → no_token → 一律 ask,只是多弹窗),也不能把凭证
        交给一个非预期的端点。
        """
        os.environ["ANTHROPIC_AUTH_TOKEN"] = "anthropic-secret"
        os.environ["SECURE_HANDLER_AI_BASE_URL"] = "http://third-party.example"
        base, token = sh._ai_endpoint()
        self.assertEqual(base, "http://third-party.example")
        self.assertEqual(token, "", "Anthropic token must not reach a custom base URL")

    def test_both_set_explicitly_still_works(self):
        """显式设满两个仍然可用 —— 用 Anthropic token 配自建代理是合法用法。"""
        os.environ["SECURE_HANDLER_AI_BASE_URL"] = "http://proxy.example"
        os.environ["SECURE_HANDLER_AI_KEY"] = "proxy-tok"
        self.assertEqual(sh._ai_endpoint(), ("http://proxy.example", "proxy-tok"))

    def test_defaults_when_unset(self):
        self.assertEqual(sh._ai_endpoint(), ("https://api.anthropic.com", ""))

    def test_empty_string_falls_through(self):
        os.environ["SECURE_HANDLER_AI_BASE_URL"] = ""
        os.environ["ANTHROPIC_BASE_URL"] = "http://old.example"
        os.environ["ANTHROPIC_AUTH_TOKEN"] = "tok-old"
        self.assertEqual(sh._ai_endpoint(), ("http://old.example", "tok-old"))

    def test_trailing_slash_stripped(self):
        os.environ["SECURE_HANDLER_AI_BASE_URL"] = "http://x.example/"
        os.environ["SECURE_HANDLER_AI_KEY"] = "t"
        self.assertEqual(sh._ai_endpoint()[0], "http://x.example")


if __name__ == "__main__":
    unittest.main()
