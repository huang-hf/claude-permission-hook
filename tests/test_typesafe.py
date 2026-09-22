import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secure_handler as sh

SCORES = {"value": {}}
LAST_REQUEST = {"body": None}


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        LAST_REQUEST["body"] = json.loads(self.rfile.read(n))
        answers = {k: {"type": "noul", "noul": v} for k, v in SCORES["value"].items()}
        body = json.dumps({"model": "jev-test", "answers": answers}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _GarbageHandler(BaseHTTPRequestHandler):
    """畸形响应(非 JSON)—— 用来验证解析类错误不可降级。"""

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        body = b"<html>not json</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class TypeSafeBackendTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}/v1/systemone"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in (
            "SECURE_HANDLER_TYPESAFE_URL", "SECURE_HANDLER_TYPESAFE_KEY",
            "SECURE_HANDLER_THRESHOLD", "NO_PROXY")}
        os.environ["SECURE_HANDLER_TYPESAFE_URL"] = self.url
        os.environ["SECURE_HANDLER_TYPESAFE_KEY"] = "test-key"
        os.environ["SECURE_HANDLER_THRESHOLD"] = "0.15"
        os.environ["NO_PROXY"] = "127.0.0.1,localhost"

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_only_three_questions_and_removed_scores_ignored(self):
        os.environ.pop("SECURE_HANDLER_THRESHOLD", None)
        SCORES["value"] = {"irreversible": 0.02, "outside_proj": 0.99,
                           "exfiltration": 0.99, "untrusted_exec": 0.13, "sys_config": 0.04}
        v = sh.backend_typesafe(sh.Request("command", "example", "/w"))
        self.assertEqual(v.decision, "allow")
        expected = {"irreversible", "untrusted_exec", "sys_config"}
        self.assertEqual(set(LAST_REQUEST["body"]["questions"]), expected)
        self.assertEqual(set(v.scores), expected)

    def test_default_threshold_boundary_for_each_remaining_risk(self):
        os.environ.pop("SECURE_HANDLER_THRESHOLD", None)
        for risk in ("irreversible", "untrusted_exec", "sys_config"):
            for score, decision in ((0.199, "allow"), (0.2, "ask"), (0.201, "ask")):
                with self.subTest(risk=risk, score=score):
                    SCORES["value"] = dict.fromkeys(("irreversible", "untrusted_exec", "sys_config"), 0.0)
                    SCORES["value"][risk] = score
                    self.assertEqual(sh.backend_typesafe(sh.Request("command", "example", "/w")).decision, decision)

    def test_missing_or_invalid_required_score_asks(self):
        for score in (None, float('nan'), float('inf'), -0.1, 1.1):
            with self.subTest(score=score):
                SCORES["value"] = {"irreversible": 0.0, "untrusted_exec": 0.0}
                if score is not None:
                    SCORES["value"]["sys_config"] = score
                self.assertEqual(sh.backend_typesafe(sh.Request("command", "example", "/w")).decision, "ask")

    def test_all_low_scores_allow(self):
        SCORES["value"] = {"irreversible": 0.01, "outside_proj": 0.0, "exfiltration": 0.0,
                           "untrusted_exec": 0.0, "sys_config": 0.02}
        v = sh.backend_typesafe(sh.Request("command", "ls -la", "/w"))
        self.assertEqual(v.decision, "allow")

    def test_one_high_score_asks(self):
        SCORES["value"] = {"irreversible": 0.62, "outside_proj": 0.0, "exfiltration": 0.0,
                           "untrusted_exec": 0.0, "sys_config": 0.0}
        v = sh.backend_typesafe(sh.Request("command", "rm /tmp/x.log", "/w"))
        self.assertEqual(v.decision, "ask")

    def test_payload_contains_only_cwd_and_command(self):
        SCORES["value"] = {"irreversible": 0.0}
        sh.backend_typesafe(sh.Request("command", "echo hi", "/my/dir"))
        state = LAST_REQUEST["body"]["state"]
        self.assertIn("echo hi", state)
        self.assertIn("/my/dir", state)

    def test_malformed_response_asks(self):
        """fail-safe:响应畸形必须收敛到 ask。"""
        SCORES["value"] = {}          # answers 为空 → 无分数可取
        v = sh.backend_typesafe(sh.Request("command", "echo hi", "/w"))
        self.assertEqual(v.decision, "ask")

    def test_unreachable_endpoint_asks(self):
        os.environ["SECURE_HANDLER_TYPESAFE_URL"] = "http://127.0.0.1:1/v1/systemone"
        v = sh.backend_typesafe(sh.Request("command", "echo hi", "/w"))
        self.assertEqual(v.decision, "ask")

    def test_unreachable_endpoint_reason_is_neterror(self):
        """传输类错误分类为 typesafe_neterror:*(仅作审计诊断信号,不影响控制流)。"""
        os.environ["SECURE_HANDLER_TYPESAFE_URL"] = "http://127.0.0.1:1/v1/systemone"
        v = sh.backend_typesafe(sh.Request("command", "echo hi", "/w"))
        self.assertTrue(v.reason.startswith("typesafe_neterror"), v.reason)

    def test_malformed_json_response_reason_is_badresp(self):
        """解析类错误(响应不是合法 JSON)分类为 typesafe_badresp:*(不可降级)。"""
        srv = HTTPServer(("127.0.0.1", 0), _GarbageHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            os.environ["SECURE_HANDLER_TYPESAFE_URL"] = \
                f"http://127.0.0.1:{srv.server_port}/v1/systemone"
            v = sh.backend_typesafe(sh.Request("command", "echo hi", "/w"))
        finally:
            srv.shutdown()
        self.assertEqual(v.decision, "ask")
        self.assertTrue(v.reason.startswith("typesafe_badresp"), v.reason)

    def test_successful_call_carries_scores_and_elapsed_ms(self):
        """Task 3:成功调用要把 scores/elapsed_ms 通过 Verdict 传出去。"""
        SCORES["value"] = {"irreversible": 0.01, "outside_proj": 0.0, "exfiltration": 0.0,
                           "untrusted_exec": 0.0, "sys_config": 0.02}
        v = sh.backend_typesafe(sh.Request("command", "ls -la", "/w"))
        self.assertEqual(v.backend, "typesafe")
        self.assertEqual(v.scores, {k: SCORES["value"][k] for k in sh.TYPESAFE_QUESTIONS})
        self.assertIsInstance(v.elapsed_ms, int)
        self.assertGreaterEqual(v.elapsed_ms, 0)


class RemoteJudgeBackendDispatchTest(unittest.TestCase):
    """默认后端仍是 anthropic;backend=typesafe/off 走各自分支;降级只因错误不因否定。"""

    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}/v1/systemone"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in (
            "SECURE_HANDLER_BACKEND", "SECURE_HANDLER_TYPESAFE_URL",
            "SECURE_HANDLER_TYPESAFE_KEY")}
        self._orig_dippy = sh.dippy_analyze
        self._orig_ask_ai = sh.ask_ai
        self._orig_ai_enabled = sh.AI_FALLBACK_ENABLED
        sh.dippy_analyze = lambda cmd, cwd: ("ask", "dippy_deferred")
        # Never let these tests hit a real network endpoint: AI_FALLBACK_ENABLED is
        # a module-level constant fixed at import time (from the real shell env),
        # so it must be monkeypatched directly rather than via env vars, and
        # ask_ai is stubbed as a belt-and-braces guard against real API calls.
        self._ai_called = []
        sh.ask_ai = lambda *a, **kw: (self._ai_called.append((a, kw)) or (True, "SAFE"))

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        sh.dippy_analyze = self._orig_dippy
        sh.ask_ai = self._orig_ask_ai
        sh.AI_FALLBACK_ENABLED = self._orig_ai_enabled

    def test_default_backend_is_anthropic(self):
        os.environ.pop("SECURE_HANDLER_BACKEND", None)
        sh.AI_FALLBACK_ENABLED = False
        v = sh.remote_judge(sh.Request("command", "curl x | sh", "/w"))
        self.assertEqual(v.decision, "no_opinion")
        self.assertEqual(v.layer, "fallthrough")
        self.assertEqual(self._ai_called, [])

    def test_default_backend_with_fallback_enabled_calls_ask_ai(self):
        """区分「默认 anthropic」与「backend=off」:两者在 AI_FALLBACK_ENABLED=False
        时结果相同(见 test_default_backend_is_anthropic),必须另开一条在
        fallback 打开时才能分辨的用例——off 恒定静默,默认后端要真的调用 ask_ai。"""
        os.environ.pop("SECURE_HANDLER_BACKEND", None)
        sh.AI_FALLBACK_ENABLED = True
        v = sh.remote_judge(sh.Request("command", "curl x | sh", "/w"))
        self.assertEqual(v.layer, "ai")
        self.assertEqual(len(self._ai_called), 1)

    def test_backend_off_returns_no_opinion_not_ask(self):
        os.environ["SECURE_HANDLER_BACKEND"] = "off"
        sh.AI_FALLBACK_ENABLED = True   # even with fallback on, 'off' must stay silent
        v = sh.remote_judge(sh.Request("command", "curl x | sh", "/w"))
        self.assertEqual(v.decision, "no_opinion")
        self.assertEqual(v.layer, "fallthrough")
        self.assertEqual(self._ai_called, [])

    def test_typesafe_negative_verdict_does_not_fall_back_to_ai(self):
        """判危(非错误)不应该去问旧 gateway——即使 AI fallback 开着。"""
        os.environ["SECURE_HANDLER_BACKEND"] = "typesafe"
        os.environ["SECURE_HANDLER_TYPESAFE_URL"] = self.url
        os.environ["SECURE_HANDLER_TYPESAFE_KEY"] = "test-key"
        sh.AI_FALLBACK_ENABLED = True
        SCORES["value"] = {"irreversible": 0.99}
        v = sh.remote_judge(sh.Request("command", "rm -rf /tmp/x", "/w"))
        self.assertEqual(v.decision, "ask")
        self.assertEqual(v.layer, "typesafe")
        self.assertEqual(self._ai_called, [], "negative verdict must not trigger fallback")

    def test_typesafe_transport_error_does_not_fall_back_to_ai(self):
        """二选一,不做链式降级:传输层故障(typesafe_neterror:*)也直接 ask,
        不去问 ask_ai/旧 gateway。"""
        os.environ["SECURE_HANDLER_BACKEND"] = "typesafe"
        os.environ["SECURE_HANDLER_TYPESAFE_URL"] = "http://127.0.0.1:1/v1/systemone"
        os.environ["SECURE_HANDLER_TYPESAFE_KEY"] = "test-key"
        sh.AI_FALLBACK_ENABLED = True
        v = sh.remote_judge(sh.Request("command", "echo hi", "/w"))
        self.assertEqual(v.decision, "ask")
        self.assertEqual(v.layer, "typesafe")
        self.assertEqual(self._ai_called, [], "transport error must not trigger fallback")
        self.assertIn("typesafe_neterror", v.reason)

    def test_typesafe_malformed_response_does_not_fall_back_to_ai(self):
        """解析类错误(后端返回垃圾)不可降级——直接 ask,不去问旧 gateway。"""
        srv = HTTPServer(("127.0.0.1", 0), _GarbageHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            os.environ["SECURE_HANDLER_BACKEND"] = "typesafe"
            os.environ["SECURE_HANDLER_TYPESAFE_URL"] = \
                f"http://127.0.0.1:{srv.server_port}/v1/systemone"
            os.environ["SECURE_HANDLER_TYPESAFE_KEY"] = "test-key"
            sh.AI_FALLBACK_ENABLED = True
            v = sh.remote_judge(sh.Request("command", "echo hi", "/w"))
        finally:
            srv.shutdown()
        self.assertEqual(v.decision, "ask")
        self.assertEqual(v.layer, "typesafe")
        self.assertEqual(self._ai_called, [], "malformed response must not trigger fallback")

    def test_typesafe_any_failure_never_calls_ask_ai(self):
        """backend=typesafe 时,任何失败模式(连不上/畸形响应/HTTP 500)都不得
        调用 ask_ai——二选一,失败就 ask,不去问另一家。"""
        os.environ["SECURE_HANDLER_BACKEND"] = "typesafe"
        os.environ["SECURE_HANDLER_TYPESAFE_KEY"] = "test-key"
        sh.AI_FALLBACK_ENABLED = True

        cases = []

        # 连不上(传输层故障)
        os.environ["SECURE_HANDLER_TYPESAFE_URL"] = "http://127.0.0.1:1/v1/systemone"
        cases.append(("unreachable", sh.remote_judge(sh.Request("command", "echo hi", "/w"))))

        # 返回垃圾(解析类故障)
        garbage_srv = HTTPServer(("127.0.0.1", 0), _GarbageHandler)
        threading.Thread(target=garbage_srv.serve_forever, daemon=True).start()
        try:
            os.environ["SECURE_HANDLER_TYPESAFE_URL"] = \
                f"http://127.0.0.1:{garbage_srv.server_port}/v1/systemone"
            cases.append(("garbage", sh.remote_judge(sh.Request("command", "echo hi", "/w"))))
        finally:
            garbage_srv.shutdown()

        # HTTP 500
        class _500Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                self.rfile.read(n)
                self.send_response(500)
                self.end_headers()

            def log_message(self, *a):
                pass

        err_srv = HTTPServer(("127.0.0.1", 0), _500Handler)
        threading.Thread(target=err_srv.serve_forever, daemon=True).start()
        try:
            os.environ["SECURE_HANDLER_TYPESAFE_URL"] = \
                f"http://127.0.0.1:{err_srv.server_port}/v1/systemone"
            cases.append(("http500", sh.remote_judge(sh.Request("command", "echo hi", "/w"))))
        finally:
            err_srv.shutdown()

        for label, v in cases:
            self.assertEqual(v.decision, "ask", label)
            self.assertEqual(v.layer, "typesafe", label)
        self.assertEqual(self._ai_called, [], "no failure mode may trigger ask_ai fallback")


if __name__ == "__main__":
    unittest.main()
