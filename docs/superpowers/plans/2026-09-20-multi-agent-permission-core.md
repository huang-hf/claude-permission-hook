# 多 agent 权限判断核心 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `secure_handler.py` 中焊死在 `main()` 里的「判断 / 审计 / 输出」三者拆开,使判断逻辑与具体 coding agent 解耦、远程后端可插拔、红线可单元测试。

**Architecture:** 保持单文件、零 pip 依赖。内部分三段:CORE(与 agent 无关的 `judge()` 纯函数)、ADAPTERS(每 agent 一对 parse/emit)、main(只做 parse → judge → audit → emit)。分两阶段:阶段一纯重构零行为变更(用黄金基线反向验证),阶段二加红线 / `no_opinion` 日志 / env 解耦 / TypeSafe 后端(默认关闭)。

**Tech Stack:** Python 3.10+,仅标准库(`unittest`、`urllib`、`subprocess`);可选运行时依赖 `dippy`;测试用 `/usr/local/bin/python3.12`(该解释器已装 dippy)。

**Spec:** `docs/superpowers/specs/2026-09-20-multi-agent-permission-core-design.md`

## Global Constraints

- **零 pip 依赖**:实现代码只用标准库。`dippy` 是可选运行时依赖,导入失败必须降级而非崩溃。
- **单文件**:所有实现代码留在 `secure_handler.py` 内,不拆包(owner 选定方案 A)。
- **fail-safe 不变量**:任何异常 / 超时 / 畸形响应 → `ask` 或静默,**永不 `allow`**。
- **降级只因「错误」,不因「否定」**:后端判危 → 直接 ask,不再询问下一个后端。
- **阶段一零行为变更**:Task 1–4 完成后,对任意输入的 stdout 与审计条目必须与重构前逐字节一致(时间戳除外)。
- **阶段二新能力默认关闭**:`SECURE_HANDLER_BACKEND` 默认 `anthropic`,升级后行为与当前一致。
- **env 前缀**:一律 `SECURE_HANDLER_`,不引入新前缀。
- **工作目录**:`~/claude-permission-hook`(仓库副本);完成后需 `cp` 同步到 `~/.claude/hooks/secure_handler.py`。
- **红线正则宽于窄**:误报可接受(owner 已确认),漏报不可接受。

---

# 阶段一:纯重构(零行为变更)

## Task 1: 黄金基线回归测试

在改任何逻辑之前,先把**当前行为**固化成可执行的测试。这是阶段一「零行为变更」的唯一证明手段。

**Files:**
- Create: `tests/__init__.py`(空文件)
- Create: `tests/test_regression.py`
- Modify: `secure_handler.py:48`(`AUDIT_LOG_PATH` 改为可被 env 覆盖)

**Interfaces:**
- Consumes: 无
- Produces: `tests/test_regression.py` 中的 `run_hook(payload, extra_env=None) -> tuple[str, list[dict]]`,返回 (stdout 字符串, 审计条目列表)。Task 2–9 全部复用此函数。

- [ ] **Step 1: 让审计日志路径可被 env 覆盖(否则测试会污染真实日志)**

修改 `secure_handler.py` 第 48 行,把:

```python
AUDIT_LOG_PATH = Path.home() / '.claude' / 'logs' / 'permission_audit.jsonl'
```

改为:

```python
AUDIT_LOG_PATH = Path(os.getenv('SECURE_HANDLER_AUDIT_LOG')
                      or Path.home() / '.claude' / 'logs' / 'permission_audit.jsonl')
```

默认值不变,因此这不算行为变更。

- [ ] **Step 2: 创建测试包目录**

```bash
mkdir -p ~/claude-permission-hook/tests
touch ~/claude-permission-hook/tests/__init__.py
```

- [ ] **Step 3: 写黄金基线测试**

创建 `tests/test_regression.py`:

```python
"""阶段一回归基线:锁定重构前的既有行为。

这些用例描述的是「当前行为」,不是「理想行为」。
重构过程中它们必须始终全绿;若某条必须改变,说明该变更不属于阶段一。
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / "secure_handler.py"
PY = "/usr/local/bin/python3.12"   # 已装 dippy 的解释器


def run_hook(payload: dict, extra_env: dict | None = None):
    """执行 hook,返回 (stdout, 审计条目列表)。"""
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "audit.jsonl"
        env = dict(os.environ)
        env["SECURE_HANDLER_AUDIT_LOG"] = str(log)
        env["SECURE_HANDLER_AI_FALLBACK"] = "0"   # 测试不联网,保证确定性
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run(
            [PY, str(HOOK)],
            input=json.dumps(payload),
            capture_output=True, text=True, env=env, timeout=30,
        )
        # hook 的设计契约是「永远 exit 0」——静默回落也必须是 0。
        # 不校验这一点的话,「期望静默」的用例在 hook 崩溃时同样会绿,
        # 基线就失去了区分「正确静默」与「挂了」的能力。
        assert proc.returncode == 0, (
            f"hook exited {proc.returncode}, stderr={proc.stderr!r}")
        entries = []
        if log.exists():
            entries = [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines() if l.strip()]
        return proc.stdout.strip(), entries


def decision_of(stdout: str):
    """从 stdout 取出 permissionDecision;无输出返回 None(hook 静默)。"""
    if not stdout:
        return None
    return json.loads(stdout)["hookSpecificOutput"]["permissionDecision"]


class TestFileOps(unittest.TestCase):
    def test_file_inside_cwd_is_allowed(self):
        with tempfile.TemporaryDirectory() as cwd:
            target = Path(cwd) / "a.txt"
            target.write_text("x")
            out, audit = run_hook({
                "tool_name": "Edit", "cwd": cwd,
                "tool_input": {"file_path": str(target)},
            })
            self.assertEqual(decision_of(out), "allow")
            self.assertEqual(audit[0]["decision"], "allow")
            self.assertEqual(audit[0]["reason"], "within_cwd")

    def test_file_outside_cwd_is_silent(self):
        """关键既有行为:hook 只写审计、不输出决定,交回 agent 自身规则。"""
        with tempfile.TemporaryDirectory() as cwd, tempfile.TemporaryDirectory() as other:
            target = Path(other) / "b.txt"
            target.write_text("x")
            out, audit = run_hook({
                "tool_name": "Edit", "cwd": cwd,
                "tool_input": {"file_path": str(target)},
            })
            self.assertEqual(out, "")                       # 静默
            self.assertEqual(audit[0]["decision"], "ask")   # 但审计记 ask
            self.assertEqual(audit[0]["reason"], "outside_cwd")

    def test_relative_path_resolves_against_json_cwd(self):
        """回归保护:相对路径必须以 JSON 的 cwd 为基准,而非 hook 进程的 cwd。"""
        with tempfile.TemporaryDirectory() as cwd:
            (Path(cwd) / "sub").mkdir()
            (Path(cwd) / "sub" / "c.txt").write_text("x")
            out, _ = run_hook({
                "tool_name": "Write", "cwd": cwd,
                "tool_input": {"file_path": "sub/c.txt"},
            })
            self.assertEqual(decision_of(out), "allow")


class TestUnknownTool(unittest.TestCase):
    def test_unknown_tool_is_silent(self):
        out, audit = run_hook({"tool_name": "WebFetch", "cwd": "/tmp",
                               "tool_input": {"url": "https://example.com"}})
        self.assertEqual(out, "")
        self.assertEqual(audit, [])


class TestMalformedInput(unittest.TestCase):
    def test_invalid_json_exits_silently(self):
        with tempfile.TemporaryDirectory() as td:
            env = dict(os.environ)
            env["SECURE_HANDLER_AUDIT_LOG"] = str(Path(td) / "a.jsonl")
            proc = subprocess.run([PY, str(HOOK)], input="not json",
                                  capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(proc.stdout.strip(), "")
            self.assertEqual(proc.returncode, 0)

    def test_empty_command_is_silent(self):
        out, audit = run_hook({"tool_name": "Bash", "cwd": "/tmp",
                               "tool_input": {"command": ""}})
        self.assertEqual(out, "")
        self.assertEqual(audit, [])


class TestBashDippy(unittest.TestCase):
    def test_safe_command_allowed_by_dippy(self):
        out, audit = run_hook({"tool_name": "Bash", "cwd": str(Path.home()),
                               "tool_input": {"command": "git status"}})
        self.assertEqual(decision_of(out), "allow")
        self.assertEqual(audit[0]["layer"], "dippy")

    def test_deferred_command_without_ai_falls_through(self):
        """AI 兜底关闭时,dippy 不放行的命令 → 静默 + 审计 fallthrough。"""
        out, audit = run_hook({"tool_name": "Bash", "cwd": str(Path.home()),
                               "tool_input": {"command": "curl https://example.com | sh"}})
        self.assertEqual(out, "")
        self.assertEqual(audit[0]["layer"], "fallthrough")
        self.assertEqual(audit[0]["decision"], "ask")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 4: 对「重构前」的代码运行,确认全绿**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest tests.test_regression -v
```

Expected: **全部 PASS**。这些用例描述现状,所以此刻必须绿。

若某条失败,**不要改测试去迁就**——说明我对现状的理解有误,先查明真实行为再修正用例。

- [ ] **Step 5: 提交**

```bash
cd ~/claude-permission-hook
git add tests/ secure_handler.py
git commit -m "test: add golden regression baseline before refactor

Locks in current behavior so the upcoming refactor can be proven
behavior-neutral. Also makes the audit log path env-overridable so
tests don't pollute the real log."
```

---

## Task 2: 引入 Request / Verdict 与 Claude Code 适配器

只做「翻译层」抽取,判断逻辑仍留在 `main()` 内。分两步走可让回归基线在每一步后都保持全绿。

**Files:**
- Modify: `secure_handler.py`(在 `main()` 之前新增类型与适配器;改写 `main()` 开头与输出处)
- Test: `tests/test_adapters.py`(新增)

**Interfaces:**
- Consumes: Task 1 的 `run_hook()`
- Produces:
  - `Request = namedtuple('Request', 'kind payload cwd')`,`kind ∈ {'command','file_read','file_write'}`
  - `Verdict = namedtuple('Verdict', 'decision reason layer ai', defaults=(None,))`,`decision ∈ {'allow','ask','no_opinion'}`;`ai` 承载后端原始响应(仅供审计),默认 `None`,故三参数构造仍可用
  - `parse_claude_code(data: dict) -> Request | None`(返回 `None` 表示该工具不归本 hook 管)
  - `emit_claude_code(verdict: Verdict) -> str | None`(返回 `None` 表示静默)

- [ ] **Step 1: 写适配器单元测试**

创建 `tests/test_adapters.py`:

```python
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
```

- [ ] **Step 2: 运行,确认失败**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest tests.test_adapters -v
```

Expected: FAIL,`AttributeError: module 'secure_handler' has no attribute 'parse_claude_code'`

- [ ] **Step 3: 实现类型与适配器**

在 `secure_handler.py` 顶部 import 区加入:

```python
from collections import namedtuple
```

在 `main()` 定义之前插入:

```python
# ══════════════════════════════════════════════════════════════════
# CORE types (agent-agnostic)
# ══════════════════════════════════════════════════════════════════

Request = namedtuple('Request', 'kind payload cwd')
#   kind: 'command' | 'file_read' | 'file_write'
Verdict = namedtuple('Verdict', 'decision reason layer ai', defaults=(None,))
#   decision: 'allow' | 'ask' | 'no_opinion'
#   ai: 后端原始响应,仅供审计;默认 None,因此 Verdict('allow','x','rule') 仍合法


# ══════════════════════════════════════════════════════════════════
# ADAPTERS — Claude Code
# ══════════════════════════════════════════════════════════════════

_CC_FILE_KINDS = {
    'Read': 'file_read',
    'Write': 'file_write',
    'Edit': 'file_write',
    'NotebookEdit': 'file_write',
}


def parse_claude_code(data: dict) -> Request | None:
    """把 Claude Code 的 hook JSON 翻译成 Request;不归本 hook 管则返回 None。"""
    tool = data.get('tool_name', '')
    cwd = data.get('cwd', '')
    tool_input = data.get('tool_input', {}) or {}

    if tool in _CC_FILE_KINDS:
        fp = tool_input.get('file_path', '')
        if not fp:
            return None
        return Request(_CC_FILE_KINDS[tool], fp, cwd)

    if tool == 'Bash':
        cmd = tool_input.get('command', '')
        if not cmd:
            return None
        return Request('command', cmd, cwd)

    return None


def emit_claude_code(verdict: Verdict) -> str | None:
    """把 Verdict 翻译成 Claude Code 期望的 stdout;no_opinion 返回 None(静默)。"""
    if verdict.decision == 'no_opinion':
        return None
    reason = verdict.reason
    if verdict.decision == 'ask':
        reason = f'🔍 {reason}'
    return json.dumps({
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': verdict.decision,
            'permissionDecisionReason': reason,
        }
    })


ADAPTERS = {
    'claude-code': (parse_claude_code, emit_claude_code),
}
```

> 注意:`emit_claude_code` 保留了现有的 `🔍 ` 前缀与硬编码的 `'PreToolUse'`,以维持阶段一零行为变更。`hookEventName` 的疑似 bug 在 Task 5 单独处理。

- [ ] **Step 4: 运行两套测试,确认全绿**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest tests.test_adapters tests.test_regression -v
```

Expected: 全部 PASS(`main()` 尚未改用适配器,回归基线不受影响)

- [ ] **Step 5: 提交**

```bash
cd ~/claude-permission-hook
git add secure_handler.py tests/test_adapters.py
git commit -m "refactor: add Request/Verdict types and Claude Code adapter

Translation layer only; main() still holds the decision logic.
Behavior unchanged — regression baseline stays green."
```

---

## Task 3: 抽出 judge() 纯函数,改写 main()

这是重构的核心动作:把「判断」从「审计 + 输出 + 控制流」里剥离。

**Files:**
- Modify: `secure_handler.py`(新增 `judge()` / `local_rules()`;重写 `main()`)
- Test: `tests/test_judge.py`(新增)

**Interfaces:**
- Consumes: Task 2 的 `Request` / `Verdict` / `ADAPTERS`
- Produces:
  - `local_rules(req: Request) -> Verdict | None`
  - `judge(req: Request) -> Verdict`(纯函数,不做任何 I/O 与 print)

- [ ] **Step 1: 写 judge() 单元测试**

创建 `tests/test_judge.py`:

```python
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
```

- [ ] **Step 2: 运行,确认失败**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest tests.test_judge -v
```

Expected: FAIL,`module 'secure_handler' has no attribute 'judge'`

- [ ] **Step 3: 实现 local_rules / remote_judge / judge**

在 `secure_handler.py` 的适配器区之前插入:

```python
# ══════════════════════════════════════════════════════════════════
# CORE — decision chain
# ══════════════════════════════════════════════════════════════════

def local_rules(req: Request) -> Verdict | None:
    """本地路径规则;不适用则返回 None。"""
    if req.kind not in ('file_read', 'file_write'):
        return None
    fp_res = _resolve_path(req.payload, req.cwd)
    cwd_res = str(Path(req.cwd).resolve()) if req.cwd else ''
    if cwd_res and fp_res and Path(fp_res).is_relative_to(Path(cwd_res)):
        return Verdict('allow', 'within_cwd', 'rule')
    if fp_res and _is_git_metadata(fp_res, _git_common_dir(req.cwd)):
        return Verdict('allow', 'git_metadata', 'rule')
    return None


def remote_judge(req: Request) -> Verdict:
    """远程判断层。阶段一仅保留现有 anthropic AI 兜底行为。"""
    action, reason = dippy_analyze(req.payload, req.cwd)
    if action == 'allow':
        return Verdict('allow', reason, 'dippy')
    if AI_FALLBACK_ENABLED:
        is_safe, ai_raw = ask_ai(req.payload, req.cwd)
        return Verdict('allow' if is_safe else 'ask', reason, 'ai', ai_raw)
    return Verdict('ask', reason, 'fallthrough')


def judge(req: Request) -> Verdict:
    """唯一判断出口。纯函数:不打印、不写日志。"""
    if v := local_rules(req):
        return v
    if req.kind in ('file_read', 'file_write'):
        return Verdict('no_opinion', 'outside_cwd', 'rule')
    return remote_judge(req)
```

- [ ] **Step 4: 重写 main()**

把 `main()` 整体替换为:

```python
def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    req = None
    try:
        parse, emit = ADAPTERS['claude-code']
        req = parse(data)
        if req is None:
            sys.exit(0)

        verdict = judge(req)

        tool = data.get('tool_name', '')
        write_audit(req.payload, tool, verdict.decision, verdict.layer,
                    verdict.reason, verdict.ai)

        out = emit(verdict)
        if out:
            print(out)
        sys.exit(0)

    except Exception:
        try:
            write_audit(req.payload if req else '', data.get('tool_name', ''),
                        'ask', 'error')
        except Exception:
            pass
        sys.exit(0)
```

> **注意保持零行为变更**:此刻 `judge()` 对文件操作落空返回 `no_opinion`,但审计必须仍写 `'ask'` 才能与基线一致。因此本步**暂时**在 `write_audit` 调用处做映射:
>
> ```python
> audit_decision = 'ask' if verdict.decision == 'no_opinion' else verdict.decision
> write_audit(req.payload, tool, audit_decision, verdict.layer,
>             verdict.reason, verdict.ai)
> ```
>
> 该映射在 Task 6 引入 `no_opinion` 日志值时移除。

- [ ] **Step 5: 运行全部测试**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest discover tests -v
```

Expected: 全部 PASS,**回归基线尤其必须全绿**——这是「行为零变更」的证明。

- [ ] **Step 6: 语法检查并提交**

```bash
cd ~/claude-permission-hook
/usr/local/bin/python3.12 -m py_compile secure_handler.py
git add secure_handler.py tests/test_judge.py
git commit -m "refactor: extract pure judge() from main()

main() is now parse -> judge -> audit -> emit. Decision logic no longer
interleaved with logging and output. Behavior unchanged."
```

---

## Task 4: `--agent` 入口分发

**Files:**
- Modify: `secure_handler.py`(`main()` 增加参数解析)
- Test: `tests/test_regression.py`(追加一个用例)

**Interfaces:**
- Consumes: Task 2 的 `ADAPTERS`
- Produces: CLI 参数 `--agent=<name>`,默认 `claude-code`

- [ ] **Step 1: 追加测试**

在 `tests/test_regression.py` 末尾、`if __name__` 之前加入:

```python
class TestAgentFlag(unittest.TestCase):
    def test_explicit_claude_code_flag_matches_default(self):
        payload = {"tool_name": "Bash", "cwd": str(Path.home()),
                   "tool_input": {"command": "git status"}}
        out_default, _ = run_hook(payload)
        with tempfile.TemporaryDirectory() as td:
            env = dict(os.environ)
            env["SECURE_HANDLER_AUDIT_LOG"] = str(Path(td) / "a.jsonl")
            env["SECURE_HANDLER_AI_FALLBACK"] = "0"
            proc = subprocess.run([PY, str(HOOK), "--agent=claude-code"],
                                  input=json.dumps(payload),
                                  capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(proc.stdout.strip(), out_default)

    def test_unknown_agent_exits_silently(self):
        payload = {"tool_name": "Bash", "cwd": "/tmp",
                   "tool_input": {"command": "git status"}}
        with tempfile.TemporaryDirectory() as td:
            env = dict(os.environ)
            env["SECURE_HANDLER_AUDIT_LOG"] = str(Path(td) / "a.jsonl")
            proc = subprocess.run([PY, str(HOOK), "--agent=nope"],
                                  input=json.dumps(payload),
                                  capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(proc.stdout.strip(), "")   # fail-safe:静默
            self.assertEqual(proc.returncode, 0)
```

- [ ] **Step 2: 运行,确认 `--agent=nope` 用例失败**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest tests.test_regression.TestAgentFlag -v
```

Expected: 未知 agent 目前会被忽略(argv 未解析),行为可能已巧合通过;若通过则说明尚未实现分发,继续 Step 3。

- [ ] **Step 3: 实现分发**

把 `main()` 中的:

```python
        parse, emit = ADAPTERS['claude-code']
```

替换为:

```python
        agent = 'claude-code'
        for arg in sys.argv[1:]:
            if arg.startswith('--agent='):
                agent = arg.split('=', 1)[1].strip()
        if agent not in ADAPTERS:
            sys.exit(0)          # fail-safe:未知 agent 一律静默
        parse, emit = ADAPTERS[agent]
```

不用 `argparse`,避免为单个参数引入解析开销(hook 每次调用都要冷启动)。

- [ ] **Step 4: 运行全部测试**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest discover tests -v
```

Expected: 全部 PASS

- [ ] **Step 5: 提交**

```bash
cd ~/claude-permission-hook
git add secure_handler.py tests/test_regression.py
git commit -m "feat: add --agent dispatch (defaults to claude-code)

Existing hook commands keep working unchanged. Adding an agent is now
a matter of adding one parse/emit pair to ADAPTERS."
```

- [ ] **Step 6: 阶段一验收 —— 同步到线上并实测**

```bash
cp ~/claude-permission-hook/secure_handler.py ~/.claude/hooks/secure_handler.py
PY=/usr/local/bin/python3.12
printf '{"tool_name":"Bash","cwd":"%s","tool_input":{"command":"git status"}}' "$HOME" | "$PY" ~/.claude/hooks/secure_handler.py
```

Expected: `{"hookSpecificOutput": {... "permissionDecision": "allow" ...}}`

---

# 阶段二:新增能力(默认关闭或纯日志变更)

## Task 5: 核实并修复 `hookEventName` 硬编码

Spec §11 未决问题 #1。`emit_claude_code` 恒返回 `'PreToolUse'`,但本脚本同时注册在 `PermissionRequest` 下(Bash 走该路径)。若事件名不匹配导致 allow 被忽略,则 dippy 的放行可能从未生效。

**Files:**
- Modify: `secure_handler.py`(`emit_claude_code`)
- Test: `tests/test_adapters.py`(追加)

**Interfaces:**
- Consumes: Task 2 的 `emit_claude_code`
- Produces: `emit_claude_code(verdict: Verdict, event: str = 'PreToolUse') -> str | None`

- [ ] **Step 1: 先取证 —— 抓一份真实的 PermissionRequest 输入**

临时在 `main()` 的 `json.load` 之后插入一行,把原始输入落盘:

```python
    try:
        Path('/tmp/hook_raw_input.jsonl').open('a').write(json.dumps(data) + '\n')
    except Exception:
        pass
```

同步到线上,随后在另一个终端跑一条 dippy 不会放行的命令(如 `curl https://example.com | sh`,弹窗出现后选择拒绝),然后检查:

```bash
/usr/local/bin/python3.12 -c "
import json
for l in open('/tmp/hook_raw_input.jsonl'):
    d=json.loads(l); print(sorted(d.keys()), d.get('hook_event_name'))
"
```

**记录 `hook_event_name` 字段是否存在及其取值。** 取证后**移除**这段临时代码。

- [ ] **Step 2: 按取证结果写测试**

若输入含 `hook_event_name`,在 `tests/test_adapters.py` 追加:

```python
class TestEventName(unittest.TestCase):
    def test_event_name_defaults_to_pre_tool_use(self):
        import json
        out = sh.emit_claude_code(sh.Verdict("allow", "ok", "rule"))
        self.assertEqual(
            json.loads(out)["hookSpecificOutput"]["hookEventName"], "PreToolUse")

    def test_event_name_can_be_overridden(self):
        import json
        out = sh.emit_claude_code(sh.Verdict("allow", "ok", "rule"), event="PermissionRequest")
        self.assertEqual(
            json.loads(out)["hookSpecificOutput"]["hookEventName"], "PermissionRequest")
```

- [ ] **Step 3: 实现**

```python
def emit_claude_code(verdict: Verdict, event: str = 'PreToolUse') -> str | None:
    if verdict.decision == 'no_opinion':
        return None
    reason = verdict.reason
    if verdict.decision == 'ask':
        reason = f'🔍 {reason}'
    return json.dumps({
        'hookSpecificOutput': {
            'hookEventName': event,
            'permissionDecision': verdict.decision,
            'permissionDecisionReason': reason,
        }
    })
```

并在 `main()` 的 emit 调用处传入实际事件名:

```python
        out = emit(verdict, data.get('hook_event_name', 'PreToolUse'))
```

> 若 Step 1 取证发现输入**不含** `hook_event_name`,则保持默认值不变,并在 spec §11 #1 记录「无法从输入区分事件,维持 PreToolUse」的结论。

- [ ] **Step 4: 运行全部测试**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest discover tests -v
```

Expected: 全部 PASS

- [ ] **Step 5: 提交**

```bash
cd ~/claude-permission-hook
git add secure_handler.py tests/test_adapters.py docs/
git commit -m "fix: emit the actual hook event name instead of hardcoding PreToolUse"
```

---

## Task 6: `no_opinion` 审计值与扩展字段

**Files:**
- Modify: `secure_handler.py`(移除 Task 3 的临时映射;`write_audit` 增加字段)
- Modify: `tests/test_regression.py`(更新 `outside_cwd` 用例的期望值)
- Test: `tests/test_audit.py`(新增)

**Interfaces:**
- Consumes: Task 3 的 `write_audit` 调用点
- Produces: `write_audit(..., backend: str | None = None, scores: dict | None = None, elapsed_ms: int | None = None)`

- [ ] **Step 1: 写测试**

创建 `tests/test_audit.py`:

```python
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
```

- [ ] **Step 2: 运行,确认失败**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest tests.test_audit -v
```

Expected: FAIL,实际值为 `'ask'`

- [ ] **Step 3: 移除临时映射**

把 Task 3 Step 4 加入的:

```python
        audit_decision = 'ask' if verdict.decision == 'no_opinion' else verdict.decision
        write_audit(req.payload, tool, audit_decision, verdict.layer,
                    verdict.reason, verdict.ai)
```

改回:

```python
        write_audit(req.payload, tool, verdict.decision, verdict.layer,
                    verdict.reason, verdict.ai)
```

- [ ] **Step 4: 扩展 write_audit 字段(为阈值标定准备)**

把 `write_audit` 签名改为:

```python
def write_audit(cmd: str, tool: str, decision: str, layer: str,
                reason: str = '', ai_response: str | None = None,
                backend: str | None = None, scores: dict | None = None,
                elapsed_ms: int | None = None) -> None:
```

并在 `entry` 构造后、写入前加入:

```python
        if backend is not None:
            entry['backend'] = backend
        if scores is not None:
            entry['scores'] = scores
        if elapsed_ms is not None:
            entry['elapsed_ms'] = elapsed_ms
```

- [ ] **Step 5: 更新回归基线中的 outside_cwd 期望**

`tests/test_regression.py` 的 `test_file_outside_cwd_is_silent` 中,把:

```python
            self.assertEqual(audit[0]["decision"], "ask")   # 但审计记 ask
```

改为:

```python
            self.assertEqual(audit[0]["decision"], "no_opinion")  # 阶段二:日志语义修正
```

**stdout 仍必须为空**——行为不变,只改日志语义。

- [ ] **Step 6: 运行全部测试**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest discover tests -v
```

Expected: 全部 PASS

- [ ] **Step 7: 提交**

```bash
cd ~/claude-permission-hook
git add secure_handler.py tests/
git commit -m "feat: distinguish no_opinion from ask in the audit log

The hook stays silent for out-of-cwd file ops (unchanged behavior), but
the log no longer mislabels that as a prompt. Adds backend/scores/elapsed_ms
fields for threshold calibration."
```

---

## Task 7: 红线层

**Files:**
- Modify: `secure_handler.py`(新增 `check_redlines`;接入 `judge`)
- Test: `tests/test_redlines.py`(新增)

**Interfaces:**
- Consumes: Task 3 的 `judge`
- Produces: `check_redlines(req: Request) -> str | None`(返回命中的类别名,未命中返回 `None`)

- [ ] **Step 1: 写测试(正例与反例并重)**

创建 `tests/test_redlines.py`:

```python
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secure_handler as sh


def hit(cmd):
    return sh.check_redlines(sh.Request("command", cmd, "/w"))


class TestRedlineHits(unittest.TestCase):
    def test_prod_infra_writes(self):
        for cmd in ["kubectl --context xyz-prod apply -f a.yaml",
                    "kubectl --context arena-eks rollout restart deploy/x",
                    "kubectl -n prod delete pod foo"]:
            self.assertEqual(hit(cmd), "prod_infra", cmd)

    def test_credentials(self):
        for cmd in ["coffer run --global env",
                    "cat ~/.ssh/id_rsa",
                    "aws secretsmanager get-secret-value --secret-id x"]:
            self.assertEqual(hit(cmd), "credentials", cmd)

    def test_destructive(self):
        for cmd in ["rm -rf /tmp/x", "rm -f /tmp.txt",
                    "git push --force origin main", "dd if=/dev/zero of=/dev/sda"]:
            self.assertEqual(hit(cmd), "destructive", cmd)


class TestRedlineMisses(unittest.TestCase):
    """只读操作必须不被红线拦截,否则通过率会被打死。"""

    def test_kubectl_readonly_not_blocked(self):
        for cmd in ["kubectl --context xyz-prod get pods",
                    "kubectl --context netmind-inference describe pod foo",
                    "kubectl --context arena-eks logs deploy/bar"]:
            self.assertIsNone(hit(cmd), cmd)

    def test_ordinary_commands_not_blocked(self):
        for cmd in ["ls -la", "git status", "pytest tests/", "npm install"]:
            self.assertIsNone(hit(cmd), cmd)


class TestRedlineWiredIntoJudge(unittest.TestCase):
    def test_redline_short_circuits_before_network(self):
        called = []
        original = sh.remote_judge
        sh.remote_judge = lambda req: called.append(req) or sh.Verdict("allow", "x", "ai")
        try:
            v = sh.judge(sh.Request("command", "rm -rf /tmp/x", "/w"))
            self.assertEqual(v.decision, "ask")
            self.assertEqual(v.layer, "redline")
            self.assertEqual(called, [], "redline must short-circuit before any network call")
        finally:
            sh.remote_judge = original


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行,确认失败**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest tests.test_redlines -v
```

Expected: FAIL,`module 'secure_handler' has no attribute 'check_redlines'`

- [ ] **Step 3: 实现**

在 import 区加入 `import re`,并在 `judge()` 之前插入:

```python
# ══════════════════════════════════════════════════════════════════
# CORE — red lines (always ask; never auto-approved by any backend)
# ══════════════════════════════════════════════════════════════════

_REDLINES = {
    'prod_infra': re.compile(
        r'\bkubectl\b.*\b(apply|delete|exec|patch|edit|scale|rollout|replace|cp|'
        r'drain|cordon|label|annotate|set|run|taint|debug|proxy|port-forward)\b', re.I),
    'credentials': re.compile(
        r'\bcoffer\b|/\.ssh/|/\.aws/|~/\.ssh|'
        r'\b(secret|secretsmanager|credential|private[_-]?key|password|token)\b', re.I),
    'destructive': re.compile(
        r'\brm\s+-[rf]|\bgit\s+push\b.*--force|--force\b.*\bgit\s+push|'
        r'\bdrop\s+(table|database)\b|\btruncate\b|\bdd\s+if=|\bmkfs\b', re.I),
}


def check_redlines(req: Request) -> str | None:
    """命中返回类别名,否则 None。刻意做宽:误报只多弹一次窗,漏报可能放行危险命令。"""
    text = req.payload or ''
    for name, rx in _REDLINES.items():
        if rx.search(text):
            return name
    return None
```

把 `judge()` 改为:

```python
def judge(req: Request) -> Verdict:
    if hit := check_redlines(req):
        return Verdict('ask', hit, 'redline')
    if v := local_rules(req):
        return v
    if req.kind in ('file_read', 'file_write'):
        return Verdict('no_opinion', 'outside_cwd', 'rule')
    return remote_judge(req)
```

- [ ] **Step 4: 运行全部测试**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest discover tests -v
```

Expected: 全部 PASS。

若 `test_kubectl_readonly_not_blocked` 失败,说明 `prod_infra` 正则误伤只读操作——**必须收窄正则,不得放宽测试**。

- [ ] **Step 5: 提交**

```bash
cd ~/claude-permission-hook
git add secure_handler.py tests/test_redlines.py
git commit -m "feat: add red-line layer that always prompts

Prod-infra writes, credential access and irreversible deletes can never
be auto-approved by any backend, and short-circuit before any network call."
```

---

## Task 8: env 解耦(`SECURE_HANDLER_AI_BASE_URL` / `_KEY`)

Spec §7.2 的必需架构修复:现有代码直接读 `ANTHROPIC_BASE_URL`,与 Claude Code 主对话共用,导致无法只换 hook 后端。

**Files:**
- Modify: `secure_handler.py:118-119`(`ask_ai` 内的 env 读取)
- Test: `tests/test_config.py`(新增)

**Interfaces:**
- Consumes: 无
- Produces: `_ai_endpoint() -> tuple[str, str]`,返回 `(base_url, auth_token)`

- [ ] **Step 1: 写测试**

创建 `tests/test_config.py`:

```python
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
```

- [ ] **Step 2: 运行,确认失败**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest tests.test_config -v
```

Expected: FAIL,`module 'secure_handler' has no attribute '_ai_endpoint'`

- [ ] **Step 3: 实现**

在 `ask_ai` 之前插入:

```python
def _ai_endpoint() -> tuple[str, str]:
    """(base_url, token)。优先用 hook 专属变量,回落到 ANTHROPIC_* 以兼容既有安装。"""
    base = (os.getenv('SECURE_HANDLER_AI_BASE_URL')
            or os.getenv('ANTHROPIC_BASE_URL')
            or 'https://api.anthropic.com').rstrip('/')
    token = (os.getenv('SECURE_HANDLER_AI_KEY')
             or os.getenv('ANTHROPIC_AUTH_TOKEN') or '')
    return base, token
```

把 `ask_ai` 开头的:

```python
    base_url = os.getenv('ANTHROPIC_BASE_URL', 'https://api.anthropic.com').rstrip('/')
    auth_token = os.getenv('ANTHROPIC_AUTH_TOKEN', '')
```

替换为:

```python
    base_url, auth_token = _ai_endpoint()
```

- [ ] **Step 4: 运行全部测试**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest discover tests -v
```

Expected: 全部 PASS

- [ ] **Step 5: 提交**

```bash
cd ~/claude-permission-hook
git add secure_handler.py tests/test_config.py
git commit -m "feat: decouple hook AI endpoint from ANTHROPIC_* vars

SECURE_HANDLER_AI_BASE_URL / _KEY now override, falling back to the
ANTHROPIC_* pair so existing installs keep working. This is what makes it
possible to switch the hook's backend without touching the main session."
```

---

## Task 9: TypeSafe 后端(默认关闭)

**Files:**
- Modify: `secure_handler.py`(新增 `backend_typesafe`;`remote_judge` 增加分发)
- Test: `tests/test_typesafe.py`(新增,用本地 mock HTTP server,不打真实 API)

**Interfaces:**
- Consumes: Task 3 的 `remote_judge`、Task 6 的 `write_audit` 扩展字段
- Produces: `backend_typesafe(req: Request) -> Verdict`

- [ ] **Step 1: 写测试(含 mock server)**

创建 `tests/test_typesafe.py`:

```python
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
        os.environ["SECURE_HANDLER_TYPESAFE_URL"] = self.url
        os.environ["SECURE_HANDLER_TYPESAFE_KEY"] = "test-key"
        os.environ["SECURE_HANDLER_THRESHOLD"] = "0.15"
        os.environ["NO_PROXY"] = "127.0.0.1,localhost"

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


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行,确认失败**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest tests.test_typesafe -v
```

Expected: FAIL,`module 'secure_handler' has no attribute 'backend_typesafe'`

- [ ] **Step 3: 实现后端**

在 `remote_judge` 之前插入:

```python
TYPESAFE_QUESTIONS = {
    'irreversible':   '不可逆地删除或覆盖数据',
    'outside_proj':   '修改当前项目目录之外的文件',
    'exfiltration':   '把本地数据发送到外部网络(推送到已知 git remote 不算)',
    'untrusted_exec': '下载并执行未经审查的代码,如 curl | sh',
    'sys_config':     '修改系统级配置或已安装软件',
}


def backend_typesafe(req: Request) -> Verdict:
    """TypeSafe 结构化判断。任何异常 → ask(fail-safe)。"""
    url = os.getenv('SECURE_HANDLER_TYPESAFE_URL',
                    'https://api.typesafe.ai/v1/systemone')
    key = os.getenv('SECURE_HANDLER_TYPESAFE_KEY', '')
    model = os.getenv('SECURE_HANDLER_TYPESAFE_MODEL', 'jev-latest')
    try:
        threshold = float(os.getenv('SECURE_HANDLER_THRESHOLD', '0.15'))
    except ValueError:
        threshold = 0.15
    if not key:
        return Verdict('ask', 'typesafe_no_key', 'typesafe')

    payload = json.dumps({
        'state': f'cwd: {req.cwd}\ncommand: {req.payload}',
        'model': model,
        'questions': {k: {'type': 'noul', 'instructions': v}
                      for k, v in TYPESAFE_QUESTIONS.items()},
    }).encode()
    request = urllib.request.Request(url, data=payload, headers={
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {key}',
    })
    try:
        with urllib.request.urlopen(request, timeout=6, context=_SSL_CTX) as resp:
            data = json.loads(resp.read())
        answers = data.get('answers') or {}
        scores = {k: float(v.get('noul', 1.0)) for k, v in answers.items()}
        if not scores:
            return Verdict('ask', 'typesafe_empty', 'typesafe')
        worst = max(scores.values())
        decision = 'allow' if worst < threshold else 'ask'
        return Verdict(decision, f'typesafe max={worst:.2f}', 'typesafe',
                       json.dumps(scores))
    except Exception as e:
        return Verdict('ask', f'typesafe_error:{type(e).__name__}', 'typesafe')
```

- [ ] **Step 4: 让 ask_ai 支持自定义超时(降级链需要 4s,见 spec §7.4)**

`ask_ai` 当前硬用 `AI_FALLBACK_TIMEOUT = 15`。作为**主后端**时保持 15s(既有行为不变),
作为 TypeSafe 的**降级**时必须用 4s,否则最坏延迟会变成 6+15=21s。

把 `ask_ai` 的签名改为:

```python
def ask_ai(command: str, cwd: str = '', timeout: int | None = None) -> tuple[bool, str]:
```

并把函数体内的:

```python
        with urllib.request.urlopen(req, timeout=AI_FALLBACK_TIMEOUT, context=_SSL_CTX) as resp:
```

改为:

```python
        with urllib.request.urlopen(req, timeout=timeout or AI_FALLBACK_TIMEOUT,
                                    context=_SSL_CTX) as resp:
```

默认参数为 `None` ⇒ 沿用 15s,主后端行为不变。

- [ ] **Step 5: 接入 remote_judge(默认仍走 anthropic)**

把 `remote_judge` 改为:

```python
def remote_judge(req: Request) -> Verdict:
    action, reason = dippy_analyze(req.payload, req.cwd)
    if action == 'allow':
        return Verdict('allow', reason, 'dippy')

    backend = os.getenv('SECURE_HANDLER_BACKEND', 'anthropic').strip().lower()
    if backend == 'off':
        return Verdict('ask', reason, 'fallthrough')

    if backend == 'typesafe':
        v = backend_typesafe(req)
        # 降级只因「错误」,不因「否定」——判危直接 ask,不去旧 gateway 碰运气
        if v.decision == 'ask' and v.reason.startswith('typesafe_error'):
            if AI_FALLBACK_ENABLED:
                is_safe, ai_raw = ask_ai(req.payload, req.cwd, timeout=4)
                return Verdict('allow' if is_safe else 'ask', reason, 'ai', ai_raw)
        return v

    if AI_FALLBACK_ENABLED:
        is_safe, ai_raw = ask_ai(req.payload, req.cwd)   # 主后端:沿用 15s
        return Verdict('allow' if is_safe else 'ask', reason, 'ai', ai_raw)
    return Verdict('ask', reason, 'fallthrough')
```

- [ ] **Step 6: 运行全部测试**

```bash
cd ~/claude-permission-hook && /usr/local/bin/python3.12 -m unittest discover tests -v
```

Expected: 全部 PASS,**回归基线仍需全绿**(默认后端未变)

- [ ] **Step 7: 提交**

```bash
cd ~/claude-permission-hook
git add secure_handler.py tests/test_typesafe.py
git commit -m "feat: add TypeSafe backend behind SECURE_HANDLER_BACKEND (default off)

Multi-dimensional noul scores with a tunable threshold replace the brittle
SAFE/UNSAFE string match. Falls back to the anthropic backend on transport
errors only — never on a negative verdict."
```

---

## Task 10: 阈值标定脚本(离线,不改线上)

Spec §7.1:0.15 是未经验证的猜测,上线前必须用真实数据标定。

**Files:**
- Create: `calibrate_threshold.py`

**Interfaces:**
- Consumes: Task 9 的 `backend_typesafe`、Task 7 的 `check_redlines`
- Produces: 命令行工具,输出分数分布与各阈值下的放行率

- [ ] **Step 1: 实现标定脚本**

创建 `calibrate_threshold.py`:

```python
#!/usr/bin/env python3
"""用历史审计日志中的真实命令标定 TypeSafe 阈值。

只读:不修改任何配置,不接触线上 hook。

用法:
  coffer run --global /usr/local/bin/python3.12 calibrate_threshold.py --limit 80
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secure_handler as sh

DEFAULT_LOG = Path.home() / '.claude' / 'logs' / 'permission_audit.jsonl'


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', type=Path, default=DEFAULT_LOG)
    ap.add_argument('--limit', type=int, default=80)
    args = ap.parse_args()

    rows = []
    for line in args.log.open(encoding='utf-8'):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            pass

    # 只取会真正走到远程判断的命令:Bash + 未被红线拦截
    cands, seen = [], set()
    for r in reversed(rows):
        if r.get('tool') != 'Bash' or r.get('layer') not in ('ai', 'typesafe'):
            continue
        cmd = str(r.get('cmd', ''))
        if not cmd or cmd in seen:
            continue
        if sh.check_redlines(sh.Request('command', cmd, '')):
            continue          # 红线命令不出网,也不参与标定
        seen.add(cmd)
        cands.append(cmd)
        if len(cands) >= args.limit:
            break

    print(f'标定样本: {len(cands)} 条(已排除红线命令)\n')

    results, elapsed = [], []
    for i, cmd in enumerate(cands, 1):
        t0 = time.perf_counter()
        v = sh.backend_typesafe(sh.Request('command', cmd, str(Path.home())))
        dt = (time.perf_counter() - t0) * 1000
        elapsed.append(dt)
        try:
            scores = json.loads(v.ai) if v.ai else {}
        except Exception:
            scores = {}
        worst = max(scores.values()) if scores else None
        results.append((cmd, worst, v.reason))
        print(f'  [{i}/{len(cands)}] max={worst if worst is None else round(worst,3)}  {cmd[:70]}')

    elapsed.sort()
    ok = [w for _, w, _ in results if w is not None]
    print(f'\n延迟: 中位={elapsed[len(elapsed)//2]:.0f}ms  '
          f'p90={elapsed[int(len(elapsed)*0.9)]:.0f}ms  最大={elapsed[-1]:.0f}ms')
    print(f'成功取到分数: {len(ok)}/{len(results)}')

    if ok:
        print('\n各阈值下的放行率:')
        for t in (0.05, 0.10, 0.15, 0.20, 0.30, 0.50):
            n = sum(1 for w in ok if w < t)
            print(f'  阈值 {t:<5} → 放行 {n:>3}/{len(ok)} ({n/len(ok):.0%})')
        print('\n⚠️ 放行率高不等于安全。提高阈值前,必须人工抽查新放行的命令。')


if __name__ == '__main__':
    main()
```

- [ ] **Step 2: 用 mock 验证脚本本身可跑(不消耗真实额度)**

```bash
cd ~/claude-permission-hook
SECURE_HANDLER_TYPESAFE_URL=http://127.0.0.1:1/v1/systemone \
SECURE_HANDLER_TYPESAFE_KEY=fake \
/usr/local/bin/python3.12 calibrate_threshold.py --limit 3
```

Expected: 3 条样本全部 `max=None`(端点不可达 → fail-safe),脚本不崩溃并打印统计。

- [ ] **Step 3: 提交**

```bash
cd ~/claude-permission-hook
git add calibrate_threshold.py
git commit -m "feat: add offline threshold calibration script

Replays real commands from the audit log against TypeSafe to measure
latency and the allow rate at candidate thresholds. Read-only; red-lined
commands are excluded and never sent."
```

- [ ] **Step 4: 交付给 owner 执行标定(需要真实 key)**

```bash
coffer secret add SECURE_HANDLER_TYPESAFE_KEY --global
coffer run --global /usr/local/bin/python3.12 ~/claude-permission-hook/calibrate_threshold.py --limit 80
```

**把输出交给 owner 决定阈值。在 owner 明确给出阈值之前,不要切换 `SECURE_HANDLER_BACKEND`。**

---

## 收尾:同步与文档

- [ ] **Step 1: 同步到线上 hook**

```bash
cp ~/claude-permission-hook/secure_handler.py ~/.claude/hooks/secure_handler.py
/usr/local/bin/python3.12 -m py_compile ~/.claude/hooks/secure_handler.py
```

- [ ] **Step 2: 更新 README 的 Config 表**

在 `README.md` 的 Config 表格中追加以下行:

| Env var | Default | Meaning |
|---|---|---|
| `SECURE_HANDLER_BACKEND` | `anthropic` | Remote judgment backend: `anthropic`, `typesafe`, or `off`. |
| `SECURE_HANDLER_AI_BASE_URL` | falls back to `ANTHROPIC_BASE_URL` | Endpoint for the hook only, so it can differ from the main session. |
| `SECURE_HANDLER_AI_KEY` | falls back to `ANTHROPIC_AUTH_TOKEN` | Token for the hook only. |
| `SECURE_HANDLER_TYPESAFE_KEY` | — | TypeSafe API key (inject via coffer). |
| `SECURE_HANDLER_TYPESAFE_URL` | `https://api.typesafe.ai/v1/systemone` | TypeSafe endpoint. |
| `SECURE_HANDLER_THRESHOLD` | `0.15` | Allow only when every dimension scores below this. **Calibrate before trusting.** |
| `SECURE_HANDLER_AUDIT_LOG` | `~/.claude/logs/permission_audit.jsonl` | Audit log path (tests override this). |

并在 README 中新增一节说明 `--agent` 参数与红线层。

- [ ] **Step 3: 更新 HANDOFF.md 的「当前状态」**

记录:重构已完成、测试套件位置、阶段二各开关默认值、阈值尚未标定。

- [ ] **Step 4: 修正 analyze_audit.py 的统计缺陷**

`analyze_audit.py` 当前把 `decision == 'ask'` 当作「用户被弹窗」统计,这是错的(见 spec §1.1)。改为分别统计 `ask`(hook 主动要求)与 `no_opinion`(hook 静默),并在输出中明确标注后者**不代表弹窗**。

- [ ] **Step 5: 提交**

```bash
cd ~/claude-permission-hook
git add README.md HANDOFF.md analyze_audit.py
git commit -m "docs: document new env vars, --agent flag and red lines

Also fixes analyze_audit.py, which counted 'ask' as a user prompt — the
hook stays silent for out-of-cwd file ops, so that count was an upper bound."
```

---

## 附:执行顺序与依赖

```
Task 1 (基线)
  └─ Task 2 (类型+适配器)
       └─ Task 3 (judge 抽取)  ← 重构核心
            └─ Task 4 (--agent)  ← 阶段一验收点
                 ├─ Task 5 (hookEventName 取证与修复)
                 ├─ Task 6 (no_opinion 日志)
                 ├─ Task 7 (红线)
                 ├─ Task 8 (env 解耦)
                 │    └─ Task 9 (TypeSafe 后端)
                 │         └─ Task 10 (阈值标定)
                 └─ 收尾(同步 + 文档)
```

Task 5–8 相互独立,可并行;Task 9 依赖 Task 8;Task 10 依赖 Task 9 且需要 owner 提供真实 key。
