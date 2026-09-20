#!/usr/bin/env python3
"""
secure_handler.py
PreToolUse Hook — dippy AST analysis + AI fallback + audit log

Flow:
1. Write/Edit/NotebookEdit: allow paths inside cwd
2. Bash: dippy AST analysis
   - allow  → audit + allow
   - ask / deny → AI fallback
       SAFE   → audit + allow
       UNSAFE → audit + ask (returns the rejection reason to steer Claude)
3. Any error → silent exit (fail-safe, falls through to the normal prompt)

Switches (env vars):
  SECURE_HANDLER_AI_FALLBACK=0  disable the AI fallback
  SECURE_HANDLER_AI_FALLBACK=1  enable (default)
  SECURE_HANDLER_AI_API=anthropic|openai  AI fallback API format (default: anthropic)
  SECURE_HANDLER_AI_MODEL=<model>         fallback model name (default: claude-haiku-4-5-20251001)
  SECURE_HANDLER_INSECURE_TLS=1           skip cert verification for local MITM proxies (default: verify)

Audit log: ~/.claude/logs/permission_audit.jsonl
  Always written: ts / tool / decision / layer / reason / hook_event_name
  Written when present: cmd / ai / backend / scores / elapsed_ms

  `decision` says what THIS hook decided, which is not the same as what the
  user saw:
    allow       -> printed an allow; the call ran without a prompt
    ask         -> printed an ask; the user was prompted
    no_opinion  -> printed nothing; the agent's own rules and mode decided,
                   so the user may or may not have been prompted
  Counting `ask` as "the user was prompted" therefore overstates prompts,
  and counting `no_opinion` that way overstates them badly.

  One exception: `layer='error'` rows record `decision='ask'` but print
  nothing (the fail-safe exits silently). The value is kept as `ask` so the
  row still reads as "this did not auto-approve"; treat `layer='error'` as
  a diagnostic signal rather than a prompt.

  `hook_event_name` is written on every row, `null` included, so that
  "the input carried no such field" stays distinguishable from "this row
  predates the field".
"""

from __future__ import annotations

import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path

# Verify certificates by default; set SECURE_HANDLER_INSECURE_TLS=1 to skip (local MITM proxies)
#
# 钉死的解释器 (/usr/local/bin/python3.12) 没有系统 CA 库,
# ssl.create_default_context() 拿不到 cafile/capath,任何 HTTPS 请求都会
# CERTIFICATE_VERIFY_FAILED。优先用 certifi 的 CA bundle;certifi 不可用
# (未安装)时退回标准库默认行为——不引入硬依赖,只是不一定能验证成功。
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except Exception:
    _SSL_CTX = ssl.create_default_context()
if os.getenv('SECURE_HANDLER_INSECURE_TLS') == '1':
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

# ── Switches ───────────────────────────────────────────────────────
AI_FALLBACK_ENABLED: bool = os.getenv('SECURE_HANDLER_AI_FALLBACK', '1') != '0'
AI_API_STYLE: str = os.getenv('SECURE_HANDLER_AI_API', 'anthropic').strip().lower()  # anthropic | openai
AI_FALLBACK_MODEL = os.getenv('SECURE_HANDLER_AI_MODEL', 'claude-haiku-4-5-20251001')  # lightweight & fast
AI_FALLBACK_TIMEOUT = 15
try:
    TYPESAFE_TIMEOUT = float(os.getenv('SECURE_HANDLER_TYPESAFE_TIMEOUT', '6'))
except ValueError:
    TYPESAFE_TIMEOUT = 6
AUDIT_LOG_PATH = Path(os.getenv('SECURE_HANDLER_AUDIT_LOG')
                      or Path.home() / '.claude' / 'logs' / 'permission_audit.jsonl')


# ══════════════════════════════════════════════════════════════════
# Audit log
# ══════════════════════════════════════════════════════════════════

def write_audit(cmd: str, tool: str, decision: str, layer: str,
                reason: str = '', ai_response: str | None = None,
                backend: str | None = None, scores: dict | None = None,
                elapsed_ms: int | None = None,
                hook_event: str | None = None) -> None:
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            'ts': datetime.now(timezone.utc).isoformat(),
            'tool': tool,
            'decision': decision,
            'layer': layer,
            'reason': reason,
        }
        if cmd:
            entry['cmd'] = cmd
        if ai_response is not None:
            entry['ai'] = ai_response
        if backend is not None:
            entry['backend'] = backend
        if scores is not None:
            entry['scores'] = scores
        if elapsed_ms is not None:
            entry['elapsed_ms'] = elapsed_ms
        entry['hook_event_name'] = hook_event   # 可能为 None:表示输入里没有该字段
        with AUDIT_LOG_PATH.open('a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════
# AI fallback
# ══════════════════════════════════════════════════════════════════

AI_PROMPT = """You are a security reviewer for an AI coding assistant.

Decide whether the following Bash command can be auto-approved:
Command: {command}
Project dir: {cwd}

SAFE: reading files, listing directories, build tools (pnpm/npm/yarn/make),
  git operations, dev tools (tsc/tsx/python/pytest/docker build),
  viewing logs, package manager installs, file operations inside the project dir.
UNSAFE: deleting files/directories, modifying files outside the project,
  accessing credentials, network data exfiltration, irreversible system-level changes.

Reply with only SAFE or UNSAFE, nothing else."""


def _ai_endpoint() -> tuple[str, str]:
    """(base_url, token)。优先用 hook 专属变量,回落到 ANTHROPIC_* 以兼容既有安装。

    两者**成对**回落,不各自独立:一旦设了 SECURE_HANDLER_AI_BASE_URL,token 就
    只认 SECURE_HANDLER_AI_KEY,不再回落到 ANTHROPIC_AUTH_TOKEN。

    独立回落时,「设了专属 URL 却忘了设专属 KEY」会把 Anthropic 的 token 发给
    那个第三方端点 —— 而这正是本函数存在的场景下最可能的误配置。想用 Anthropic
    的 token 配自建代理仍然可以,把两个变量都显式设上即可:那是一次明确的选择,
    而不是一次意外。
    """
    sh_base = os.getenv('SECURE_HANDLER_AI_BASE_URL')
    if sh_base:
        return sh_base.rstrip('/'), (os.getenv('SECURE_HANDLER_AI_KEY') or '')
    base = (os.getenv('ANTHROPIC_BASE_URL')
            or 'https://api.anthropic.com').rstrip('/')
    token = (os.getenv('SECURE_HANDLER_AI_KEY')
             or os.getenv('ANTHROPIC_AUTH_TOKEN') or '')
    return base, token


def ask_ai(command: str, cwd: str = '') -> tuple[bool, str]:
    base_url, auth_token = _ai_endpoint()
    if not auth_token:
        return False, 'no_token'

    content = AI_PROMPT.format(command=command, cwd=cwd or 'unknown')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {auth_token}',
    }
    if AI_API_STYLE == 'openai':
        url = f'{base_url}/v1/chat/completions'
        payload = json.dumps({
            'model': AI_FALLBACK_MODEL,
            'max_tokens': 10,
            'messages': [{'role': 'user', 'content': content}],
        }).encode()
    else:
        url = f'{base_url}/v1/messages'
        headers['anthropic-version'] = '2023-06-01'
        payload = json.dumps({
            'model': AI_FALLBACK_MODEL,
            'max_tokens': 10,
            'messages': [{'role': 'user', 'content': content}],
        }).encode()

    req = urllib.request.Request(url, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=AI_FALLBACK_TIMEOUT,
                                    context=_SSL_CTX) as resp:
            data = json.loads(resp.read())
            if AI_API_STYLE == 'openai':
                text = data['choices'][0]['message']['content']
            else:
                text = data['content'][0]['text']
            text = text.strip().upper()
            return text == 'SAFE', text
    except Exception:
        return False, 'error'


# ══════════════════════════════════════════════════════════════════
# dippy AST analysis
# ══════════════════════════════════════════════════════════════════

def dippy_analyze(command: str, cwd: str) -> tuple[str, str]:
    """
    Run the dippy analyzer, returns (action, reason).
    action: 'allow' | 'ask' | 'deny'
    On import failure returns ('ask', 'dippy_unavailable') → AI fallback.
    """
    try:
        from dippy.core.analyzer import analyze
        from dippy.core.config import load_config
        cwd_path = Path(cwd) if cwd else Path.home()
        config = load_config(cwd_path)
        result = analyze(command, config, cwd_path)
        return result.action, result.reason
    except Exception as e:
        return 'ask', f'dippy_error:{e}'


# ══════════════════════════════════════════════════════════════════
# git metadata allow (worktree coordination files under .git/...)
# ══════════════════════════════════════════════════════════════════

def _resolve_path(file_path: str, cwd: str) -> str:
    """Resolve file_path to an absolute path; relative paths use the JSON cwd (not the hook process cwd)."""
    if not file_path:
        return ''
    p = Path(file_path)
    if not p.is_absolute() and cwd:
        p = Path(cwd) / p
    try:
        return str(p.resolve())
    except Exception:
        return str(p)


def _git_common_dir(cwd: str) -> str | None:
    """Absolute path of the repo's main .git dir for cwd; None if not a git repo."""
    if not cwd:
        return None
    try:
        r = subprocess.run(['git', '-C', cwd, 'rev-parse', '--git-common-dir'],
                           capture_output=True, text=True, timeout=3)
        if r.returncode == 0 and r.stdout.strip():
            return os.path.realpath(os.path.join(cwd, r.stdout.strip()))
    except Exception:
        pass
    return None


def _is_git_metadata(fp_resolved: str, common_dir: str | None) -> bool:
    """Whether the resolved file is inside the repo's .git dir (excluding hooks/ and config danger surfaces)."""
    if not common_dir or not fp_resolved:
        return False
    if not (fp_resolved == common_dir or fp_resolved.startswith(common_dir + os.sep)):
        return False
    rel = fp_resolved[len(common_dir):].lstrip(os.sep)
    parts = rel.split(os.sep)
    if 'hooks' in parts:
        return False   # any .git/.../hooks/ path still prompts (can hold executable hooks)
    if os.path.basename(rel) in ('config', 'config.worktree'):
        return False   # git config files still prompt (can change hooksPath etc.)
    return True


# ══════════════════════════════════════════════════════════════════
# CORE types (agent-agnostic)
# ══════════════════════════════════════════════════════════════════

Request = namedtuple('Request', 'kind payload cwd')
#   kind: 'command' | 'file_read' | 'file_write'
Verdict = namedtuple('Verdict', 'decision reason layer ai backend scores elapsed_ms',
                     defaults=(None, None, None, None))
#   decision: 'allow' | 'ask' | 'no_opinion'
#   ai: 后端原始响应,仅供审计;默认 None,因此 Verdict('allow','x','rule') 仍合法
#   backend/scores/elapsed_ms: 供审计用的标定数据(Task 6 write_audit 已支持这三个
#   字段但一直没有写入方;这里补上),默认均为 None,不影响既有只传 4 个位置参数的调用点


# ══════════════════════════════════════════════════════════════════
# CORE — red lines (always ask; never auto-approved by any backend)
# ══════════════════════════════════════════════════════════════════

_REDLINES = {
    'prod_infra': re.compile(
        r'\bkubectl\b.*\b(apply|delete|exec|patch|edit|scale|rollout|replace|cp|'
        r'drain|cordon|label|annotate|set|run|taint|debug|proxy|port-forward|'
        r'create|uncordon|attach|expose|autoscale|rollback)\b|'
        r'\bkubectl\s+config\s+use-context\b|'
        r'\bterraform\s+(apply|destroy)\b|'
        r'\bhelm\s+(upgrade|install|delete|rollback)\b|'
        r'\beksctl\s+(create|delete)\b|'
        r'\baws\s+s3\s+rm\b', re.I),
    # 凭证位置。对命令和文件路径都适用 —— 路径指向凭证存放处,与它怎么被提到无关。
    'credentials': re.compile(
        r'\bcoffer\b|/\.(ssh|aws|kube|gnupg)(/|$)|~/\.(ssh|aws|kube|gnupg)(/|$)|'
        r'/\.netrc\b|/\.docker/config\.json|\bid_rsa\b|\.pem\b|'
        # 按文件名判定的凭证文件。刻意用窄白名单而非泛关键词:这些名字几乎只用于
        # 存凭证,实测在 owner 的三个仓库里命中 8/22006、36/130750、74/48022
        # (均 <0.2%),不会重演关键词匹配那次 32% 的误伤。
        r'(^|/)(\.env(\.|$)|\.git-credentials|\.npmrc|\.pypirc|\.pgpass|'
        r'authorized_keys|kubeconfig|secrets?\.ya?ml)|\.(key|p12|pfx|jks)$', re.I),
    'destructive': re.compile(
        # rm 的 -r/-f 不一定是第一个 token(如 `rm -i -rf x`、`rm --recursive --force x`),
        # 用前瞻扫整条 rm 调用(遇 ; & | 截断,避免跨命令误伤)而不是死认第一个参数。
        # (?<!-) 挡住 `--rm` 里的 rm:否则 `docker run --rm --user 1000` 会命中,
        # 因为 `[a-z]*[rf]` 匹配任何以 r/f 结尾的 flag(--user、--filter、--platform…)。
        r'(?<!-)\brm\b(?=[^;&|]*\s-{1,2}(?:[a-z]*[rf]|recursive|force)\b)|'
        r'\bgit\s+push\b[^;&|]*\s-(?:f\b|-force)|'
        r'\bgit\s+reset\b[^;&|]*\s--hard\b|'
        r'\bgit\s+clean\b[^;&|]*\s-[a-zA-Z]*f[a-zA-Z]*d[a-zA-Z]*\b|'
        r'\bgit\s+clean\b[^;&|]*\s-[a-zA-Z]*d[a-zA-Z]*f[a-zA-Z]*\b|'
        # 不可逆丢弃「尚未提交」的工作成果 —— 这类命令 git 自己也救不回来。
        # 它们大多落在 owner 的 Bash allow 规则里(git checkout*/git stash*),
        # 所以只有 PreToolUse 上的红线能覆盖到,见 Global Constraints 的方案 B。
        r'\bgit\s+checkout\b[^;&|]*(\s--\s|\s\.(\s|$))|'   # git checkout -- . / git checkout .
        r'\bgit\s+restore\b|'                              # restore 天然就是丢弃工作区改动
        r'\bgit\s+stash\s+(clear|drop)\b|'                 # stash 本身安全,clear/drop 不可逆
        r'\bgit\s+branch\b[^;&|]*\s(?-i:-D)\b|'            # 仅此处区分大小写:-D 强删,-d 安全
        r'\bgit\s+worktree\s+remove\b[^;&|]*--force|'
        r'\bdrop\s+(table|database)\b|\btruncate\b|\bdd\s+if=|\bmkfs\b', re.I),
}


# 凭证「关键词」—— 只对命令生效,不对文件路径生效。
#
# 出现在命令文本里的 `token` / `secret` 说明这条命令在摆弄凭证,是有效信号;
# 出现在文件名里则几乎没有信号 —— 实测 owner 的一个仓库有 32%(8348/25687)
# 的源文件名含这些词(token_usage.py、erc20_token_config…),按路径匹配会让
# 每三次文件编辑就弹一次窗。位置(在 ~/.ssh 下)和命名(叫 token_utils.py)
# 是两种强度完全不同的证据,不能套用同一条规则。
#
# 刻意不加两侧 \b:下划线两侧都是 \w,会把词边界吃掉,导致
# AWS_SECRET_ACCESS_KEY / GITHUB_TOKEN 漏报。
_CREDENTIAL_WORDS = re.compile(
    r'(secret|secretsmanager|credential|private[_-]?key|password|token)', re.I)


def check_redlines(req: Request) -> str | None:
    """命中返回类别名,否则 None。刻意做宽:误报只多弹一次窗,漏报可能放行危险命令。"""
    text = req.payload or ''
    for name, rx in _REDLINES.items():
        if rx.search(text):
            return name
    if req.kind == 'command' and _CREDENTIAL_WORDS.search(text):
        return 'credentials'
    return None


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


TYPESAFE_QUESTIONS = {
    'irreversible':   '不可逆地删除或覆盖数据',
    'outside_proj':   '修改当前项目目录之外的文件',
    'exfiltration':   '把本地数据发送到外部网络(推送到已知 git remote 不算)',
    'untrusted_exec': '下载并执行未经审查的代码,如 curl | sh',
    'sys_config':     '修改系统级配置或已安装软件',
}


def backend_typesafe(req: Request) -> Verdict:
    """TypeSafe 结构化判断。

    异常分两类,reason 前缀不同:
      typesafe_neterror:*  传输层故障(连不上/超时/HTTP 错误)。
      typesafe_badresp:*   后端连上了但返回解析不出结果。
    两者都收敛到 decision='ask',不再影响控制流(backend 是二选一,不降级到
    另一家)——这个区分现在只作为审计诊断信号保留:事后能看出 TypeSafe 是
    连不上还是返回了垃圾,便于排查该换端点还是该联系供应商。
    """
    url = os.getenv('SECURE_HANDLER_TYPESAFE_URL',
                    'https://api.typesafe.ai/v1/systemone')
    key = os.getenv('SECURE_HANDLER_TYPESAFE_KEY', '')
    model = os.getenv('SECURE_HANDLER_TYPESAFE_MODEL', 'jev-latest')
    try:
        threshold = float(os.getenv('SECURE_HANDLER_THRESHOLD', '0.15'))
    except ValueError:
        threshold = 0.15
    if not key:
        return Verdict('ask', 'typesafe_no_key', 'typesafe', backend='typesafe')

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

    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=TYPESAFE_TIMEOUT,
                                    context=_SSL_CTX) as resp:
            raw = resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return Verdict('ask', f'typesafe_neterror:{type(e).__name__}', 'typesafe',
                       backend='typesafe', elapsed_ms=elapsed_ms)
    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return Verdict('ask', f'typesafe_badresp:{type(e).__name__}', 'typesafe',
                       backend='typesafe', elapsed_ms=elapsed_ms)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    try:
        data = json.loads(raw)
        answers = data.get('answers') or {}
        scores = {k: float(v.get('noul', 1.0)) for k, v in answers.items()}
        if not scores:
            return Verdict('ask', 'typesafe_empty', 'typesafe',
                           backend='typesafe', elapsed_ms=elapsed_ms)
        worst = max(scores.values())
        decision = 'allow' if worst < threshold else 'ask'
        return Verdict(decision, f'typesafe max={worst:.2f}', 'typesafe',
                       backend='typesafe', scores=scores, elapsed_ms=elapsed_ms)
    except Exception as e:
        return Verdict('ask', f'typesafe_badresp:{type(e).__name__}', 'typesafe',
                       backend='typesafe', elapsed_ms=elapsed_ms)


def remote_judge(req: Request) -> Verdict:
    """远程判断层。默认后端 anthropic,与升级前行为一致。"""
    action, reason = dippy_analyze(req.payload, req.cwd)
    if action == 'allow':
        return Verdict('allow', reason, 'dippy')

    backend = os.getenv('SECURE_HANDLER_BACKEND', 'anthropic').strip().lower()
    if backend == 'off':
        # decision='no_opinion' 才能让 emit_claude_code 保持静默,见 Global Constraints。
        return Verdict('no_opinion', reason, 'fallthrough')

    if backend == 'typesafe':
        # 二选一,不做链式降级:选了 typesafe 就用 typesafe,失败(无论传输层
        # 故障还是解析出垃圾)一律 ask,不去问 ask_ai/旧 gateway 碰运气。
        return backend_typesafe(req)

    if AI_FALLBACK_ENABLED:
        is_safe, ai_raw = ask_ai(req.payload, req.cwd)   # 主后端:沿用 15s
        return Verdict('allow' if is_safe else 'ask', reason, 'ai', ai_raw)
    # 重构前此分支只写审计、不打印(交回 Claude Code 自身的默认权限提示)。
    # decision='no_opinion' 才能让 emit_claude_code 保持静默;main() 里的
    # 临时映射会把它记回审计里的 'ask',与基线逐字节一致。
    return Verdict('no_opinion', reason, 'fallthrough')


def judge(req: Request) -> Verdict:
    """唯一判断出口。纯函数:不打印、不写日志。"""
    if hit := check_redlines(req):
        return Verdict('ask', hit, 'redline')
    if not req.payload:
        # 空 payload 无法有意义地判断,且不应为此付出 dippy 子进程开销。
        # main() 实际走不到这里(parse_claude_code 对空命令返回 None),
        # 这条只是让 judge() 本身对空输入保持防御性、可单测。
        return Verdict('no_opinion', 'empty payload', 'rule')
    if v := local_rules(req):
        return v
    if req.kind in ('file_read', 'file_write'):
        return Verdict('no_opinion', 'outside_cwd', 'rule')
    return remote_judge(req)


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


_CC_RULE_DISPLAY = {'within_cwd': 'within cwd', 'git_metadata': 'git metadata dir'}


def emit_claude_code(verdict: Verdict, event: str = 'PreToolUse') -> str | None:
    """把 Verdict 翻译成 Claude Code 期望的 stdout;no_opinion 返回 None(静默)。

    展示层:stdout 的 permissionDecisionReason 是给人看的文案,与审计里
    机器可读的 verdict.reason 刻意不同(重构前即如此,这里只是保持一致)。

    白名单而非黑名单(Task 2 review 的 🟡-2):只有 allow/ask 会被输出,
    任何笔误或未来新增的 decision 值都静默回落,而不是被原样塞给 agent。
    """
    if verdict.decision not in ('allow', 'ask'):
        return None
    reason = verdict.reason
    if verdict.decision == 'allow' and verdict.layer == 'ai':
        reason = f'ai:SAFE ({reason})'
    elif verdict.layer == 'rule':
        reason = _CC_RULE_DISPLAY.get(reason, reason)
    if verdict.decision == 'ask':
        reason = f'🔍 {reason}'
    return json.dumps({
        'hookSpecificOutput': {
            'hookEventName': event,
            'permissionDecision': verdict.decision,
            'permissionDecisionReason': reason,
        }
    })


ADAPTERS = {
    'claude-code': (parse_claude_code, emit_claude_code),
}


# ══════════════════════════════════════════════════════════════════
# Main flow
# ══════════════════════════════════════════════════════════════════

def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    req = None
    try:
        agent = 'claude-code'
        argv = sys.argv[1:]
        for i, arg in enumerate(argv):
            if arg.startswith('--agent='):
                agent = arg.split('=', 1)[1].strip()
            elif arg == '--agent':
                # 也接受空格写法 `--agent codex`。不接受的话它会被无声忽略,
                # 从而回落到 claude-code —— 等于拿本适配器去解析别家 agent 的
                # payload。缺少取值时给一个必定不在 ADAPTERS 里的哨兵,走静默。
                agent = argv[i + 1].strip() if i + 1 < len(argv) else '\x00'
        if agent not in ADAPTERS:
            sys.exit(0)          # fail-safe:未知 agent 一律静默
        parse, emit = ADAPTERS[agent]
        req = parse(data)
        if req is None:
            sys.exit(0)

        hook_event = data.get('hook_event_name') if isinstance(data, dict) else None
        if req.kind == 'command' and hook_event == 'PreToolUse':
            # PreToolUse 对每次工具调用都触发(PermissionRequest 只在 Claude Code
            # 判定"需要权限决策"时才触发),所以这是红线唯一能覆盖到「被 allow
            # 规则放行的命令」的地方。这里只跑本地正则:完整判断链
            # (dippy/AI/typesafe)留在 PermissionRequest,避免给本已放行的命令
            # 平白增加子进程与网络开销。未命中必须 no_opinion(静默),绝不能
            # 输出 ask —— 否则会覆盖 owner 的 allow 规则。
            if hit := check_redlines(req):
                verdict = Verdict('ask', hit, 'redline')
            else:
                verdict = Verdict('no_opinion', 'redline_pass', 'rule')
        else:
            verdict = judge(req)

        tool = data.get('tool_name', '')
        write_audit(req.payload, tool, verdict.decision, verdict.layer,
                    verdict.reason, verdict.ai,
                    backend=verdict.backend, scores=verdict.scores,
                    elapsed_ms=verdict.elapsed_ms,
                    hook_event=hook_event)

        out = emit(verdict, hook_event if hook_event is not None else 'PreToolUse')
        if out:
            print(out)
        sys.exit(0)

    except Exception:
        try:
            tool = data.get('tool_name', '') if isinstance(data, dict) else ''
            # hook_event 也要传:不传的话它会记成 null,于是「输入里没有这个
            # 字段」和「出错了没取到」就分不开了 —— 而区分这两者正是记录
            # 该字段的全部意义。
            write_audit(req.payload if req else '', tool, 'ask', 'error',
                        hook_event=(data.get('hook_event_name')
                                    if isinstance(data, dict) else None))
        except Exception:
            pass
        sys.exit(0)


if __name__ == '__main__':
    main()
