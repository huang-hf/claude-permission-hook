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
  Fields: ts / cmd / tool / decision / layer / ai / reason
"""

from __future__ import annotations

import json
import os
import ssl
import subprocess
import sys
import urllib.request
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path

# Verify certificates by default; set SECURE_HANDLER_INSECURE_TLS=1 to skip (local MITM proxies)
_SSL_CTX = ssl.create_default_context()
if os.getenv('SECURE_HANDLER_INSECURE_TLS') == '1':
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

# ── Switches ───────────────────────────────────────────────────────
AI_FALLBACK_ENABLED: bool = os.getenv('SECURE_HANDLER_AI_FALLBACK', '1') != '0'
AI_API_STYLE: str = os.getenv('SECURE_HANDLER_AI_API', 'anthropic').strip().lower()  # anthropic | openai
AI_FALLBACK_MODEL = os.getenv('SECURE_HANDLER_AI_MODEL', 'claude-haiku-4-5-20251001')  # lightweight & fast
AI_FALLBACK_TIMEOUT = 15
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


def ask_ai(command: str, cwd: str = '') -> tuple[bool, str]:
    base_url = os.getenv('ANTHROPIC_BASE_URL', 'https://api.anthropic.com').rstrip('/')
    auth_token = os.getenv('ANTHROPIC_AUTH_TOKEN', '')
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
        with urllib.request.urlopen(req, timeout=AI_FALLBACK_TIMEOUT, context=_SSL_CTX) as resp:
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
Verdict = namedtuple('Verdict', 'decision reason layer ai', defaults=(None,))
#   decision: 'allow' | 'ask' | 'no_opinion'
#   ai: 后端原始响应,仅供审计;默认 None,因此 Verdict('allow','x','rule') 仍合法


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
    # 重构前此分支只写审计、不打印(交回 Claude Code 自身的默认权限提示)。
    # decision='no_opinion' 才能让 emit_claude_code 保持静默;main() 里的
    # 临时映射会把它记回审计里的 'ask',与基线逐字节一致。
    return Verdict('no_opinion', reason, 'fallthrough')


def judge(req: Request) -> Verdict:
    """唯一判断出口。纯函数:不打印、不写日志。"""
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


def emit_claude_code(verdict: Verdict) -> str | None:
    """把 Verdict 翻译成 Claude Code 期望的 stdout;no_opinion 返回 None(静默)。

    展示层:stdout 的 permissionDecisionReason 是给人看的文案,与审计里
    机器可读的 verdict.reason 刻意不同(重构前即如此,这里只是保持一致)。
    """
    if verdict.decision == 'no_opinion':
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
            'hookEventName': 'PreToolUse',
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

        verdict = judge(req)

        tool = data.get('tool_name', '')
        write_audit(req.payload, tool, verdict.decision, verdict.layer,
                    verdict.reason, verdict.ai,
                    hook_event=data.get('hook_event_name') if isinstance(data, dict) else None)

        out = emit(verdict)
        if out:
            print(out)
        sys.exit(0)

    except Exception:
        try:
            tool = data.get('tool_name', '') if isinstance(data, dict) else ''
            write_audit(req.payload if req else '', tool, 'ask', 'error')
        except Exception:
            pass
        sys.exit(0)


if __name__ == '__main__':
    main()
