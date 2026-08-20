#!/usr/bin/env python3
"""
secure_handler.py
PreToolUse Hook — Dippy AST 解析 + AI 兜底 + 审计日志

处理流程：
1. Write/Edit/NotebookEdit：cwd 内路径直接放行
2. Bash：Dippy AST 解析
   - allow  → 审计 + 放行
   - ask / deny → AI 兜底
       SAFE   → 审计 + 放行
       UNSAFE → 审计 + ask（返回拒绝原因，引导 Claude 修正）
3. 任何异常 → 静默退出（fail-safe，交弹窗处理）

开关控制：
  环境变量 SECURE_HANDLER_AI_FALLBACK=0  禁用 AI 兜底
           SECURE_HANDLER_AI_FALLBACK=1  启用（默认）
           SECURE_HANDLER_AI_API=anthropic|openai   AI 兜底 API 格式（默认 anthropic）
           SECURE_HANDLER_AI_MODEL=<model>          兜底模型名（默认 claude-haiku-4-5-20251001）
           SECURE_HANDLER_INSECURE_TLS=1            本地 MITM 代理场景跳过证书验证（默认验证）

审计日志：~/.claude/logs/permission_audit.jsonl
  字段：ts / cmd / tool / decision / layer / ai / reason
"""

from __future__ import annotations

import json
import os
import ssl
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# 默认验证证书；本地 MITM 代理场景可设 SECURE_HANDLER_INSECURE_TLS=1 跳过验证
_SSL_CTX = ssl.create_default_context()
if os.getenv('SECURE_HANDLER_INSECURE_TLS') == '1':
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

# ── 开关 ──────────────────────────────────────────────────────────
AI_FALLBACK_ENABLED: bool = os.getenv('SECURE_HANDLER_AI_FALLBACK', '1') != '0'
AI_API_STYLE: str = os.getenv('SECURE_HANDLER_AI_API', 'anthropic').strip().lower()  # anthropic | openai
AI_FALLBACK_MODEL = os.getenv('SECURE_HANDLER_AI_MODEL', 'claude-haiku-4-5-20251001')  # 轻量快速
AI_FALLBACK_TIMEOUT = 15
AUDIT_LOG_PATH = Path.home() / '.claude' / 'logs' / 'permission_audit.jsonl'


# ══════════════════════════════════════════════════════════════════
# 审计日志
# ══════════════════════════════════════════════════════════════════

def write_audit(cmd: str, tool: str, decision: str, layer: str,
                reason: str = '', ai_response: str | None = None) -> None:
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
        with AUDIT_LOG_PATH.open('a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════
# 响应构造（PreToolUse 格式）
# ══════════════════════════════════════════════════════════════════

def _pre_tool_response(decision: str, reason: str) -> dict:
    return {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': decision,
            'permissionDecisionReason': reason,
        }
    }


def allow_response(reason: str = '') -> dict:
    return _pre_tool_response('allow', reason)


def ask_response(reason: str = '') -> dict:
    return _pre_tool_response('ask', f'🔍 {reason}')


# ══════════════════════════════════════════════════════════════════
# AI 兜底
# ══════════════════════════════════════════════════════════════════

AI_PROMPT = """你是开发者 AI 编程助手的安全审查员。

判断以下 Bash 命令是否可以自动放行：
命令：{command}
项目目录：{cwd}

安全（SAFE）：读取文件、列目录、构建工具（pnpm/npm/yarn/make）、
  git 操作、开发工具（tsc/tsx/python/pytest/docker build）、
  查看日志、包管理器安装、项目目录内文件操作等常规开发操作。
不安全（UNSAFE）：删除文件/目录、修改项目外文件、访问凭证、
  网络数据外泄、不可逆系统级变更。

只回复 SAFE 或 UNSAFE，不要其他内容。"""


def ask_ai(command: str, cwd: str = '') -> tuple[bool, str]:
    base_url = os.getenv('ANTHROPIC_BASE_URL', 'https://api.anthropic.com').rstrip('/')
    auth_token = os.getenv('ANTHROPIC_AUTH_TOKEN', '')
    if not auth_token:
        return False, 'no_token'

    content = AI_PROMPT.format(command=command, cwd=cwd or '未知')
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
# Dippy AST 分析
# ══════════════════════════════════════════════════════════════════

def dippy_analyze(command: str, cwd: str) -> tuple[str, str]:
    """
    调用 Dippy analyzer，返回 (action, reason)。
    action: 'allow' | 'ask' | 'deny'
    导入失败时返回 ('ask', 'dippy_unavailable') 交 AI 兜底。
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
# git 元数据放行（worktree 的 .git/.../sdd 等协作产物）
# ══════════════════════════════════════════════════════════════════

def _resolve_path(file_path: str, cwd: str) -> str:
    """把 file_path 解析为绝对路径；相对路径按 JSON 的 cwd(而非钩子进程 cwd)解析。"""
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
    """当前 cwd 所属仓库的主 .git 目录(绝对路径)；非 git 返回 None。"""
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
    """文件是否落在当前仓库的 .git 目录内(排除 hooks/ 与 config 危险面)。"""
    if not common_dir or not fp_resolved:
        return False
    if not (fp_resolved == common_dir or fp_resolved.startswith(common_dir + os.sep)):
        return False
    rel = fp_resolved[len(common_dir):].lstrip(os.sep)
    parts = rel.split(os.sep)
    if 'hooks' in parts:
        return False   # 任意层级的 .git/.../hooks/ 仍弹窗（可塞可执行钩子）
    if os.path.basename(rel) in ('config', 'config.worktree'):
        return False   # git 配置文件仍弹窗（可改 hooksPath 等）
    return True


# ══════════════════════════════════════════════════════════════════
# 主流程
# ══════════════════════════════════════════════════════════════════

def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    command = ''
    tool = ''

    try:
        tool = data.get('tool_name', '')
        cwd = data.get('cwd', '')

        # ── Write / Edit / NotebookEdit：cwd 内路径直接放行 ──────
        if tool in ('Read', 'Write', 'Edit', 'NotebookEdit'):
            file_path = data.get('tool_input', {}).get('file_path', '')
            fp_res = _resolve_path(file_path, cwd)
            cwd_res = str(Path(cwd).resolve()) if cwd else ''
            if cwd_res and fp_res and Path(fp_res).is_relative_to(Path(cwd_res)):
                write_audit(file_path, tool, 'allow', 'rule', 'within_cwd')
                print(json.dumps(allow_response('within cwd')))
            elif fp_res and _is_git_metadata(fp_res, _git_common_dir(cwd)):
                write_audit(file_path, tool, 'allow', 'rule', 'git_metadata')
                print(json.dumps(allow_response('git metadata dir')))
            else:
                write_audit(file_path, tool, 'ask', 'rule', 'outside_cwd')
            sys.exit(0)

        if tool != 'Bash':
            sys.exit(0)

        command = data.get('tool_input', {}).get('command', '')
        if not command:
            sys.exit(0)

        # ── 第一层：Dippy AST 解析 ────────────────────────────────
        action, reason = dippy_analyze(command, cwd)

        if action == 'allow':
            write_audit(command, tool, 'allow', 'dippy', reason)
            print(json.dumps(allow_response(reason)))
            sys.exit(0)

        # ── 第二层：AI 兜底（Dippy 说 ask / deny）───────────────
        if AI_FALLBACK_ENABLED:
            is_safe, ai_raw = ask_ai(command, cwd)
            if is_safe:
                write_audit(command, tool, 'allow', 'ai', reason, ai_raw)
                print(json.dumps(allow_response(f'ai:SAFE ({reason})')))
                sys.exit(0)
            else:
                write_audit(command, tool, 'ask', 'ai', reason, ai_raw)
                print(json.dumps(ask_response(reason)))
                sys.exit(0)

        # ── 兜底：退回弹窗 ────────────────────────────────────────
        write_audit(command, tool, 'ask', 'fallthrough', reason)
        sys.exit(0)

    except Exception:
        try:
            write_audit(command, tool, 'ask', 'error')
        except Exception:
            pass
        sys.exit(0)


if __name__ == '__main__':
    main()
