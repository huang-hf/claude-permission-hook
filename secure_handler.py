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
AUDIT_LOG_PATH = Path.home() / '.claude' / 'logs' / 'permission_audit.jsonl'


# ══════════════════════════════════════════════════════════════════
# Audit log
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
# Response helpers (PreToolUse format)
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
# Main flow
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

        # ── Write / Edit / NotebookEdit: allow paths inside cwd ──
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

        # ── Layer 1: dippy AST analysis ────────────────────────────
        action, reason = dippy_analyze(command, cwd)

        if action == 'allow':
            write_audit(command, tool, 'allow', 'dippy', reason)
            print(json.dumps(allow_response(reason)))
            sys.exit(0)

        # ── Layer 2: AI fallback (dippy said ask / deny) ───────────
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

        # ── Fallback: back to the normal prompt ────────────────────
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
