# claude-permission-hook

A smart permission gate for [Claude Code](https://claude.com/claude-code). It auto-approves
obviously-safe operations so you stop clicking "Yes" all day, while still prompting for
anything risky — and it logs every decision for auditing.

It runs as a Claude Code hook (`PreToolUse` + `PermissionRequest`) and decides per tool call:

- **File reads/edits** (`Read`/`Write`/`Edit`/`NotebookEdit`): auto-allow when the path is
  inside the current working directory, or inside the current repo's `.git` metadata
  (e.g. worktree coordination files). Everything else falls through to Claude's normal prompt.
  `.git/hooks/` and `.git/config` are always kept prompting (they can execute code).
- **Bash commands**: analyzed in two layers —
  1. **[dippy](https://pypi.org/project/dippy/) AST analysis** (local, fast, offline). If it
     says *allow*, the command runs with no prompt.
  2. **AI fallback**: if dippy defers (or isn't installed), a small model (Haiku) judges the
     command `SAFE` / `UNSAFE`. `SAFE` → allow, `UNSAFE` → prompt.
- **Fail-safe**: any error, missing token, or unhandled tool → silently defers to Claude's
  normal permission prompt. It never *reduces* safety on failure.

Every decision is appended to `~/.claude/logs/permission_audit.jsonl`.

## How it fits Claude Code's permission model

Order of resolution: `deny rules → allow rules → PreToolUse hook → permission mode (default/auto)`.
This hook sits at the `PreToolUse` layer, so its `allow` short-circuits *before* the prompt.
What it doesn't explicitly allow simply falls through to your normal mode.

> Note: `permissionDecision: allow` is honored for **`PreToolUse`** hooks. Registering the
> script under `PreToolUse` (not only `PermissionRequest`) is what makes the auto-allow
> actually take effect. Bash analysis is wired under `PermissionRequest` in the template.

## Install

1. Copy the script:
   ```bash
   mkdir -p ~/.claude/hooks
   cp secure_handler.py ~/.claude/hooks/
   chmod +x ~/.claude/hooks/secure_handler.py
   ```

2. Install the dippy dependency into a specific Python, and **pin that interpreter** in the
   hook command (do not rely on `python3` from `PATH` — it differs per terminal/venv/conda):
   ```bash
   python3.12 -m pip install --user dippy
   which python3.12   # e.g. /usr/local/bin/python3.12  → use this absolute path below
   ```

3. Merge `settings.json.template` into your `~/.claude/settings.json`, replacing:
   - `<PYTHON_WITH_DIPPY>` → the absolute path from step 2 (e.g. `/usr/local/bin/python3.12`)
   - `<YOUR_ANTHROPIC_TOKEN>` / `<YOUR_ANTHROPIC_BASE_URL...>` → your values (only needed for
     the AI fallback; set `SECURE_HANDLER_AI_FALLBACK=0` to disable it and use dippy only).

4. Reload: open `/hooks` once, or restart Claude Code (hook registration is read at startup).

## Config

| Env var | Default | Meaning |
|---|---|---|
| `ANTHROPIC_AUTH_TOKEN` | — | Token for the AI fallback call. No token → AI fallback is skipped. |
| `ANTHROPIC_BASE_URL` | `https://api.anthropic.com` | API base (supports a proxy). |
| `SECURE_HANDLER_AI_FALLBACK` | `1` | `0` disables the AI layer (dippy-only). |
| `SECURE_HANDLER_AI_API` | `anthropic` | API format for the AI fallback: `anthropic` (Messages API) or `openai` (chat completions — works with OpenAI-compatible gateways/proxies). |
| `SECURE_HANDLER_AI_MODEL` | `claude-haiku-4-5-20251001` | Model used by the AI fallback. |
| `SECURE_HANDLER_INSECURE_TLS` | — | Set to `1` to skip TLS certificate verification (only for local MITM proxies). Off by default — certificates are verified. |

## ⚠️ Security notes

- **This script has no hardcoded secrets** — the token and base URL are read from env vars.
  Never commit your real `~/.claude/settings.json` (it holds the token) or the audit log
  (it holds your full command history). See `.gitignore`.
- **TLS verification is on by default.** Only if you use a local MITM proxy (e.g. cert
  inspection for debugging) set `SECURE_HANDLER_INSECURE_TLS=1` to bypass it. With the bypass
  off, the AI fallback verifies the certificate of `ANTHROPIC_BASE_URL`. Note that combining
  an `http://` base URL with the bypass is only meant for local debugging.
- Auto-approval is a convenience/safety tradeoff. Review the rules in `secure_handler.py` and
  adjust `AI_PROMPT` / the git-metadata logic to your own risk tolerance before trusting it.

## License

MIT (or your choice).
