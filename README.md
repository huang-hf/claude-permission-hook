# claude-permission-hook

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Hook-orange)](https://claude.com/claude-code)

A smart permission gate for [Claude Code](https://claude.com/claude-code). It auto-approves
obviously-safe operations so you stop clicking "Yes" all day, while still prompting for
anything risky — and it logs every decision for auditing.

- **Fewer prompts, same safety.** Safe file ops and commands run without asking; anything
  risky still prompts.
- **Two-layer Bash analysis.** Local offline AST parsing first, an AI fallback second — never
  just blind-trusts a command.
- **Fail-safe by design.** Any error, missing token, or unhandled case falls back to Claude's
  normal permission prompt. It never *reduces* safety on failure.
- **Full audit trail.** Every decision is appended to `~/.claude/logs/permission_audit.jsonl`.
- **No hardcoded secrets.** Token and API base come from env vars; nothing sensitive in the repo.

## Why

Claude Code's default permission flow asks about *everything* — safe commands too. You can
switch to `yolo` mode to silence the prompts, but that means no guardrails at all. This hook
is the middle path: it says yes to things that are clearly safe, and still asks before
anything that could hurt.

## How it works

Claude Code resolves permissions in this order:
`deny rules → allow rules → PreToolUse hook → permission mode (default / auto)`.

This hook sits at the `PreToolUse` layer, so its `allow` short-circuits *before* the prompt.
What it doesn't explicitly allow falls through to your normal mode.

### Per tool

| Tool | Behavior |
|---|---|
| `Read` / `Write` / `Edit` / `NotebookEdit` | Allow when the path is inside the current working directory, or inside the current repo's `.git` metadata (e.g. worktree coordination files). `.git/hooks/` and `.git/config` always prompt (they can execute code). |
| `Bash` | 1. **dippy AST analysis** — local, fast, offline. `allow` → runs with no prompt. <br> 2. **AI fallback** — if dippy defers (or isn't installed), a small model (Haiku) judges the command `SAFE` / `UNSAFE`. `SAFE` → allow, `UNSAFE` → prompt. |
| Anything else | Silent exit → Claude's normal prompt. |

### Decision flow

```
tool call
   │
   ├─ Read/Write/Edit/NotebookEdit ── path in cwd or .git metadata? ── yes → allow + audit
   │                                   no → fall through to prompt
   │
   ├─ Bash ── dippy AST ── allow → run + audit
   │              │ ask/deny
   │              ▼
   │         AI fallback (Haiku) ── SAFE → allow + audit
   │                                UNSAFE → prompt + audit
   │
   └─ error / no token / unknown tool ── silent exit → normal prompt (fail-safe)
```

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
     the AI fallback; set `SECURE_HANDLER_AI_FALLBACK=0` to skip the AI layer entirely)

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

## FAQ

**Q: Does this let dangerous commands run without asking?**
No. Anything dippy or the AI layer flags as unsafe prompts first. And if the whole analysis
machinery fails, it falls back to prompting — never to auto-allowing.

**Q: Do I need the AI fallback?**
No. Set `SECURE_HANDLER_AI_FALLBACK=0` to run dippy-only. You'll get fewer auto-allows but
zero network calls and no token needed.

**Q: Can I use it with an OpenAI-compatible gateway?**
Yes. Set `SECURE_HANDLER_AI_API=openai` and point `ANTHROPIC_BASE_URL` at your gateway.

**Q: Will it work in git worktrees?**
Yes. Relative paths are resolved against the hook's JSON `cwd`, and `.git` metadata files
used by worktrees are handled explicitly.

## License

MIT — see [LICENSE](LICENSE).