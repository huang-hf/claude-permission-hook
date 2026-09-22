# claude-permission-hook

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Hook-orange)](https://claude.com/claude-code)

A smart permission gate for [Claude Code](https://claude.com/claude-code), with a
[Codex PermissionRequest adapter](#codex-installation). It auto-approves
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
   cp secure_handler.py personal_rules.py ~/.claude/hooks/
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

## Codex installation

Codex and Claude Code can use the **same installed `secure_handler.py`**. The
`--agent codex` flag selects the Codex protocol; omitting it preserves Claude's
existing behavior. Both call the same `judge()` (redlines → local rules → dippy →
configured AI/TypeSafe backend), so future policy changes apply to both clients.

1. Install/update the shared script and dippy using steps 1–2 above.
2. Merge `codex.hooks.json.template` into `~/.codex/hooks.json`, replacing
   `<PYTHON_WITH_DIPPY>` with your interpreter's absolute path. Preserve any existing
   hooks. The template intentionally registers only **Bash / PermissionRequest**.
   It uses the shared script at `~/.claude/hooks/secure_handler.py`.
3. Restart Codex and use `/hooks` in the CLI to review and trust the new hook.
   Codex skips untrusted hooks. Hooks must be enabled; a managed policy can restrict
   them. Avoid defining the same handler again in inline `config.toml` hooks.
4. Launch Codex with the backend environment variables you want it to inherit.
   Codex does **not** inherit the `env` section of Claude's `settings.json`.
   When remote judgment is needed, missing backend credentials result in normal
   approval, not an automatic allow. Local dippy approvals still work without keys.

Use a Codex version supporting `PermissionRequest` command hooks. This integration
was developed with CLI 0.155.1 (hooks enabled); see the
[official hook contract](https://developers.openai.com/codex/hooks/).

| Shared verdict | Codex behavior |
|---|---|
| `allow` | Emit `hookSpecificOutput.decision.behavior: "allow"`; approve without a prompt. |
| `ask` / `no_opinion` / error | Emit no decision; continue Codex's normal approval flow. |
| Unsupported event, tool, or malformed request | Emit no decision. |

This is **approval automation, not interception of every operation**:

- `PermissionRequest` only runs when Codex would otherwise request approval.
  Existing allow rules and operations that need no approval do not pass through it.
- Codex's `PreToolUse` does not currently support `permissionDecision: "ask"`.
  The adapter deliberately ignores that event; it cannot reproduce Claude's
  redline-forces-a-prompt behavior for already-allowed commands.
- `apply_patch` (including its `Edit`/`Write` aliases), MCP calls, and other tools
  are left to Codex. Patch text is never passed to the shell-command judge.
- A conflicting hook denial wins over this hook's approval. Other Codex policies
  still apply. Do not disable the sandbox or use approval bypass mode to install it.

The default audit file is shared with Claude:
`~/.claude/logs/permission_audit.jsonl`. To separate Codex records, set
`SECURE_HANDLER_AUDIT_LOG` in its hook command or launch environment to an absolute
path such as `~/.codex/logs/permission_audit.jsonl` (expand `~` in the shell).
For Codex, audit `decision=ask` means the judge deferred; it does not prove a prompt
was displayed. Keep audit files out of version control.

## Two code layers

```text
secure_handler.py    # Core: Claude/Codex protocols, redlines, dippy/AI, audit, fallback
personal_rules.py    # Personal rules: which commands and temporary redirects to allow
```

Run with the default personal rules beside the core script:

```bash
python3 secure_handler.py
python3 secure_handler.py --agent codex
```

Or select your own rule file (any filename is supported):

```bash
python3 secure_handler.py --rule personal_rule.py
python3 secure_handler.py --agent codex --rule ~/.claude/hooks/my_rules.py
```

`--rule` defaults to `personal_rules.py` in the **core script's directory**.
An explicit relative path is resolved from the process working directory; use
an absolute path in hook configuration. `--rule=PATH` is also supported.
The selected file replaces the default personal rules and exposes the same two
functions below. It is executable Python code, so select your own trusted file.
A missing or broken file adds no personal allowances. Existing hook commands
continue to work without changes. Use `--help` to see the options.

To customize behavior, edit **`personal_rules.py`**. Both Claude and Codex call it
through the same core. There is no plugin framework or package hierarchy.

The personal file exposes just two entry points:

- `approved_programs(command, cwd)` returns approved program names only after
  checking the entire command, or `None` to leave the normal flow in control.
- `redirect_rules(command)` returns dippy rules for checked output targets, or
  an empty list to add no redirect allowances.

The supplied implementation dispatches command checks in `_command()`. For example,
to allow one exact invocation of your own CLI within configured trusted directories,
add this branch there:

```python
if tool == 'my-cli':
    return args == ['status', '--json']
```

The existing parser still rejects unsupported shell constructs, checks every
command in a compound expression, and validates redirects. The core retains its
redlines and explicit dippy restrictions. Do not approve a whole interpreter or
shell merely to add support for one command.

`scoped_policy.json` is optional **personal data** used by the supplied rules for
directories and other scopes; it is not another code layer. Its existing filename
and `SECURE_HANDLER_POLICY_PATH` remain compatible. The old `scoped_policy.py`
module has been replaced by `personal_rules.py`.

When migrating an existing installation, install `personal_rules.py` once and
merge any customizations from your old `scoped_policy.py` into it. Keep the
existing JSON unchanged and archive the old Python module. Core-only updates
apply after this one-time migration.

Run `python3.12 -m unittest discover -s tests -q` after changes. For a first install,
copy both Python files. When updating only the core, copy just `secure_handler.py`
to preserve your customized `personal_rules.py` and JSON data. Back up and merge
personal-rule changes when intentionally updating that file. Hooks load the files
on each invocation, so both clients use the same current personal rules.

### Scoped allowances

Copy `scoped_policy.json.template` to `~/.claude/hooks/scoped_policy.json` and fill
in your approved scopes. Its empty defaults enable nothing. Override the location
with `SECURE_HANDLER_POLICY_PATH` if needed. Both clients read the same file on
each invocation. Keep this personal configuration out of Git.

| Setting | Scope |
|---|---|
| `trusted_roots` | Absolute project directories (or `~/...`), including their descendants. Required for every new allowance. |
| `python_executables` | Exact interpreter names/paths allowed for `-m unittest` and loopback-only `-m http.server`. |
| `http_read_endpoints` | HTTPS GET/HEAD endpoints. A trailing `/` allows that path subtree; otherwise the URL path must match exactly. Downloads can write only to `/tmp`. |
| `clone_sources` | Exact Git clone URLs; an explicit destination inside cwd is required. |
| `kube_contexts` | Explicit contexts allowed for selected non-secret `get` resources and `rollout status`. |
| `coffer_namespaces` | Namespaces allowed for `coffer check --global --json` and `coffer run --global` wrapping only scoped kubectl/ECR reads. |
| `aws_regions`, `ecr_repositories` | Regions and repositories for the wrapped `aws ecr describe-images` call. |

Within trusted directories this also allows ordinary `git add`/`git commit -m`,
`lark-cli docs +fetch`, and `code` opening local paths. Git hooks and unittest
execute code belonging to the trusted project. Configure project roots accordingly.
Git push/merge/amend, deployment restarts, secret reads, document writes, arbitrary
Python/shell scripts, uploads, unknown options and dynamic shell expansions do not
receive these new allowances. Existing dippy and AI behavior still applies to
operations outside this module's scope.

Every command in a supported compound expression must pass its own argument
checks. Redirects are restricted to temporary files. Explicit dippy ask/deny rules
retain precedence. A fully recognized readonly kubectl call bypasses the old
infrastructure keyword check so a resource name containing `proxy` no longer
causes a false positive. Only recognized scoped coffer calls bypass the blanket
`coffer` keyword check; other credential and destructive redlines remain active.

## Config

Output redirection to literal paths inside `/tmp/` is allowed by default,
including creation, overwrite (`>`), and append (`>>`). On macOS this also covers
the resolved `/private/tmp/` path. The target is resolved before allowing it;
symlinks or `..` that lead outside the temporary directory do not get this
allowance. Dynamic targets remain subject to normal analysis. Explicit dippy
redirect rules take precedence. This only allows the output target: all commands,
other redirects, and the script's redlines still undergo their existing checks.

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
