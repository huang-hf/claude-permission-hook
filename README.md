# claude-permission-hook

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Hook-orange)](https://claude.com/claude-code)

A smart permission gate for [Claude Code](https://claude.com/claude-code) (with a small
multi-agent adapter layer for other coding agents). It auto-approves obviously-safe
operations so you stop clicking "Yes" all day, while a fixed set of red lines always still
prompt — and it logs every decision for auditing.

- **Fewer prompts, same safety.** Safe file ops and commands run without asking; anything
  risky still prompts.
- **Red lines come first and never go out to any backend.** Production infra, destructive
  operations, and credential access are matched by local regex before anything else runs —
  no network call can ever override them.
- **Pluggable Bash judgment backend.** Local offline AST parsing (dippy) first, then one
  judgment backend of your choice for what dippy can't decide.
- **Fail-safe by design.** Any error, missing token/key, or unhandled case hands the decision
  back to the agent's own permission mode. It never *reduces* safety on failure.
- **Full audit trail.** Every decision is appended to `~/.claude/logs/permission_audit.jsonl`
  (or `SECURE_HANDLER_AUDIT_LOG`).
- **No hardcoded secrets.** Tokens/keys and API bases come from env vars; nothing sensitive in
  the repo.

## Why

Claude Code's default permission flow asks about *everything* — safe commands too. You can
switch to `yolo`/`bypassPermissions` mode to silence the prompts, but that means no guardrails
at all. This hook is the middle path: it says yes to things that are clearly safe, always says
no (i.e. still prompts) for a fixed red-line set, and lets a judgment backend decide the rest.

## How it works

Claude Code resolves permissions in this order:
`deny rules → allow rules → PreToolUse hook → permission mode (default / auto)`.

This hook is agent-agnostic internally (`Request` → `judge()` → `Verdict`), with a thin
adapter per agent at the edges. Only the `claude-code` adapter is implemented today; pass
`--agent claude-code` (or omit `--agent`, since `claude-code` is the default) in the hook
command. An unrecognized `--agent` value exits silently (fail-safe) rather than guessing.

For Claude Code, the hook sits at the `PreToolUse` layer, so its `allow` short-circuits
*before* the prompt. What it doesn't explicitly allow falls through to your normal mode.

### Decision order (every request)

1. **Red lines** (`check_redlines`) — always checked first, purely local regex, no network.
   A hit always means `ask`; nothing downstream can override it.
2. **Local path rules** — file reads/writes handled without touching a backend (see below).
3. **dippy** — local offline AST analysis of the Bash command. `allow` → done, no prompt.
4. **Judgment backend** (only reached if dippy didn't allow) — one of `anthropic` /
   `typesafe` / `off`, selected by `SECURE_HANDLER_BACKEND`. Backends are **mutually
   exclusive, not chained**: pick one, and if it fails or is unconfigured you get `ask` (or
   `off`'s silent hand-back) — the hook does not fall through to try a different backend.

### The four allow rules

Everything the hook can say `allow` to, in one place:

| # | Rule | Where | Condition |
|---|---|---|---|
| 1 | **File read, any path** | `local_rules`, `file_read` | Any `Read`, as long as it didn't already hit a credentials red line (e.g. `~/.ssh/`, `~/.aws/`, `.env`, `kubeconfig`, macOS Keychain, shell history). Reading doesn't mutate anything, and blocking reads outside cwd mostly just makes the agent retry — so reads are allowed everywhere except the credential-location red line. |
| 2 | **File write inside cwd / git metadata** | `local_rules`, `file_write` | `Write`/`Edit`/`NotebookEdit` where the resolved path is inside the current working directory, or inside the current repo's `.git` common dir (excluding `.git/hooks/` and `.git/config*`, which can execute code / change hook paths). |
| 3 | **dippy static allow** | `remote_judge` | dippy's local AST analysis classifies the Bash command as safe, purely offline. |
| 4 | **Backend judged safe** | `remote_judge` → `ask_ai` / `backend_typesafe` | dippy deferred, and the configured backend (`anthropic` fallback model, or `typesafe`) judged the command safe. |

Anything not covered by these four falls through to `ask` (red line / backend said unsafe) or
`no_opinion` (hook stays silent — see the audit schema below).

### Red lines (never auto-approved, by any backend)

Three fixed categories, matched by local regex in `check_redlines()`, checked before anything
else and before any network call:

| Category | Covers |
|---|---|
| `prod_infra` | `kubectl` write verbs (`apply`/`delete`/`exec`/`patch`/`rollout`/... and `config use-context`), `terraform apply/destroy`, `helm upgrade/install/delete/rollback`, `eksctl create/delete`, `aws s3 rm`. |
| `credentials` | Credential *locations* (`~/.ssh`, `~/.aws`, `~/.kube`, `~/.gnupg`, `.netrc`, `.docker/config.json`, `id_rsa`/`.pem`, `~/.claude/settings(.local).json`, `gh`/`gcloud`/`azure` credential stores, shell history, `.tfstate`, macOS Keychain), a narrow filename whitelist (`.env`, `.git-credentials`, `.npmrc`, `.pypirc`, `.pgpass`, `authorized_keys`, `kubeconfig`, `secrets.yaml`, key/cert files), plus credential *actions* in command text (`export …SECRET…=`, `--password=`/`--token=`, `vault …`, `gh auth token`, `docker login`, `kubectl get secret`, `coffer …`). |
| `destructive` | `rm -rf`/`-fr` (any flag order/spelling), `git push --force`, `git reset --hard`, `git clean -fd`, `git checkout -- .`/`git checkout .`, `git restore`, `git stash clear/drop`, `git branch -D`, `git worktree remove --force`, `drop table/database`, `truncate`, `dd if=`, `mkfs`. |

These are deliberately biased toward over-matching: a false positive here just costs one extra
prompt; a false negative could run something unrecoverable. See the "lessons" note in
`secure_handler.py` (`_PATH_END`) about a recurring class of bug: path-shaped patterns (`^`,
`$`, `/` anchors, bare keyword matches) behave completely differently against a *file path*
than against a *command string* — a pattern must be validated against both shapes.

### Per tool

| Tool | Behavior |
|---|---|
| `Read` | Allow any path, unless it hits a credentials red line. |
| `Write` / `Edit` / `NotebookEdit` | Allow when the path is inside the current working directory, or inside the current repo's `.git` metadata (excluding `hooks/` and `config`). Otherwise `no_opinion` (falls through to your normal mode). |
| `Bash` | Red lines first. Then dippy AST analysis (local, offline): `allow` → runs with no prompt. Otherwise the configured judgment backend decides `SAFE`/`UNSAFE` (or `ask`/`no_opinion` for `off`). |
| Anything else | Silent exit → agent's normal prompt. |

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
   python3.12 -m pip install --user dippy certifi
   which python3.12   # e.g. /usr/local/bin/python3.12  → use this absolute path below
   ```

   `certifi` is optional but recommended — see the TLS note below.

3. Merge `settings.json.template` into your `~/.claude/settings.json`, replacing:
   - `<PYTHON_WITH_DIPPY>` → the absolute path from step 2 (e.g. `/usr/local/bin/python3.12`)
   - the env placeholders for whichever judgment backend you pick (see Config below)

4. Reload: open `/hooks` once, or restart Claude Code (hook registration is read at startup).

## Config

### Core switches

| Env var | Default | Meaning |
|---|---|---|
| `SECURE_HANDLER_BACKEND` | `anthropic` | Which judgment backend handles Bash commands dippy didn't decide: `anthropic` (small-model SAFE/UNSAFE fallback), `typesafe` (structured risk-question backend), or `off` (no backend call — hand back to the agent's own mode, silently). Backends are **mutually exclusive**: there is no chaining/fallback between them. |
| `SECURE_HANDLER_AUDIT_LOG` | `~/.claude/logs/permission_audit.jsonl` | Where audit rows are appended. |
| `SECURE_HANDLER_INSECURE_TLS` | — | Set to `1` to skip TLS certificate verification (only for local MITM proxies). Off by default — certificates are verified. |

### `anthropic` backend (`SECURE_HANDLER_BACKEND=anthropic`, the default)

| Env var | Default | Meaning |
|---|---|---|
| `SECURE_HANDLER_AI_FALLBACK` | `1` | `0` disables this backend entirely (dippy-only; undecided commands fall through as `no_opinion`). |
| `SECURE_HANDLER_AI_API` | `anthropic` | API format: `anthropic` (Messages API) or `openai` (chat completions — OpenAI-compatible gateways/proxies). |
| `SECURE_HANDLER_AI_MODEL` | `claude-haiku-4-5-20251001` | Model used for the SAFE/UNSAFE judgment call. |
| `SECURE_HANDLER_AI_BASE_URL` / `SECURE_HANDLER_AI_KEY` | — | Base URL / key dedicated to this hook, decoupled from your main conversation's credentials. If set, they are used **as a pair** — setting only `SECURE_HANDLER_AI_BASE_URL` does not fall back to `ANTHROPIC_AUTH_TOKEN` for the key (that would leak your main-conversation token to an unrelated endpoint by accident). |
| `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_BASE_URL` | — | Fallback pair used only if the `SECURE_HANDLER_AI_*` pair above is unset. Kept for installs that don't want a separate token. |

### `typesafe` backend (`SECURE_HANDLER_BACKEND=typesafe`)

| Env var | Default | Meaning |
|---|---|---|
| `SECURE_HANDLER_TYPESAFE_URL` | `https://api.typesafe.ai/v1/systemone` | Endpoint. |
| `SECURE_HANDLER_TYPESAFE_KEY` | — | Required; no key → `ask` (`typesafe_no_key`). |
| `SECURE_HANDLER_TYPESAFE_MODEL` | `jev-latest` | Model name sent in the request. |
| `SECURE_HANDLER_THRESHOLD` | `0.15` | Risk score threshold (0–1, per-dimension "worst wins"): `allow` if the max risk score across dimensions is below this, else `ask`. |
| `SECURE_HANDLER_TYPESAFE_TIMEOUT` | `6` (seconds) | Request timeout. |

Before switching to `typesafe`, read the calibration note below — as of this writing its
score *ranking* was found unreliable, independent of threshold choice.

## Audit schema

Every hook invocation appends one JSON line. Always written: `ts` / `tool` / `decision` /
`layer` / `reason` / `hook_event_name`. Written when present: `cmd` / `ai` / `backend` /
`scores` / `elapsed_ms`.

`decision` has three values, and **they are not interchangeable**:

| `decision` | Meaning |
|---|---|
| `allow` | The hook actively approved the call — it ran with **no prompt**. Real, measurable savings. |
| `ask` | The hook actively **required** a prompt (red line hit, backend judged unsafe, etc). This is a genuine "hook asked". |
| `no_opinion` | The hook printed nothing and handed the decision back to the agent's own permission rules / mode. **The user may or may not have been prompted** — the hook has no visibility into that outcome. |

**The recurring footgun:** treating `no_opinion` as "the user was prompted" is wrong and
overstates prompt counts. This distinction didn't exist before this project's audit-schema
change — older log lines predate the `no_opinion` value (and predate the `hook_event_name`
field) and recorded this same "handed back silently" case as `ask`, because there was no
better value available at the time. `hook_event_name` being absent as a *key* (not just
`null`) is how you tell a pre-refactor row from a new one. `analyze_audit.py` reports `allow`
/ `ask` / `no_opinion` as separate counts and calls this out explicitly rather than folding
`no_opinion` into a prompt rate.

`backend` / `scores` / `elapsed_ms` are only present on rows that reached a backend that
reports them (currently `typesafe`): `backend` names it, `scores` is the per-dimension risk
score dict, `elapsed_ms` is request latency. `analyze_audit.py` surfaces latency percentiles
and score distribution when these fields are present.

## Bash judgment prompt (anthropic backend)

The `anthropic` backend asks a small model to classify a command as `SAFE`/`UNSAFE` given the
command and the project cwd — see `AI_PROMPT` in `secure_handler.py` if you want to tune the
criteria to your own risk tolerance. Red lines are checked before this, so the model is never
the last line of defense for the categories in the red-line table above.

## TLS

The script prefers [`certifi`](https://pypi.org/project/certifi/)'s CA bundle if it's
importable, falling back to the stdlib default context otherwise. This matters because
python.org's macOS installer does **not** ship a system CA bundle the way Homebrew/system
Python does — with a bare `ssl.create_default_context()` on that Python, HTTPS calls to any
backend fail with `CERTIFICATE_VERIFY_FAILED`. Fix either by installing `certifi`
(`python3.12 -m pip install --user certifi`, picked up automatically) or by running Python's
own `Install Certificates.command` (in `/Applications/Python 3.x/`). TLS verification is on
by default regardless of which CA source is used; `SECURE_HANDLER_INSECURE_TLS=1` only exists
for local MITM debugging proxies.

## Tests

```bash
python3.12 -m unittest discover tests
```

120 tests across the local rule engine, red lines (path-form and command-form), the
Claude Code adapter, the audit log, the `typesafe` backend, config parsing, and the
`PreToolUse` red-line short-circuit.

## Calibration script

`calibrate_threshold.py` replays real commands from your own audit log (last N days /
last N deduped commands, red-line commands excluded before anything is sent anywhere) through
`backend_typesafe()` to see how a candidate backend's risk scores actually distribute before
you rely on them. It's read-only: it doesn't touch your live config or hook.

```bash
SECURE_HANDLER_TYPESAFE_KEY=... \
  python3.12 calibrate_threshold.py --limit 80 --days 30
```

It reports latency percentiles, the score distribution (with a histogram), allow-rate at a
few candidate thresholds, and — most importantly — a **disagreement list**: commands where
the backend's decision differs from what your historical audit log recorded, sorted by score
so you can eyeball the worst cases first. A backend can look fine in aggregate (good latency,
sane allow-rate) while still having several commands come out with an *inverted* risk
ordering relative to each other — no threshold fixes that, only re-testing the backend does.
Re-run this whenever the backend/model changes before trusting a new threshold.

## ⚠️ Security notes

- **This script has no hardcoded secrets** — tokens/keys and base URLs are read from env vars.
  Never commit your real `~/.claude/settings.json` (it holds your tokens) or the audit log
  (it holds your full command history). See `.gitignore`.
- **TLS verification is on by default.** Only if you use a local MITM proxy set
  `SECURE_HANDLER_INSECURE_TLS=1` to bypass it. Combining an `http://` base URL with the
  bypass is only meant for local debugging.
- **Red lines are the actual safety boundary**, not the backend. Review the patterns in
  `secure_handler.py` (`_REDLINES`, `_CREDENTIAL_ACTIONS`) and adjust them to your own risk
  tolerance — a backend judgment can be wrong or unreachable, but a red-line hit is always
  `ask`, unconditionally.
- Putting a hook on `PreToolUse` for `Bash` (not just `PermissionRequest`) makes a rule
  genuinely unbypassable, including by `bypassPermissions`/yolo mode — but it also means a
  false positive there stalls the workflow rather than costing one extra confirmation click.
  Keep whatever you register there to near-zero false-positive patterns.

## FAQ

**Q: Does this let dangerous commands run without asking?**
No. Red lines always prompt regardless of backend. Anything else dippy or the backend flags
as unsafe prompts first. And if the whole analysis machinery fails, it hands back to the
agent's normal mode — never to auto-allowing.

**Q: Do I need a judgment backend?**
No. Set `SECURE_HANDLER_BACKEND=off` (or `SECURE_HANDLER_AI_FALLBACK=0` with the default
`anthropic` backend) to run dippy + red-lines only. You'll get fewer auto-allows but zero
extra network calls.

**Q: Can I use the anthropic backend with an OpenAI-compatible gateway?**
Yes. Set `SECURE_HANDLER_AI_API=openai` and point `SECURE_HANDLER_AI_BASE_URL` (or
`ANTHROPIC_BASE_URL`) at your gateway.

**Q: Should I switch to the `typesafe` backend?**
Calibrate first with `calibrate_threshold.py` against your own traffic and look at the
disagreement list, not just the aggregate score distribution — a plausible-looking latency
and allow-rate can still hide an unreliable score ranking.

**Q: Will it work in git worktrees?**
Yes. Relative paths are resolved against the hook's JSON `cwd`, and `.git` metadata files
used by worktrees are handled explicitly.

**Q: What other agents does `--agent` support?**
Only `claude-code` today (`ADAPTERS` in `secure_handler.py`). The `Request`/`Verdict`/`judge()`
core is agent-agnostic by design; adding another agent means writing a `parse_*`/`emit_*`
adapter pair, not touching the decision logic.

## License

MIT — see [LICENSE](LICENSE).
