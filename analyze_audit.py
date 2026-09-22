#!/usr/bin/env python3
"""
analyze_audit.py — surface permission-prompt optimization candidates.

Reads the secure_handler audit log (~/.claude/logs/permission_audit.jsonl) and
reports which `ask` decisions (the ones the hook actively required) recur often
enough to be worth allowlisting — split into:

  1. File-op prompts (Read/Edit/Write outside cwd)  → candidate `permissions.allow` rules
  2. Bash prompts (hook said ask)                    → mostly keep; safe read-only ones flagged
  3. dippy_error rows                                → a session on the wrong Python (infra fix)

`decision` in the audit log has THREE values, and they are NOT interchangeable:

  allow       — the hook actively approved the call; it ran with no prompt.
                A real, measurable prompt saved.
  ask         — the hook actively required a prompt (redline hit, AI/TypeSafe
                judged unsafe, dippy deferred with no fallback allow, etc).
                This IS the hook asking for confirmation.
  no_opinion  — the hook stayed silent and handed the decision back to the
                agent's own permission rules / mode. The user MAY OR MAY NOT
                have been prompted — this script has no visibility into that.
                Counting `no_opinion` as "prompted" overstates prompts badly.

Older log lines (written before `no_opinion` existed as a value, and before
`hook_event_name` was recorded) recorded this same "handed back to the agent"
case as `ask` — there was no other value available at the time. That means
historical `ask` counts mix two different things: "hook actively asked" and
"hook said nothing, old code labeled it ask anyway". `hook_event_name` being
absent (None, not just falsy) is how you tell old rows from new ones; this
script reports both counts explicitly instead of silently combining them.

Usage:
  python3 analyze_audit.py [--days N] [--top N] [--log PATH]

Nothing here auto-changes config. It only recommends. You decide what to apply.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import statistics
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_LOG = Path.home() / ".claude" / "logs" / "permission_audit.jsonl"

# Commands that SHOULD keep prompting — never suggest allowlisting these.
KEEP_PATTERNS = re.compile(
    r"kubectl|coffer|secret|credential|token|private[_\- ]?key|password|"
    r"aws .*secret|rm -rf|rm -fr|\bdd \b|mkfs|shutdown|reboot|"
    r"curl .*-d|curl .*--data|wget .*post|nc |ncat |\bscp\b|"
    r"chmod -R|chown -R|/\.ssh/|/\.aws/",
    re.IGNORECASE,
)
# Read-only-ish tokens: if a Bash `ask` row is dominated by these, it's a
# candidate worth reviewing (probably a pipe/redirect tripped a pattern).
SAFE_HINT = re.compile(
    r"\b(cat|sed|head|tail|less|grep|rg|find|ls|wc|awk|cut|sort|uniq|jq|"
    r"git log|git diff|git status|git show|gh run view|gh pr view|gh issue view)\b",
    re.IGNORECASE,
)


def load(log: Path, days: int) -> list[dict]:
    if not log.exists():
        raise SystemExit(f"audit log not found: {log}")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = []
    with log.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("ts", "") >= cutoff:
                rows.append(r)
    return rows


def top_dir(path: str, depth: int = 5) -> str:
    """Group a file path by its first `depth` components (e.g. ~/PycharmProjects/repo)."""
    parts = [p for p in path.split(os.sep) if p]
    return os.sep + os.sep.join(parts[:depth]) if parts else path


def _quantile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return float("nan")
    idx = min(len(sorted_vals) - 1, int(len(sorted_vals) * q))
    return sorted_vals[idx]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--log", type=Path, default=DEFAULT_LOG)
    args = ap.parse_args()

    rows = load(args.log, args.days)

    allows = [r for r in rows if r.get("decision") == "allow"]
    asks = [r for r in rows if r.get("decision") == "ask"]
    no_opinions = [r for r in rows if r.get("decision") == "no_opinion"]

    # hook_event_name is written on every new-format row (null included when
    # the input carried no such field). Its plain absence as a key marks a
    # pre-refactor row — that's how old "ask" (= silently handed back) and
    # new "ask" (= hook actively required a prompt) are told apart below.
    legacy_rows = [r for r in rows if "hook_event_name" not in r]
    legacy_asks = [r for r in legacy_rows if r.get("decision") == "ask"]

    print(f"# Permission audit — last {args.days}d  ({args.log})")
    print(f"total={len(rows)}  allow={len(allows)}  ask={len(asks)}  "
          f"no_opinion={len(no_opinions)}  legacy(no hook_event_name)={len(legacy_rows)}\n")
    print("  allow      = hook actively approved → ran with no prompt (real savings).")
    print("  ask        = hook actively required a prompt (redline / unsafe judgment).")
    print("  no_opinion = hook stayed silent, handed off to the agent's own rules/mode —")
    print("               the user MAY OR MAY NOT have been prompted; unknown from this log.")
    if legacy_rows:
        print(f"  ⚠️  {len(legacy_asks)}/{len(legacy_rows)} legacy rows (pre-dates `no_opinion`/"
              f"`hook_event_name`) are recorded as decision='ask' but may actually be what would")
        print(f"      now be classified `no_opinion` — the two were not distinguishable back then.")
        print(f"      Do not read historical ask-rate trends across the {len(legacy_rows)} legacy "
              f"rows as directly comparable to new ask-rate.")
    print()

    # 1) File-op prompts (the usual biggest win) ---------------------------------
    # Only `ask` rows are genuine prompts; file-op `no_opinion` rows fell through
    # to the agent's own permission handling and may or may not have prompted.
    fileops = [r for r in asks if r.get("tool") in ("Read", "Write", "Edit", "NotebookEdit")]
    fileops_no_opinion = [r for r in no_opinions
                          if r.get("tool") in ("Read", "Write", "Edit", "NotebookEdit")]
    dir_count: dict[str, int] = collections.Counter()
    dir_last: dict[str, str] = {}
    for r in fileops:
        d = top_dir(str(r.get("cmd", "")))
        dir_count[d] += 1
        ts = r.get("ts", "")
        if ts > dir_last.get(d, ""):
            dir_last[d] = ts
    print(f"## 1. File-op `ask` rows: {len(fileops)}  → candidate permissions.allow rules")
    print(f"    (file-op no_opinion rows: {len(fileops_no_opinion)} — hook stayed silent, "
          f"not counted as prompts here)")
    print(f"  {'cnt':>4}  {'last seen':<16}  dir")
    if dir_count:
        for d, n in dir_count.most_common(args.top):
            print(f"  {n:>4}× {dir_last[d][:16]:<16}  {d}")
        print("  → for a directory you trust:  "
              'Read(//<dir>/**), Edit(//<dir>/**), Write(//<dir>/**)')
        print("  → 'last seen' before your last config change = already fixed (stale), ignore it.")
    else:
        print("  (none)")
    print()

    # 2) Bash prompts -------------------------------------------------------------
    bash = [r for r in asks if r.get("tool") == "Bash"]
    bash_no_opinion = [r for r in no_opinions if r.get("tool") == "Bash"]
    keep, candidate = [], []
    for r in bash:
        blob = f"{r.get('reason','')} {r.get('cmd','')}"
        if KEEP_PATTERNS.search(blob):
            keep.append(r)
        elif SAFE_HINT.search(blob) and not KEEP_PATTERNS.search(blob):
            candidate.append(r)
        else:
            candidate.append(r)  # unknown → surface for human review
    def by_reason(group):
        cnt: dict[str, int] = collections.Counter()
        last: dict[str, str] = {}
        for r in group:
            key = str(r.get("reason", ""))[:52]
            cnt[key] += 1
            ts = r.get("ts", "")
            if ts > last.get(key, ""):
                last[key] = ts
        return cnt, last

    print(f"## 2. Bash `ask` rows: {len(bash)}  (keep={len(keep)}  review={len(candidate)})")
    print(f"    (Bash no_opinion rows: {len(bash_no_opinion)} — hook deferred to the agent, "
          f"not counted as prompts here)")
    print("  -- KEEP prompting (dangerous — do NOT allowlist): top reasons --")
    kc, kl = by_reason(keep)
    for reason, n in kc.most_common(8):
        print(f"    {n:>4}× {kl[reason][:16]:<16}  {reason}")
    print("  -- REVIEW (read-only-ish that still prompted — maybe tune autoMode.allow) --")
    cc, cl = by_reason(candidate)
    for reason, n in cc.most_common(args.top):
        print(f"    {n:>4}× {cl[reason][:16]:<16}  {reason}")
    print()

    # 3) Infra: dippy_error = a session on the wrong Python ------------------------
    derr = [r for r in rows if "dippy_error" in str(r.get("reason", ""))]
    print(f"## 3. dippy_error rows: {len(derr)}")
    if derr:
        print("  → a Claude Code session is running the hook with a python that lacks dippy.")
        print("    Pin the hook command to the python that has dippy (see README).")
    else:
        print("  ✅ none — every session's hook is using dippy.")
    print()

    # 4) Backend telemetry: latency + score distribution (only present when the
    #    `backend`/`elapsed_ms`/`scores` fields were written, e.g. TypeSafe rows) --
    backend_rows = [r for r in rows if r.get("backend")]
    print(f"## 4. Backend telemetry: {len(backend_rows)} rows carry `backend`/`elapsed_ms`/`scores`")
    if backend_rows:
        by_backend: dict[str, list[dict]] = collections.defaultdict(list)
        for r in backend_rows:
            by_backend[str(r.get("backend"))].append(r)
        for backend, group in sorted(by_backend.items()):
            elapsed = sorted(r["elapsed_ms"] for r in group if r.get("elapsed_ms") is not None)
            print(f"  backend={backend}  n={len(group)}")
            if elapsed:
                median = statistics.median(elapsed)
                p90 = _quantile(elapsed, 0.9)
                print(f"    latency: median={median:.0f}ms  p90={p90:.0f}ms  max={elapsed[-1]:.0f}ms")
            worst_scores = sorted(
                max(r["scores"].values()) for r in group if r.get("scores")
            )
            if worst_scores:
                print(f"    score (max over dims): min={worst_scores[0]:.3f}  "
                      f"median={statistics.median(worst_scores):.3f}  "
                      f"p90={_quantile(worst_scores, 0.9):.3f}  max={worst_scores[-1]:.3f}")
    else:
        print("  (none — no backend telemetry in this window; typical for dippy-only/off/anthropic runs)")


if __name__ == "__main__":
    main()
