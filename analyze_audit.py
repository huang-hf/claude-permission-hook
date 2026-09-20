#!/usr/bin/env python3
"""
analyze_audit.py — surface permission-prompt optimization candidates.

Reads the secure_handler audit log (~/.claude/logs/permission_audit.jsonl) and
reports which `ask` decisions (the ones that interrupted you) recur often enough
to be worth allowlisting — split into:

  1. File-op prompts (Read/Edit/Write outside cwd)  → candidate `permissions.allow` rules
  2. Bash prompts (dippy deferred → AI said UNSAFE)  → mostly keep; safe read-only ones flagged
  3. dippy_error rows                                → a session on the wrong Python (infra fix)

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
# Read-only-ish tokens: if a deferred Bash prompt is dominated by these, it's a
# candidate worth reviewing (dippy didn't allow it, often due to a pipe/redirect).
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--log", type=Path, default=DEFAULT_LOG)
    args = ap.parse_args()

    rows = load(args.log, args.days)
    asks = [r for r in rows if r.get("decision") == "ask"]
    allows = [r for r in rows if r.get("decision") == "allow"]
    print(f"# Permission audit — last {args.days}d  ({args.log})")
    print(f"total={len(rows)}  allow={len(allows)}  ask(prompted you)={len(asks)}"
          f"  → prompt rate {len(asks)/max(1,len(rows)):.0%}\n")

    # 1) File-op prompts (the usual biggest win) ---------------------------------
    fileops = [r for r in asks if r.get("tool") in ("Read", "Write", "Edit", "NotebookEdit")]
    dir_count: dict[str, int] = collections.Counter()
    dir_last: dict[str, str] = {}
    for r in fileops:
        d = top_dir(str(r.get("cmd", "")))
        dir_count[d] += 1
        ts = r.get("ts", "")
        if ts > dir_last.get(d, ""):
            dir_last[d] = ts
    print(f"## 1. File-op prompts: {len(fileops)}  → candidate permissions.allow rules")
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

    print(f"## 2. Bash prompts: {len(bash)}  (keep={len(keep)}  review={len(candidate)})")
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


if __name__ == "__main__":
    main()
