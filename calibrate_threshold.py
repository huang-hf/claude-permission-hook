#!/usr/bin/env python3
"""用历史审计日志中的真实命令标定 TypeSafe 阈值。

只读:不修改任何配置,不接触线上 hook。红线命令(`sh.check_redlines`)在取样阶段
就被剔除,绝不会被发送出去。

用法:
  SECURE_HANDLER_TYPESAFE_KEY=... \\
  /usr/local/bin/python3.12 calibrate_threshold.py --limit 80 --days 30
"""
from __future__ import annotations

import argparse
import collections
import json
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secure_handler as sh

DEFAULT_LOG = Path.home() / '.claude' / 'logs' / 'permission_audit.jsonl'
SLEEP_BETWEEN_CALLS = 0.1  # 秒,避免打爆对方的限流
CANDIDATE_LAYERS = ('ai', 'typesafe')  # 只取曾经真正走到远程判断的命令


def load_rows(log: Path, days: int | None) -> list[dict]:
    if not log.exists():
        raise SystemExit(f'audit log not found: {log}')
    cutoff = None
    if days is not None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = []
    with log.open(encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if cutoff is not None and str(r.get('ts', '')) < cutoff:
                continue
            rows.append(r)
    return rows


def collect_candidates(rows: list[dict], limit: int) -> list[tuple[str, str | None]]:
    """去重、按红线过滤后的 (cmd, 历史 decision) 列表,最多 `limit` 条,取最近的。"""
    cands: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    for r in reversed(rows):  # 最近的在前
        if r.get('tool') != 'Bash' or r.get('layer') not in CANDIDATE_LAYERS:
            continue
        cmd = str(r.get('cmd', ''))
        if not cmd or cmd in seen:
            continue
        if sh.check_redlines(sh.Request('command', cmd, '')):
            continue  # 红线命令不出网,也不参与标定
        seen.add(cmd)
        cands.append((cmd, r.get('decision')))
        if len(cands) >= limit:
            break
    return cands


def quantile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return float('nan')
    idx = min(len(sorted_vals) - 1, int(len(sorted_vals) * q))
    return sorted_vals[idx]


def histogram(worst_scores: list[float], buckets: int = 10) -> None:
    counts = [0] * buckets
    for w in worst_scores:
        b = min(buckets - 1, int(w * buckets))
        counts[b] += 1
    peak = max(counts) or 1
    for i, c in enumerate(counts):
        lo, hi = i / buckets, (i + 1) / buckets
        bar = '█' * int(40 * c / peak)
        print(f'  [{lo:.2f}, {hi:.2f}) {c:>3}  {bar}')


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', type=Path, default=DEFAULT_LOG)
    ap.add_argument('--limit', type=int, default=80,
                    help='最多回放多少条去重后的命令(默认 80)')
    ap.add_argument('--days', type=int, default=None,
                    help='只取最近 N 天的审计日志(默认不限)')
    args = ap.parse_args()

    rows = load_rows(args.log, args.days)
    cands = collect_candidates(rows, args.limit)
    print(f'标定样本: {len(cands)} 条(已排除红线命令)\n')

    # results: cmd, 历史 decision, Verdict
    results: list[tuple[str, str | None, sh.Verdict]] = []
    for i, (cmd, hist_decision) in enumerate(cands, 1):
        try:
            v = sh.backend_typesafe(sh.Request('command', cmd, str(Path.home())))
        except Exception as e:
            # 单条失败不能打断整轮标定;记成一个等价的失败 Verdict 继续。
            v = sh.Verdict('ask', f'calibrate_exception:{type(e).__name__}', 'typesafe',
                           backend='typesafe')
        results.append((cmd, hist_decision, v))
        worst = max(v.scores.values()) if v.scores else None
        shown = 'None' if worst is None else f'{worst:.3f}'
        print(f'  [{i}/{len(cands)}] max={shown:<6} {v.reason:<28} {cmd[:60]}')
        time.sleep(SLEEP_BETWEEN_CALLS)

    print()
    _report(results)


def _report(results: list[tuple[str, str | None, sh.Verdict]]) -> None:
    ok = [(cmd, hist, v) for cmd, hist, v in results if v.scores]
    failed = [(cmd, hist, v) for cmd, hist, v in results if not v.scores]

    # -- 延迟分布 --------------------------------------------------------
    elapsed = sorted(v.elapsed_ms for _, _, v in results if v.elapsed_ms is not None)
    if elapsed:
        median = statistics.median(elapsed)
        p90 = quantile(elapsed, 0.9)
        print(f'延迟: 中位={median:.0f}ms  p90={p90:.0f}ms  最大={elapsed[-1]:.0f}ms  (n={len(elapsed)})')
    else:
        print('延迟: 无数据')

    # -- 失败统计 ---------------------------------------------------------
    fail_kinds: dict[str, int] = collections.Counter()
    for _, _, v in failed:
        prefix = str(v.reason).split(':', 1)[0]
        fail_kinds[prefix] += 1
    print(f'\n成功取到分数: {len(ok)}/{len(results)}    失败: {len(failed)}/{len(results)}')
    if fail_kinds:
        for kind, n in fail_kinds.most_common():
            print(f'  {kind:<24} {n}')

    if not ok:
        print('\n⚠️ 没有任何一条取到分数,以下统计全部跳过(检查后端 URL/KEY 是否配置)。')
        return

    # -- 分数分布(worst = max over dimensions)----------------------------
    worst_scores = sorted(max(v.scores.values()) for _, _, v in ok)
    print(f'\n分数分布(每条命令取各维度最差分,共 {len(worst_scores)} 条):')
    print(f'  min={worst_scores[0]:.3f}  p25={quantile(worst_scores, 0.25):.3f}  '
          f'median={statistics.median(worst_scores):.3f}  '
          f'p75={quantile(worst_scores, 0.75):.3f}  '
          f'p90={quantile(worst_scores, 0.9):.3f}  max={worst_scores[-1]:.3f}')
    histogram(worst_scores)

    # -- 各阈值下的放行率 ---------------------------------------------------
    print('\n各阈值下的放行率:')
    for t in (0.05, 0.10, 0.15, 0.20, 0.30, 0.50):
        n = sum(1 for w in worst_scores if w < t)
        print(f'  阈值 {t:<5} → 放行 {n:>3}/{len(worst_scores)} ({n/len(worst_scores):.0%})')
    print('\n⚠️ 放行率高不等于安全。提高阈值前,必须人工抽查新放行的命令(见下面的分歧清单)。')

    # -- 分歧清单:TypeSafe 判定 vs 历史 decision --------------------------
    # 用当前配置的 SECURE_HANDLER_THRESHOLD(即 v.decision,backend_typesafe 已按它算过)
    # 与历史记录里这条命令当时被判定的 decision 做对比,按分数从高到低排序,方便人工优先看
    # "TypeSafe 觉得危险、历史却放行" 或反过来的样本。
    disagreements = []
    for cmd, hist, v in ok:
        worst = max(v.scores.values())
        if hist is not None and hist != v.decision:
            disagreements.append((worst, cmd, hist, v.decision, v.reason))
    disagreements.sort(key=lambda x: x[0], reverse=True)
    print(f'\n分歧清单(TypeSafe 判定 ≠ 历史 decision,共 {len(disagreements)} 条,按分数降序,供人工抽查):')
    if disagreements:
        for worst, cmd, hist, cur, reason in disagreements:
            print(f'  score={worst:.3f}  历史={hist:<6} → TypeSafe={cur:<6}  {cmd[:70]}')
    else:
        print('  (无 —— 抽样范围内 TypeSafe 判定与历史记录完全一致)')


if __name__ == '__main__':
    main()
