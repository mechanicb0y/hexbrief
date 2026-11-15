"""Summarise the daily run logs for the resume bullets (real numbers only).

    python scripts/run_stats.py            # all runs/YYYY-MM-DD.json

Prints the days covered, the first-try pass rate of the LLM narrative, how many
briefs shipped with a validated narrative vs facts-only, findings in/after dedupe,
and the median runtime. Nothing is sent anywhere.
"""

from __future__ import annotations

import json
import re
import statistics
from pathlib import Path

RUNS = Path(__file__).resolve().parents[1] / "runs"
DAY = re.compile(r"^\d{4}-\d{2}-\d{2}\.json$")


def main() -> int:
    logs = []
    for p in sorted(RUNS.glob("*.json")):
        if DAY.match(p.name):
            try:
                logs.append(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as e:
                print(f"skip {p.name}: {e}")
    if not logs:
        print("no run logs in runs/")
        return 1
    llm = [r.get("llm") or {} for r in logs]
    tried = [x for x in llm if x.get("attempts")]
    first = sum(
        1 for x in tried if x["attempts"][0].get("valid") and x["attempts"][0].get("complete")
    )
    shipped = sum(1 for x in llm if x.get("ok"))
    print(f"days: {len(logs)} ({logs[0].get('day')} .. {logs[-1].get('day')})")
    if tried:
        pct = 100 * first / len(tried)
        print(f"first-try pass (faithful + complete): {first}/{len(tried)} = {pct:.0f}%")
    print(f"validated narrative shipped: {shipped}/{len(logs)}; facts-only: {len(logs) - shipped}")
    fin = [r["findings_in"] for r in logs if "findings_in" in r]
    ded = [r["after_dedupe"] for r in logs if "after_dedupe" in r]
    rt = [r["runtime_seconds"] for r in logs if "runtime_seconds" in r]
    if fin:
        print(f"findings in: total {sum(fin)}, median/day {statistics.median(fin):.0f}")
    if ded:
        print(f"after dedupe: total {sum(ded)}, median/day {statistics.median(ded):.0f}")
    if rt:
        print(f"median runtime: {statistics.median(rt):.0f} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
