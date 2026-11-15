"""Benchmark local models on one fixed fixture (Phase 4, ADR-005).

    python scripts/llm_benchmark.py llama3.2:3b qwen3.5:4b qwen3.5:9b --runs 3

For each model and run: generate (temperature 0.1, schema-constrained), validate,
and retry up to 2 times with the validator's errors fed back, exactly as the brief
engine will. Records time, tokens, JSON validity, first-try pass, final pass and
what was invented. Writes docs/benchmarks/llm-<date>.md (+ raw JSON in runs/).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from hexbrief.llm.client import PROMPT_VERSION, OllamaWriter  # noqa: E402
from hexbrief.validate import validate_narrative  # noqa: E402

FIXTURE = REPO / "tests" / "fixtures" / "brief_findings.json"


def ollama_processor(model: str) -> str:
    """'100% GPU' / '45%/55% CPU/GPU' from `ollama ps` for the loaded model."""
    try:
        exe = shutil.which("ollama")
        if not exe:
            return "?"
        out = subprocess.run([exe, "ps"], capture_output=True, text=True, timeout=30).stdout  # noqa: S603
    except (OSError, subprocess.TimeoutExpired):
        return "?"
    for line in out.splitlines()[1:]:
        if line.startswith(model):
            parts = line.split()
            for i, p in enumerate(parts):
                if p.endswith("GPU") or p.endswith("CPU"):
                    return " ".join(parts[i - 1 : i + 1]) if "%" in parts[i - 1] else p
    return "?"


def run_one(writer: OllamaWriter, findings: list, seed: int) -> dict:
    attempts, feedback, previous = [], None, None
    for attempt in range(3):  # first try + 2 retries
        res = writer.write(findings, feedback=feedback, previous=previous, seed=seed + attempt)
        val = validate_narrative(res.parsed, findings)
        attempts.append(
            {
                "seconds": round(res.seconds, 1),
                "prompt_tokens": res.prompt_tokens,
                "output_tokens": res.output_tokens,
                "json_ok": res.parsed is not None,
                "error": res.error,
                "valid": val.ok,
                "errors": val.errors,
                "invented": val.invented,
            }
        )
        if val.ok:
            break
        feedback = val.errors or [res.error or "invalid output"]
        previous = res.raw or None
    return {"seed": seed, "attempts": attempts, "final_ok": attempts[-1]["valid"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("models", nargs="+")
    ap.add_argument("--runs", type=int, default=3)
    args = ap.parse_args()
    findings = json.loads(FIXTURE.read_text(encoding="utf-8"))

    results = {}
    for model in args.models:
        print(f"== {model}", flush=True)
        with OllamaWriter(model) as w:
            warm = w.write(findings[:1], seed=1)  # warm-up: load weights, not timed
            if warm.error:
                print(f"   skipped: {warm.error}", flush=True)
                continue
            proc = ollama_processor(model)
            runs = [run_one(w, findings, seed=100 * i + 7) for i in range(args.runs)]
        results[model] = {"processor": proc, "runs": runs}
        for r in runs:
            a = r["attempts"]
            print(
                f"   seed {r['seed']}: {len(a)} attempt(s), final_ok={r['final_ok']}, "
                f"first={a[0]['seconds']}s invented={a[0]['invented']}",
                flush=True,
            )

    day = datetime.now(UTC).strftime("%Y-%m-%d")
    raw = REPO / "runs" / f"llm-benchmark-{day}.json"
    raw.parent.mkdir(exist_ok=True)
    raw.write_text(json.dumps(results, indent=1), encoding="utf-8")

    lines = [
        f"# LLM benchmark — {day}",
        "",
        f"Fixture: `tests/fixtures/brief_findings.json` (8 TLP:CLEAR findings). Prompt "
        f"`{PROMPT_VERSION}`, temperature 0.1, JSON-schema structured output, "
        f"{args.runs} runs per model, up to 2 retries with validator feedback.",
        "Hardware: RTX 3050 Laptop 4 GB VRAM, i5-12450H, 14 GB WSL cap (Ollama runs on Windows).",
        "",
        "| Model | Placement | First-try pass | Pass after retries | Avg time / attempt (s) "
        "| Avg output tokens | Attempts with invented facts | JSON valid |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for model, data in results.items():
        runs = data["runs"]
        atts = [a for r in runs for a in r["attempts"]]
        first = sum(r["attempts"][0]["valid"] for r in runs)
        final = sum(r["final_ok"] for r in runs)
        invented = sum(bool(a["invented"]) for a in atts)
        lines.append(
            f"| `{model}` | {data['processor']} | {first}/{len(runs)} | {final}/{len(runs)} | "
            f"{mean(a['seconds'] for a in atts):.0f} | "
            f"{mean(a['output_tokens'] for a in atts):.0f} | {invented}/{len(atts)} | "
            f"{sum(a['json_ok'] for a in atts)}/{len(atts)} |"
        )
    lines += [
        "",
        f"Invented facts and validator errors per attempt are in `runs/{raw.name}` (git-ignored).",
    ]
    out = REPO / "docs" / "benchmarks" / f"llm-{day}.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")  # UTF-8 for the em dash
    print(f"wrote {out.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
