# ADR-005: Local LLM for the brief narrative

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

The narrative must be written by a **local** model (TLP: intel never goes to a cloud API), on an RTX 3050 Laptop with **4 GB VRAM**. The model only writes prose about findings it is given. A validator (`hexbrief.validate`) rejects any IP, domain, URL, hash, CVE or ATT&CK ID that isn't in the input, and the engine retries up to 2 times with the errors fed back before falling back to a facts-only brief.

## Benchmark

[`docs/benchmarks/llm-2026-11-15.md`](../benchmarks/llm-2026-11-15.md). Fixed 8-finding TLP:CLEAR fixture, prompt v1, temperature 0.1, Ollama structured output (JSON schema), `think: false`, `num_ctx` 8192, 3 runs per model.

| Model | Placement | First-try pass | Avg s / brief | Invented facts |
|---|---|---|---|---|
| `llama3.2:3b` | 33/67 CPU/GPU | 3/3 | 16 | 0 |
| `qwen3.5:4b` | 52/48 CPU/GPU | 3/3 | 91 | 0 |
| `qwen3.5:9b` | 74/26 CPU/GPU | 3/3 | 192 | 0 |

All three always produced schema-valid JSON and never invented a fact, so the schema constraint plus the prompt work. The validator therefore can't separate them, and **content quality** decided. A side-by-side sample on the same fixture:
- **llama3.2:3b** cited only 2 threats, wrote "Nothing notable today" for the Education/ASEAN watch even though F2 is a phishing campaign against Malaysian and Indonesian universities (a factual omission the validator can't catch), and gave generic actions ("use antivirus").
- **qwen3.5:4b** covered 5 threats, got the Education/ASEAN watch right, and gave specific actions (block the domain, hunt PowerShell launched from LNK files, patch CVE-2026-21345). Weak spots: it called a phishing-campaign IP "C2" and made an unsupported "increasing" trend claim. Prompt v2 should forbid trend claims that aren't in the data.
- **qwen3.5:9b** had similar quality at roughly twice the time, with most layers on the CPU.

Even 3–4B models don't fit fully in 4 GB VRAM at an 8k context, because the KV cache spills over. Speed doesn't matter much for a 07:00 batch job.

## Decision

- **Default: `qwen3.5:4b`** (`OLLAMA_MODEL`). About 1.5 min per brief, best grounded content.
- **Fallback: `llama3.2:3b`.** Used if the default times out or Ollama lacks it, and for quick local iteration. Still gated by the same validator.
- Keep `temperature ≤ 0.2` (enforced in code), structured output and `think: false`.

## Consequences

- Validator passes measure *faithfulness*, not *completeness*. Phase 5 adds a deterministic completeness check: every top-ranked finding must be cited, and the Education/ASEAN watch must mention any finding tagged with education or ASEAN.
- Re-run `scripts/llm_benchmark.py` whenever the model, prompt or schema changes, and update this ADR.
