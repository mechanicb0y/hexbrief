"""Ollama writer: findings in, schema-constrained JSON narrative out.

- Local only: talks to the Ollama HTTP API on 127.0.0.1 (no cloud AI).
- Structured outputs: the JSON schema is passed as ``format``, so decoding is
  constrained to valid JSON of the right shape.
- Low temperature (default 0.1): we want faithful summaries, not creativity.
- "Thinking" models (e.g. qwen3.5) are asked not to think aloud: the schema only
  has room for the brief, and thinking costs minutes on a 4 GB GPU.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from importlib import resources
from typing import Any

import httpx

PROMPT_VERSION = "v1"
DEFAULT_HOST = "http://127.0.0.1:11434"


def load_schema() -> dict[str, Any]:
    return json.loads(resources.files("hexbrief.llm").joinpath("brief.schema.json").read_text())


def load_system_prompt(version: str = PROMPT_VERSION) -> str:
    path = resources.files("hexbrief.llm").joinpath(f"prompts/{version}_system.md")
    return path.read_text(encoding="utf-8")


def findings_message(findings: list[dict[str, Any]]) -> str:
    """Render ranked findings as compact JSON for the user turn.

    Only the fields the model needs; ids are F1..Fn in rank order.
    """
    keep = (
        "id",
        "title",
        "summary",
        "type",
        "sources",
        "first_seen",
        "tlp",
        "confidence",
        "cves",
        "attack_ids",
        "iocs",
        "sectors",
        "countries",
        "in_kev",
    )
    rows = [{k: f[k] for k in keep if k in f and f[k] not in (None, [], "")} for f in findings]
    return (
        "Today's ranked findings (most important first). Write the brief from these only.\n"
        + json.dumps(rows, ensure_ascii=False, indent=1)
    )


@dataclass(frozen=True)
class WriteResult:
    model: str
    raw: str
    parsed: dict[str, Any] | None
    seconds: float
    prompt_tokens: int
    output_tokens: int
    error: str | None = None


class OllamaWriter:
    def __init__(
        self,
        model: str,
        *,
        host: str = DEFAULT_HOST,
        temperature: float = 0.1,
        num_ctx: int = 8192,
        timeout: float = 900,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not 0 <= temperature <= 0.2:
            raise ValueError("temperature must be between 0 and 0.2 for grounded writing")
        self.model = model
        self.temperature = temperature
        self.num_ctx = num_ctx
        self._http = httpx.Client(
            base_url=host, timeout=timeout, trust_env=False, transport=transport
        )
        self.schema = load_schema()
        self.system = load_system_prompt()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> OllamaWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def write(
        self,
        findings: list[dict[str, Any]],
        *,
        feedback: list[str] | None = None,
        previous: str | None = None,
        seed: int = 7,
    ) -> WriteResult:
        """One generation.

        On a retry, ``previous`` is the rejected answer and ``feedback`` the validator's
        errors: the model sees what it wrote and why it was rejected.
        """
        messages = [
            {"role": "system", "content": self.system},
            {"role": "user", "content": findings_message(findings)},
        ]
        if previous:
            messages.append({"role": "assistant", "content": previous})
        if feedback:
            messages.append(
                {
                    "role": "user",
                    "content": "Your previous answer was rejected for these reasons. Fix them and "
                    "answer again, following every rule:\n- " + "\n- ".join(feedback[:15]),
                }
            )
        body = {
            "model": self.model,
            "messages": messages,
            "format": self.schema,
            "stream": False,
            "think": False,
            "options": {"temperature": self.temperature, "num_ctx": self.num_ctx, "seed": seed},
        }
        start = time.perf_counter()
        try:
            r = self._http.post("/api/chat", json=body)
            r.raise_for_status()
            data = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            return WriteResult(
                self.model,
                "",
                None,
                time.perf_counter() - start,
                0,
                0,
                error=f"{type(exc).__name__}: {exc}",
            )
        seconds = time.perf_counter() - start
        raw = str((data.get("message") or {}).get("content") or "")
        try:
            parsed = json.loads(raw)
            err = None if isinstance(parsed, dict) else "output is not a JSON object"
            parsed = parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError as exc:
            parsed, err = None, f"invalid JSON: {exc}"
        return WriteResult(
            self.model,
            raw,
            parsed,
            seconds,
            int(data.get("prompt_eval_count") or 0),
            int(data.get("eval_count") or 0),
            err,
        )
