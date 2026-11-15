"""``hexbrief demo``: a full brief from recorded TLP:CLEAR data.

No API keys, no MISP, no OpenCTI, no Docker; Ollama is optional. The recorded
narrative is run through the *same* faithfulness gate as a live run, so the demo
proves the pipeline, not just the templates.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from importlib import resources
from typing import Any

from hexbrief.engine import BriefResult, finding_from_json, run
from hexbrief.model import Finding


def _demo_file(name: str) -> dict[str, Any] | list[Any] | None:
    path = resources.files("hexbrief.demo").joinpath(name)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def demo_findings() -> tuple[list[Finding], datetime]:
    data = _demo_file("findings.json")
    if not isinstance(data, dict):
        raise RuntimeError("demo fixture missing: hexbrief/demo/findings.json")
    now = datetime.fromisoformat(str(data["meta"]["now"]).replace(" ", "T") + "+08:00")
    return [finding_from_json(d) for d in data["findings"]], now


@dataclass
class _Recorded:
    parsed: dict[str, Any] | None
    raw: str
    seconds: float = 0.0
    output_tokens: int = 0
    error: str | None = None


class RecordedWriter:
    """Replays the narrative recorded with the local model (``scripts/record_demo.py``)."""

    model = "recorded (qwen3.5:4b)"

    def __init__(self) -> None:
        data = _demo_file("narrative.json")
        self.narrative = data if isinstance(data, dict) else None

    def write(self, findings: Any, **_: Any) -> _Recorded:
        if self.narrative is None:
            return _Recorded(None, "", error="no recorded narrative")
        return _Recorded(self.narrative, json.dumps(self.narrative))


def demo_run(writer: Any | None = None) -> BriefResult:
    findings, now = demo_findings()
    return run(
        {"recorded fixture": lambda _now, _h: [f for f in findings]},
        now=now,
        writer=writer or RecordedWriter(),
        max_retries=0 if writer is None else 2,
    )
