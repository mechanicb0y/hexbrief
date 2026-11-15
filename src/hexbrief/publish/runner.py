"""Run every publishing step for one brief; one failing step never blocks the others.

Returns human-readable status lines and records each step in the run log.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from hexbrief.engine import BriefResult

REPO = Path(__file__).resolve().parents[3]
STACK_ENV = REPO / "docker" / "opencti" / ".env.opencti"


def _stack_value(key: str) -> str:
    """Read ONE key from the OpenCTI stack env file (never the whole file into env)."""
    if not STACK_ENV.is_file():
        return ""
    for line in STACK_ENV.read_text(encoding="utf-8").splitlines():
        k, _, v = line.partition("=")
        if k.strip() == key:
            return v.strip()
    return ""


def _bundle(paths: dict[str, Path]) -> dict[str, Any]:
    """Read inside each step, so a missing/bad file fails that step only."""
    return dict(json.loads(paths["stix"].read_text(encoding="utf-8")))


def publish(
    result: BriefResult,
    paths: dict[str, Path],
    *,
    pdf: bool = True,
    push: bool = False,
    pages: bool = False,
    notify: bool = False,
    site: Path | None = None,
) -> list[str]:
    steps: dict[str, Any] = {}
    lines: list[str] = []

    def step(name: str, fn: Any) -> None:
        try:
            detail = fn()
            steps[name] = {"ok": True, "detail": detail}
            lines.append(f"  publish {name:8} ok{f' ({detail})' if detail else ''}")
        except Exception as exc:  # report and continue
            steps[name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}
            lines.append(f"  publish {name:8} FAILED ({type(exc).__name__})")

    if pdf:
        from hexbrief.render.pdf import html_to_pdf

        def do_pdf() -> str:
            paths["pdf"] = html_to_pdf(paths["html"], paths["html"].with_suffix(".pdf"))
            return paths["pdf"].name

        step("pdf", do_pdf)

    if push:
        from hexbrief.publish.stix_push import push_opencti, push_taxii

        step(
            "opencti",
            lambda: push_opencti(
                _bundle(paths),
                os.environ.get("OPENCTI_URL", "http://127.0.0.1:8088"),
                _stack_value("OPENCTI_IMPORTER_TOKEN"),
            ),
        )
        step(
            "taxii",
            lambda: push_taxii(
                _bundle(paths),
                os.environ.get("TAXII_URL", "http://127.0.0.1:5000/taxii2/"),
                os.environ.get("TAXII_USER", ""),
                os.environ.get("TAXII_PASSWORD", ""),
            ).get("status"),
        )

    public = None
    if pages or notify:
        from hexbrief.publish.public import public_view

        public = public_view(result)

    if pages and public is not None:
        from hexbrief.publish.pages import write_brief

        step("pages", lambda: str(write_brief(public, site or REPO / "site").name))

    if notify and public is not None:
        url = os.environ.get("WEBHOOK_URL", "")
        if url:
            from hexbrief.publish.webhook import send

            base = os.environ.get("PAGES_URL", "").rstrip("/")
            link = f"{base}/briefs/{public.day}.html" if base else None
            step("webhook", lambda: send(url, public.day, public.narrative.get("bluf", ""), link))
        else:
            steps["webhook"] = {"ok": True, "detail": "skipped (WEBHOOK_URL not set)"}

    result.run_log["publish"] = steps
    paths["runlog"].write_text(json.dumps(result.run_log, indent=1, default=str), encoding="utf-8")
    return lines
