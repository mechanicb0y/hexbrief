"""The public view of a brief: TLP:CLEAR findings only.

Rule from the master prompt: only TLP:CLEAR goes to the repo, the Pages archive or
LinkedIn. If every top finding is CLEAR, the validated narrative is reused. If any
is not, the narrative might mention it, so the public view drops the narrative and
uses the facts-only text built from the CLEAR findings alone.
"""

from __future__ import annotations

from dataclasses import replace

from hexbrief.engine import BriefResult, facts_only_narrative


def is_clear(tlp: str) -> bool:
    return tlp.upper().replace("TLP:WHITE", "TLP:CLEAR") == "TLP:CLEAR"


def public_view(result: BriefResult) -> BriefResult:
    clear_top = [(fid, f) for fid, f in result.top if is_clear(f.tlp)]
    all_clear = len(clear_top) == len(result.top)
    narrative = result.narrative if all_clear and result.llm_ok else facts_only_narrative(clear_top)
    return replace(
        result,
        tlp="TLP:CLEAR",
        top=clear_top,
        others=[f for f in result.others if is_clear(f.tlp)],
        all_findings=[f for f in result.all_findings if is_clear(f.tlp)],
        narrative=narrative,
        llm_ok=result.llm_ok and all_clear,
        run_log={**result.run_log, "public_dropped": len(result.top) - len(clear_top)},
    )
