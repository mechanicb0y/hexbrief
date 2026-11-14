"""summarize_attack(): offline tests on a small hand-written ATT&CK fixture."""

from __future__ import annotations

from typing import Any

from hexbrief.stixkit.bundle import AttackSummary, summarize_attack


def _obj(kind: str, n: int, **extra: Any) -> dict[str, Any]:
    return {
        "type": kind,
        "id": f"{kind}--00000000-0000-4000-8000-{n:012d}",
        "modified": "2026-01-01T00:00:00.000Z",
        **extra,
    }


FIXTURE = [
    _obj("attack-pattern", 1),  # technique (flag absent)
    _obj("attack-pattern", 2, x_mitre_is_subtechnique=False),  # technique
    _obj("attack-pattern", 3, x_mitre_is_subtechnique=True),  # sub-technique
    _obj("attack-pattern", 4, revoked=True),  # skipped
    _obj("attack-pattern", 5, x_mitre_is_subtechnique=True, x_mitre_deprecated=True),  # skipped
    _obj("x-mitre-tactic", 6),
    _obj("x-mitre-tactic", 7),
    _obj("intrusion-set", 8),  # group
    _obj("intrusion-set", 9, revoked=True),  # skipped
    _obj("malware", 10),  # software
    _obj("tool", 11),  # software
    _obj("tool", 12, x_mitre_deprecated=True),  # skipped
    _obj("relationship", 13),  # not counted
    _obj("x-mitre-matrix", 14),  # not counted
    _obj("course-of-action", 15, revoked=True),  # not counted, and not "skipped" either
]


def test_counts_each_category() -> None:
    assert summarize_attack(FIXTURE) == AttackSummary(
        techniques=2, subtechniques=1, tactics=2, groups=1, software=2, skipped=4
    )


def test_empty_input() -> None:
    assert summarize_attack([]) == AttackSummary()


def test_false_flags_are_not_skipped() -> None:
    obj = _obj("intrusion-set", 1, revoked=False, x_mitre_deprecated=False)
    assert summarize_attack([obj]) == AttackSummary(groups=1)


def test_newest_version_wins_in_any_order() -> None:
    old = _obj("intrusion-set", 1)
    new = {**old, "modified": "2026-06-01T00:00:00.000Z", "revoked": True}
    assert summarize_attack([old, new]) == AttackSummary(skipped=1)
    assert summarize_attack([new, old]) == AttackSummary(skipped=1)


def test_same_object_twice_is_counted_once() -> None:
    obj = _obj("malware", 1)
    assert summarize_attack([obj, dict(obj)]) == AttackSummary(software=1)


def test_objects_without_id_are_ignored() -> None:
    assert summarize_attack([{"type": "tool"}]) == AttackSummary()


def test_accepts_a_generator_and_as_dict() -> None:
    summary = summarize_attack(o for o in FIXTURE)
    assert summary.as_dict() == {
        "techniques": 2,
        "subtechniques": 1,
        "tactics": 2,
        "groups": 1,
        "software": 2,
        "skipped": 4,
    }
