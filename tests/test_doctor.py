from __future__ import annotations

from pathlib import Path

import pytest

from hexbrief.doctor import Check, check_env, parse_env_value, render


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("abc", ("abc", None)),
        ("abc # TODO", ("abc", None)),
        ("abc#def", ("abc#def", None)),
        ('"a # b"', ("a # b", None)),
        ("'x'  # note", ("x", None)),
        ('"abc', (None, "unclosed quote")),  # issue #2
        ("'abc\"", (None, "unclosed quote")),
        ("", ("", None)),
    ],
)
def test_parse_env_value(raw: str, expected: tuple) -> None:
    assert parse_env_value(raw) == expected


def test_check_env_never_shows_values(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "ABUSECH_AUTH_KEY=s3cret-value\nOTX_API_KEY=__replace_me__  # todo\n"
        'OPENCTI_URL="http://127.0.0.1:8088\nOPENCTI_TOKEN=tok\n',
        encoding="utf-8",
    )
    checks = {c.name: c for c in check_env(env)}
    assert checks["env ABUSECH_AUTH_KEY"].status == "ok"
    assert checks["env OTX_API_KEY"].status == "fail"
    assert checks["env OPENCTI_URL"].detail == "unclosed quote"
    assert checks["env MISP_URL"].status == "warn"
    assert all("s3cret" not in c.detail and c.detail != "tok" for c in checks.values())


def test_missing_env_and_exit_code(tmp_path: Path) -> None:
    assert check_env(tmp_path / "nope")[0].status == "fail"
    lines: list[str] = []
    assert render([Check("a", "ok", "x"), Check("b", "warn", "y")], lines.append) == 0
    assert render([Check("c", "fail", "z")], lines.append) == 1
