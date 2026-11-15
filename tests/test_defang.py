from __future__ import annotations

import pytest

from hexbrief.model import Ioc
from hexbrief.render.defang import defang_ioc, defang_text


@pytest.mark.parametrize(
    ("ioc", "expected"),
    [
        (Ioc("ipv4", "198.51.100.23"), "198.51.100[.]23"),
        (Ioc("ipv6", "2001:db8::1"), "2001[:]db8[:][:]1"),
        (Ioc("domain", "bad.example.test"), "bad[.]example[.]test"),
        (
            Ioc("url", "https://bad.example.test/a.php?x=1"),
            "hxxps://bad[.]example[.]test/a.php?x=1",
        ),
        (Ioc("url", "http://198.51.100.23:8080/x"), "hxxp://198[.]51[.]100[.]23[:]8080/x"),
        (Ioc("sha256", "ab" * 32), "ab" * 32),
    ],
)
def test_every_ioc_type_is_defanged(ioc: Ioc, expected: str) -> None:
    assert defang_ioc(ioc) == expected


def test_text_is_defanged_once_and_filenames_kept() -> None:
    text = (
        "Block 198.51.100.23 and bad.example.test; payload at http://x.example.test/a.bin, run.exe"
    )
    out = defang_text(text)
    assert "198.51.100[.]23" in out
    assert "bad[.]example[.]test" in out
    assert "hxxp://x[.]example[.]test/a.bin" in out
    assert "run.exe" in out
    assert defang_text(out) == out  # idempotent
    assert "e.g." in defang_text("e.g. this")
