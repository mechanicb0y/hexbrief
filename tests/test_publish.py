from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx

from hexbrief.engine import run, write_outputs
from hexbrief.publish.pages import write_brief
from hexbrief.publish.public import public_view
from hexbrief.publish.webhook import send
from tests.test_engine import COLLECTORS, NOW, FakeWriter, cluster_finding, good, kev_finding


def _amber_run():
    amber = cluster_finding()
    amber.tlp = "TLP:AMBER"
    amber.confidence = 100
    cols = {"kev": lambda now, h: [kev_finding()], "x": lambda now, h: [amber]}
    return run(cols, now=NOW, writer=FakeWriter([good(["F1", "F2"])]))


def test_public_view_drops_non_clear_and_its_narrative() -> None:
    res = _amber_run()
    assert res.tlp == "TLP:AMBER" and res.llm_ok
    pub = public_view(res)
    assert pub.tlp == "TLP:CLEAR"
    assert all(f.tlp == "TLP:CLEAR" for _, f in pub.top)
    assert not pub.llm_ok  # narrative may have mentioned the AMBER finding
    assert "203.0.113.45" not in json.dumps(pub.narrative)
    assert pub.run_log["public_dropped"] == 1


def test_public_view_keeps_narrative_when_all_clear() -> None:
    res = run(COLLECTORS, now=NOW, writer=FakeWriter([good(["F1", "F2"])]))
    assert public_view(res).narrative == res.narrative


def test_pages_refuses_non_clear_and_writes_index(tmp_path: Path) -> None:
    res = _amber_run()
    with pytest.raises(ValueError, match="non-TLP:CLEAR"):
        write_brief(res, tmp_path)
    page = write_brief(public_view(res), tmp_path)
    assert page.name == f"{res.day}.html"
    index = (tmp_path / "index.html").read_text("utf-8")
    assert f"briefs/{res.day}.html" in index and "TLP:CLEAR" in index
    assert "203.0.113" not in page.read_text("utf-8")


def test_pages_output_is_defanged(tmp_path: Path) -> None:
    res = run(COLLECTORS, now=NOW, writer=FakeWriter([good(["F1", "F2"])]))
    html = write_brief(public_view(res), tmp_path).read_text("utf-8")
    assert "198.51.100[.]23" in html and "198.51.100.23" not in html


@respx.mock
def test_webhook_discord_and_telegram_payloads() -> None:
    d = respx.post("https://discord.com/api/webhooks/1/x").respond(204)
    send("https://discord.com/api/webhooks/1/x", "2026-11-16", "C2 at 198.51.100.23", None)
    body = json.loads(d.calls.last.request.content)
    assert "198.51.100[.]23" in body["content"] and body["allowed_mentions"] == {"parse": []}
    t = respx.post("https://api.telegram.org/botX/sendMessage").respond(200)
    send("https://api.telegram.org/botX/sendMessage", "d", "bluf", "https://x.test/b")
    assert json.loads(t.calls.last.request.content)["disable_web_page_preview"] is True


@respx.mock
def test_webhook_errors_never_echo_the_url() -> None:
    respx.post("https://discord.com/api/webhooks/1/secret").respond(401)
    with pytest.raises(RuntimeError) as err:
        send("https://discord.com/api/webhooks/1/secret", "d", "b")
    assert "secret" not in str(err.value)
    with pytest.raises(ValueError):
        send("https://evil.test/hook", "d", "b")


def test_rendered_ids_are_strict(tmp_path: Path) -> None:
    f = kev_finding()
    f.cves = {"CVE-2026-20001", "CVE-1<script>"}
    f.attack_ids = {"T1059", "T1059](javascript:x)"}
    res = run({"k": lambda now, h: [f]}, now=NOW, writer=None)
    md = write_outputs(res, tmp_path / "o", tmp_path / "r")["md"].read_text("utf-8")
    assert "<script>" not in md and "javascript:" not in md
