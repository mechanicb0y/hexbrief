"""Ollama writer with a mocked Ollama API (no model needed)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from hexbrief.llm.client import OllamaWriter, findings_message, load_schema

CHAT = "http://127.0.0.1:11434/api/chat"
FINDINGS = [{"id": "F1", "title": "x", "cves": ["CVE-2026-20001"], "iocs": [], "note": "drop"}]


@respx.mock
def test_request_is_local_schema_constrained_and_cold() -> None:
    route = respx.post(CHAT).respond(
        200,
        json={
            "message": {"content": json.dumps({"bluf": "ok"})},
            "eval_count": 5,
            "prompt_eval_count": 50,
        },
    )
    with OllamaWriter("llama3.2:3b") as w:
        res = w.write(FINDINGS)
    body = json.loads(route.calls.last.request.content)
    assert body["format"] == load_schema()
    assert body["stream"] is False and body["think"] is False
    assert body["options"]["temperature"] <= 0.2
    assert body["messages"][0]["role"] == "system"
    assert res.parsed == {"bluf": "ok"} and res.output_tokens == 5


@respx.mock
def test_feedback_is_appended_on_retry() -> None:
    route = respx.post(CHAT).respond(200, json={"message": {"content": "{}"}})
    with OllamaWriter("m") as w:
        w.write(FINDINGS, feedback=["mentions ips not in the findings: 192.0.2.1"])
    msgs = json.loads(route.calls.last.request.content)["messages"]
    assert msgs[-1]["role"] == "user" and "192.0.2.1" in msgs[-1]["content"]


@respx.mock
def test_bad_json_and_http_errors_are_reported_not_raised() -> None:
    respx.post(CHAT).respond(200, json={"message": {"content": "not json"}})
    with OllamaWriter("m") as w:
        res = w.write(FINDINGS)
    assert res.parsed is None and "invalid JSON" in (res.error or "")
    respx.post(CHAT).mock(side_effect=httpx.ConnectError("down"))
    with OllamaWriter("m") as w:
        assert w.write(FINDINGS).error


def test_temperature_is_capped() -> None:
    with pytest.raises(ValueError):
        OllamaWriter("m", temperature=0.7)


def test_findings_message_keeps_only_needed_fields() -> None:
    msg = findings_message(FINDINGS)
    assert "CVE-2026-20001" in msg and "drop" not in msg
