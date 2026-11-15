"""Optional Discord / Telegram notification (off unless WEBHOOK_URL is set).

Sends the public (TLP:CLEAR) BLUF, defanged, plus the archive link. The webhook URL
is a secret (it authorises posting) and is never logged or printed.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from hexbrief.render.defang import defang_text


def message(day: str, bluf: str, link: str | None) -> str:
    text = f"HexBrief {day} (TLP:CLEAR)\n{defang_text(bluf)[:1500]}"
    return text + (f"\n{link}" if link else "")


def send(
    url: str,
    day: str,
    bluf: str,
    link: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> None:
    host = urlsplit(url).hostname or ""
    body = message(day, bluf, link)
    with httpx.Client(timeout=20, trust_env=False, transport=transport) as http:
        if host.endswith(("discord.com", "discordapp.com")):
            r = http.post(url, json={"content": body[:1900], "allowed_mentions": {"parse": []}})
        elif host == "api.telegram.org":
            # WEBHOOK_URL = https://api.telegram.org/bot<token>/sendMessage?chat_id=<id>
            r = http.post(url, json={"text": body[:4000], "disable_web_page_preview": True})
        else:
            raise ValueError("WEBHOOK_URL must be a Discord webhook or Telegram sendMessage URL")
        if r.status_code >= 400:
            raise RuntimeError(f"webhook answered HTTP {r.status_code}")  # no URL in errors
