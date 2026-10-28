"""Slack/Telegram alerter tests."""

from __future__ import annotations

import httpx
import respx

from coldtrail.alerts import SlackAlerter, TelegramAlerter


@respx.mock
async def test_slack_alerter():
    route = respx.post("https://hooks.slack.test/x").mock(return_value=httpx.Response(200))
    assert await SlackAlerter("https://hooks.slack.test/x").send("title", "body")
    assert route.called


@respx.mock
async def test_telegram_alerter():
    route = respx.post("https://api.telegram.org/bottoken/sendMessage").mock(
        return_value=httpx.Response(200)
    )
    assert await TelegramAlerter("token:123").send("title", "body")
    assert route.called
