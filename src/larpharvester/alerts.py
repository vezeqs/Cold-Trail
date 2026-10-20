from __future__ import annotations

import asyncio
import os
import smtplib
from email.message import EmailMessage

import httpx


class Alerter:
    name = "base"

    async def send(self, title: str, body: str) -> bool:
        raise NotImplementedError


class WebhookAlerter(Alerter):
    name = "webhook"

    def __init__(self, url: str) -> None:
        self.url = url

    async def send(self, title: str, body: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(self.url, json={"title": title, "body": body})
            return response.status_code < 400
        except httpx.HTTPError:
            return False


class DiscordAlerter(Alerter):
    name = "discord"

    def __init__(self, url: str) -> None:
        self.url = url

    async def send(self, title: str, body: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    self.url, json={"content": f"**{title}**\n{body[:1800]}"}
                )
            return response.status_code < 400
        except httpx.HTTPError:
            return False


class NtfyAlerter(Alerter):
    name = "ntfy"

    def __init__(self, topic: str) -> None:
        self.url = topic if topic.startswith("http") else f"https://ntfy.sh/{topic}"

    async def send(self, title: str, body: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    self.url,
                    content=body.encode(),
                    headers={"Title": title, "Tags": "mag"},
                )
            return response.status_code < 400
        except httpx.HTTPError:
            return False


class SmtpAlerter(Alerter):
    name = "smtp"

    def __init__(self, target: str) -> None:
        self.target = target

    async def send(self, title: str, body: str) -> bool:
        return await asyncio.to_thread(self._send_sync, title, body)

    def _send_sync(self, title: str, body: str) -> bool:
        host = os.environ.get("LARPHARVESTER_SMTP_HOST")
        sender = os.environ.get("LARPHARVESTER_SMTP_FROM")
        if not host or not sender:
            return False
        message = EmailMessage()
        message["Subject"] = title
        message["From"] = sender
        message["To"] = self.target
        message.set_content(body)
        port = int(os.environ.get("LARPHARVESTER_SMTP_PORT", "587"))
        try:
            with smtplib.SMTP(host, port, timeout=15) as smtp:
                smtp.starttls()
                user = os.environ.get("LARPHARVESTER_SMTP_USER")
                password = os.environ.get("LARPHARVESTER_SMTP_PASS")
                if user and password:
                    smtp.login(user, password)
                smtp.send_message(message)
            return True
        except (OSError, smtplib.SMTPException):
            return False


def build_alerters(kind: str, target: str) -> list[Alerter]:
    if kind == "webhook":
        return [WebhookAlerter(target)]
    if kind == "discord":
        return [DiscordAlerter(target)]
    if kind == "ntfy":
        return [NtfyAlerter(target)]
    if kind == "smtp":
        return [SmtpAlerter(target)]
    return []


async def dispatch(alerters: list[Alerter], title: str, body: str) -> list[str]:
    if not alerters:
        return []
    results = await asyncio.gather(*(alerter.send(title, body) for alerter in alerters))
    return [alerter.name for alerter, ok in zip(alerters, results, strict=True) if ok]
