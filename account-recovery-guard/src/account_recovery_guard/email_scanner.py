from __future__ import annotations

import imaplib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email import message_from_bytes
from email.message import EmailMessage, Message
from email.utils import parsedate_to_datetime, parseaddr
from html import unescape
from typing import Iterable
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .models import CompromisedAccountFinding, Severity

RISK_PATTERNS: tuple[tuple[re.Pattern[str], str, int], ...] = (
    (re.compile(r"\b(password|account)\s+(was\s+)?(changed|reset)", re.I), "password changed/reset", 4),
    (re.compile(r"\bsuspicious\b|\bunauthorized\b|\bnot\s+you\b", re.I), "suspicious activity", 4),
    (re.compile(r"\bnew\s+(sign-?in|login)\b|\baccessed\s+from\b", re.I), "new login/access alert", 3),
    (re.compile(r"\bsecurity\s+alert\b|\baccount\s+alert\b", re.I), "security alert", 3),
    (re.compile(r"\bdata\s+breach\b|\bbreach\b|\bcompromised\b", re.I), "breach/compromise language", 5),
    (re.compile(r"\bverify\s+your\s+identity\b|\bconfirm\s+this\s+was\s+you\b", re.I), "identity confirmation", 2),
)

RESET_LINK_PATTERN = re.compile(
    r"https?://[^\s<>'\"]*(?:reset|recover|password|security|account)[^\s<>'\"]*",
    re.I,
)


@dataclass(frozen=True)
class ImapMailboxConfig:
    host: str
    username: str
    password: str
    port: int = 993
    folder: str = "INBOX"
    days_back: int = 30


class EmailClassifier:
    def classify(self, message: Message) -> CompromisedAccountFinding | None:
        subject = _header(message, "Subject")
        sender = _header(message, "From")
        body = extract_body(message)
        haystack = f"{subject}\n{sender}\n{body}"

        score = 0
        reasons: list[str] = []
        for pattern, reason, weight in RISK_PATTERNS:
            if pattern.search(haystack):
                score += weight
                reasons.append(reason)

        if score < 3:
            return None

        sender_domain = domain_from_sender(sender)
        reset_link = extract_reset_link(body)
        if reset_link:
            score += 1

        return CompromisedAccountFinding(
            service_name=service_name_from_domain(sender_domain),
            sender_domain=sender_domain,
            sender=sender,
            subject=subject,
            timestamp=parse_message_date(_header(message, "Date")),
            severity=severity_for_score(score),
            reasons=reasons,
            reset_link=reset_link,
            message_id=_header(message, "Message-ID") or None,
        )


class ImapEmailScanner:
    def __init__(self, config: ImapMailboxConfig, classifier: EmailClassifier | None = None):
        self.config = config
        self.classifier = classifier or EmailClassifier()

    def scan(self) -> list[CompromisedAccountFinding]:
        messages = self.fetch_messages()
        findings = [finding for message in messages if (finding := self.classifier.classify(message))]
        return sorted(findings, key=lambda item: item.timestamp or datetime.min.replace(tzinfo=UTC), reverse=True)

    def fetch_messages(self) -> list[Message]:
        since = (datetime.now(UTC) - timedelta(days=self.config.days_back)).strftime("%d-%b-%Y")
        messages: list[Message] = []
        with imaplib.IMAP4_SSL(self.config.host, self.config.port, timeout=30) as client:
            client.login(self.config.username, self.config.password)
            client.select(self.config.folder, readonly=True)
            status, data = client.search(None, "SINCE", since)
            if status != "OK":
                raise RuntimeError(f"IMAP search failed with status {status}")
            for message_id in data[0].split():
                status, msg_data = client.fetch(message_id, "(RFC822)")
                if status != "OK":
                    continue
                raw = next((part[1] for part in msg_data if isinstance(part, tuple)), None)
                if not raw:
                    continue
                messages.append(message_from_bytes(raw))
        return messages


def extract_body(message: Message) -> str:
    if message.is_multipart():
        parts: Iterable[Message] = message.walk()
    else:
        parts = (message,)

    text_chunks: list[str] = []
    html_chunks: list[str] = []
    for part in parts:
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        decoded = payload.decode(charset, errors="replace")
        if content_type == "text/plain":
            text_chunks.append(decoded)
        else:
            html_chunks.append(decoded)

    if text_chunks:
        return "\n".join(text_chunks)
    if html_chunks:
        soup = BeautifulSoup("\n".join(html_chunks), "html.parser")
        return unescape(soup.get_text("\n"))
    if isinstance(message, EmailMessage):
        return str(message.get_content())
    return str(message.get_payload())


def extract_reset_link(body: str) -> str | None:
    match = RESET_LINK_PATTERN.search(body)
    return match.group(0).rstrip(").,;") if match else None


def domain_from_sender(sender: str) -> str:
    _, address = parseaddr(sender)
    domain = address.rsplit("@", 1)[-1].lower() if "@" in address else sender.lower()
    return domain.strip("<> ")


def service_name_from_domain(domain: str) -> str:
    pieces = [piece for piece in domain.split(".") if piece and piece not in {"mail", "email", "security", "accounts"}]
    if len(pieces) >= 2:
        return pieces[-2]
    return pieces[0] if pieces else "unknown"


def parse_message_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def severity_for_score(score: int) -> Severity:
    if score >= 13:
        return "critical"
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def _header(message: Message, name: str) -> str:
    value = message.get(name, "")
    return str(value).strip()
