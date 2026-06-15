from __future__ import annotations

import re
from collections import defaultdict
from email.message import Message

from .email_scanner import domain_from_sender, extract_body, service_name_from_domain
from .models import DiscoveredAccount

ACCOUNT_SIGNAL_PATTERNS: tuple[tuple[re.Pattern[str], str, int], ...] = (
    (re.compile(r"\bwelcome\b|\bthanks for signing up\b", re.I), "signup/welcome email", 3),
    (re.compile(r"\bverify\b|\bconfirm\b.*\b(account|email)\b", re.I), "account verification email", 3),
    (re.compile(r"\bnew\s+(login|sign-?in)\b|\bsecurity alert\b", re.I), "login/security email", 4),
    (re.compile(r"\bpassword\b|\brecovery\b|\breset\b", re.I), "password/recovery email", 4),
    (re.compile(r"\bmfa\b|\b2fa\b|\btwo[-\s]?factor\b|\bpasskey\b|\bauthenticator\b", re.I), "MFA/passkey account email", 4),
    (re.compile(r"\bsecurity\s+(settings?|preferences?)\b|\baccount\s+settings\b", re.I), "account settings email", 3),
    (re.compile(r"\bsubscription\b|\btrial\b|\bmembership\b|\bplan\b", re.I), "subscription/account email", 2),
    (re.compile(r"\bpayment\b|\bbilling\b|\bstatement\b|\bcharged\b|\brenewal\b", re.I), "billing account email", 2),
    (re.compile(r"\breceipt\b|\binvoice\b|\border\b", re.I), "transactional account email", 2),
)

IGNORED_SERVICE_NAMES = {
    "gmail",
    "googlemail",
    "outlook",
    "hotmail",
    "icloud",
    "yahoo",
    "noise",
}


class AccountDiscovery:
    def discover(self, messages: list[Message]) -> list[DiscoveredAccount]:
        scores: dict[str, int] = defaultdict(int)
        counts: dict[str, int] = defaultdict(int)
        domains: dict[str, str] = {}
        reasons: dict[str, set[str]] = defaultdict(set)

        for message in messages:
            subject = str(message.get("Subject", ""))
            domain = domain_from_sender(str(message.get("From", "")))
            service = service_name_from_domain(domain)
            if service in IGNORED_SERVICE_NAMES or not domain:
                continue
            haystack = f"{subject}\n{extract_body(message)}"
            matched = False
            for pattern, reason, weight in ACCOUNT_SIGNAL_PATTERNS:
                if pattern.search(haystack):
                    scores[service] += weight
                    domains[service] = domain
                    reasons[service].add(reason)
                    matched = True
            if matched:
                counts[service] += 1

        accounts = [
            DiscoveredAccount(
                service_name=service,
                sender_domain=domains[service],
                message_count=counts[service],
                confidence=_confidence(scores[service], counts[service]),
                reasons=sorted(reasons[service]),
            )
            for service in scores
            if scores[service] >= 2
        ]
        return sorted(accounts, key=lambda account: (-account.message_count, account.service_name))


def _confidence(score: int, count: int) -> str:
    if score >= 3 or count >= 2:
        return "high"
    if score >= 2:
        return "medium"
    return "low"
