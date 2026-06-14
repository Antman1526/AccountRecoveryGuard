from __future__ import annotations

from dataclasses import dataclass, field

from .breach_checker import HibpBreach
from .models import CompromisedAccountFinding, DiscoveredAccount, Severity


SAFE_EXPOSURE_BOUNDARY = (
    "Safe exposure checks use authorized mailbox evidence, reputable breach intelligence, and HIBP "
    "k-anonymous password checks. The app does not crawl paste sites, dark-web sources, criminal forums, "
    "or random web pages for plaintext passwords."
)


@dataclass(frozen=True)
class ExposureRecommendation:
    service_name: str
    sender_domain: str | None
    priority: Severity
    rotate: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ExposureReport:
    email_address: str
    breach_count: int
    email_breach_lookup_status: str
    password_pwned_count: int | None
    recommendations: tuple[ExposureRecommendation, ...]
    safety_boundary: str = SAFE_EXPOSURE_BOUNDARY

    @property
    def rotation_count(self) -> int:
        return sum(1 for recommendation in self.recommendations if recommendation.rotate)


def build_exposure_report(
    email_address: str,
    breaches: list[HibpBreach],
    discovered_accounts: list[DiscoveredAccount],
    findings: list[CompromisedAccountFinding],
    password_pwned_count: int | None = None,
    email_breach_lookup_status: str = "checked",
) -> ExposureReport:
    service_rows: dict[str, dict[str, object]] = {}

    for account in discovered_accounts:
        key = _key(account.service_name)
        row = service_rows.setdefault(
            key,
            {
                "service_name": account.service_name,
                "sender_domain": account.sender_domain,
                "score": _confidence_score(account.confidence),
                "rotate": False,
                "reasons": set(account.reasons),
            },
        )
        row["score"] = max(int(row["score"]), _confidence_score(account.confidence))

    for finding in findings:
        key = _key(finding.service_name)
        row = service_rows.setdefault(
            key,
            {
                "service_name": finding.service_name,
                "sender_domain": finding.sender_domain,
                "score": 0,
                "rotate": False,
                "reasons": set(),
            },
        )
        row["sender_domain"] = row["sender_domain"] or finding.sender_domain
        row["score"] = max(int(row["score"]), _severity_score(finding.severity))
        row["rotate"] = bool(row["rotate"]) or finding.severity in {"high", "critical"}
        reasons = row["reasons"]
        assert isinstance(reasons, set)
        reasons.update(finding.reasons)
        reasons.add(f"mail security signal: {finding.subject}")

    for breach in breaches:
        breach_name = breach.name.strip()
        if not breach_name:
            continue
        matched_key = _match_breach_to_service(breach_name, service_rows)
        if matched_key is None:
            matched_key = _key(breach_name)
            service_rows.setdefault(
                matched_key,
                {
                    "service_name": breach_name,
                    "sender_domain": None,
                    "score": 70,
                    "rotate": True,
                    "reasons": set(),
                },
            )
        row = service_rows[matched_key]
        row["score"] = max(int(row["score"]), 70)
        row["rotate"] = True
        reasons = row["reasons"]
        assert isinstance(reasons, set)
        reasons.add(f"known breach for this email: {breach_name}")

    if password_pwned_count and password_pwned_count > 0:
        for row in service_rows.values():
            row["score"] = max(int(row["score"]), 85)
            row["rotate"] = True
            reasons = row["reasons"]
            assert isinstance(reasons, set)
            reasons.add(
                "checked password appears in breach corpuses; rotate this account if it uses that password"
            )

    recommendations = [
        ExposureRecommendation(
            service_name=str(row["service_name"]),
            sender_domain=str(row["sender_domain"]) if row["sender_domain"] else None,
            priority=_priority_for_score(int(row["score"])),
            rotate=bool(row["rotate"]),
            reasons=tuple(sorted(str(reason) for reason in row["reasons"] if reason)),
        )
        for row in service_rows.values()
    ]
    recommendations.sort(key=lambda item: (_severity_sort(item.priority), item.service_name.casefold()), reverse=True)
    return ExposureReport(
        email_address=email_address,
        breach_count=len(breaches),
        email_breach_lookup_status=email_breach_lookup_status,
        password_pwned_count=password_pwned_count,
        recommendations=tuple(recommendations),
    )


def _key(value: str) -> str:
    return "".join(ch for ch in value.casefold() if ch.isalnum())


def _match_breach_to_service(breach_name: str, service_rows: dict[str, dict[str, object]]) -> str | None:
    breach_key = _key(breach_name)
    for key, row in service_rows.items():
        service_key = _key(str(row["service_name"]))
        domain_key = _key(str(row["sender_domain"] or ""))
        if service_key and (service_key in breach_key or breach_key in service_key):
            return key
        if domain_key and (domain_key in breach_key or breach_key in domain_key):
            return key
    return None


def _confidence_score(confidence: str) -> int:
    return {"high": 35, "medium": 20, "low": 10}.get(confidence, 0)


def _severity_score(severity: Severity) -> int:
    return {"critical": 95, "high": 75, "medium": 45, "low": 20}.get(severity, 0)


def _priority_for_score(score: int) -> Severity:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _severity_sort(severity: Severity) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}[severity]
