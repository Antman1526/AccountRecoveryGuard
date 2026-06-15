from __future__ import annotations

from .models import AccountRisk, AccountRiskFinding, DiscoveredAccount

SEVERITY_POINTS = {
    "low": 10,
    "medium": 25,
    "high": 45,
    "critical": 70,
}


def score_account_risk(
    email_address: str,
    account: DiscoveredAccount,
    findings: list[AccountRiskFinding],
    breach_names: list[str] | None = None,
    password_reused: bool = False,
    mfa_unknown: bool = True,
) -> AccountRisk:
    score = 0
    reasons: list[str] = []
    breach_names = breach_names or []

    if account.confidence == "high":
        score += 10
    elif account.confidence == "medium":
        score += 5

    for finding in findings:
        if finding.service_name != account.service_name:
            continue
        score += SEVERITY_POINTS.get(finding.severity, 0)
        reasons.extend(finding.reasons)

    for breach in breach_names:
        score += 35
        reasons.append(f"known breach: {breach}")

    if password_reused:
        score += 25
        reasons.append("password appears reused")
    if mfa_unknown:
        score += 5
        reasons.append("MFA status unknown")

    score = min(score, 100)
    needs_attention = score >= 70 or bool(breach_names)
    interpretation = (
        "Risk signals need review; this score is not proof of account takeover."
        if needs_attention
        else "No urgent risk signal was found; this score is not proof that the account is safe."
    )
    return AccountRisk(
        email_address=email_address,
        service_name=account.service_name,
        sender_domain=account.sender_domain,
        needs_attention=needs_attention,
        score=score,
        interpretation=interpretation,
        reasons=sorted(set(reasons)),
        breach_names=breach_names,
    )
