from account_recovery_guard.models import AccountRiskFinding, DiscoveredAccount
from account_recovery_guard.risk import score_account_risk


def test_score_account_risk_combines_breach_and_mail_signals():
    account = DiscoveredAccount("example", "example.com", 3, "high", ["login/security email"])
    finding = AccountRiskFinding(
        service_name="example",
        sender_domain="example.com",
        sender="security@example.com",
        subject="Suspicious login",
        timestamp=None,
        severity="high",
        reasons=["suspicious activity"],
    )

    risk = score_account_risk("me@example.com", account, [finding], ["ExampleBreach"], password_reused=True)

    assert risk.needs_attention is True
    assert risk.score >= 80
    assert "not proof" in risk.interpretation
    assert "compromised" not in risk.interpretation
    assert "known breach: ExampleBreach" in risk.reasons
    assert "password appears reused" in risk.reasons


def test_low_risk_account_interpretation_still_stays_evidence_based():
    account = DiscoveredAccount("example", "example.com", 1, "low", ["welcome email"])

    risk = score_account_risk("me@example.com", account, [], [], password_reused=False, mfa_unknown=False)

    assert risk.needs_attention is False
    assert risk.score == 0
    assert "not proof" in risk.interpretation
    assert "compromised" not in risk.interpretation
