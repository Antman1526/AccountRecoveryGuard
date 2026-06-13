from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from .models import CompromisedAccountFinding, PasswordCandidate, RotationChoiceSummary
from .rotation import summarize_rotation_choices


class MailProviderChoice(StrEnum):
    GMAIL = "gmail"
    OUTLOOK = "outlook"
    OTHER_EMAIL = "other_email"


class GuiStep(StrEnum):
    CONNECT_EMAIL = "connect_email"
    SCAN_CONSENT = "scan_consent"
    SCANNING = "scanning"
    RESULTS = "results"
    ACCOUNT_REVIEW = "account_review"
    ROTATION = "rotation"
    DASHBOARD = "dashboard"


@dataclass(frozen=True)
class AccountReview:
    service_name: str
    username: str
    url: str | None = None
    risk_label: str = "Review recommended"
    reasons: tuple[str, ...] = ()
    reset_link: str | None = None

    @classmethod
    def from_finding(cls, finding: CompromisedAccountFinding, username: str) -> "AccountReview":
        return cls(
            service_name=finding.service_name.title(),
            username=username,
            url=f"https://{finding.sender_domain}" if finding.sender_domain else None,
            risk_label=_risk_label(finding.severity),
            reasons=tuple(finding.reasons),
            reset_link=finding.reset_link,
        )

    @classmethod
    def from_finding_stub(cls, service_name: str, username: str) -> "AccountReview":
        return cls(service_name=service_name, username=username)


@dataclass(frozen=True)
class ScanSummary:
    findings: tuple[CompromisedAccountFinding, ...]
    total_accounts_found: int
    accounts_needing_attention: int
    recommended: CompromisedAccountFinding | None

    @classmethod
    def from_findings(cls, findings: list[CompromisedAccountFinding], discovered_count: int) -> "ScanSummary":
        ordered = sorted(findings, key=lambda item: _severity_rank(item.severity), reverse=True)
        return cls(
            findings=tuple(ordered),
            total_accounts_found=discovered_count,
            accounts_needing_attention=len(ordered),
            recommended=ordered[0] if ordered else None,
        )

    @property
    def headline(self) -> str:
        return f"Your scan found {self.total_accounts_found} accounts"

    @property
    def attention_text(self) -> str:
        if self.accounts_needing_attention == 0:
            return "No urgent account alerts were found."
        if self.accounts_needing_attention == 1:
            return "1 account needs attention."
        return f"{self.accounts_needing_attention} accounts need attention."


@dataclass(frozen=True)
class RotationSession:
    account: AccountReview
    choices: list[PasswordCandidate]
    selected_index: int | None = None

    def select_choice(self, index: int) -> "RotationSession":
        if index < 1 or index > len(self.choices):
            raise ValueError("Selected password choice is out of range")
        return replace(self, selected_index=index)

    @property
    def selected_candidate(self) -> PasswordCandidate:
        if self.selected_index is None:
            raise ValueError("No password choice has been selected")
        return self.choices[self.selected_index - 1]

    @property
    def choice_summaries(self) -> list[RotationChoiceSummary]:
        return summarize_rotation_choices([candidate.password for candidate in self.choices])


@dataclass(frozen=True)
class VaultSyncStatus:
    bitwarden: str = "not_configured"
    nordpass: str = "import_needed"
    verification: str = "pending"
    csv_path: str | None = None

    @property
    def primary_message(self) -> str:
        if self.bitwarden == "updated" and self.nordpass == "csv_prepared":
            return "Bitwarden updated. Import the prepared NordPass CSV next."
        if self.bitwarden == "not_configured":
            return "Bitwarden is not configured yet."
        if self.nordpass == "verified" and self.verification == "verified":
            return "Both vaults are verified."
        return "Continue vault sync to keep Bitwarden and NordPass aligned."

    @property
    def requires_csv_cleanup(self) -> bool:
        return self.nordpass in {"csv_prepared", "waiting_for_import", "export_needed"}


@dataclass(frozen=True)
class GuiAppState:
    current_step: GuiStep
    mail_provider: MailProviderChoice | None = None
    scan_started: bool = False
    scan_summary: ScanSummary | None = None
    selected_account: AccountReview | None = None
    rotation_session: RotationSession | None = None
    vault_status: VaultSyncStatus = VaultSyncStatus()

    @classmethod
    def new(cls) -> "GuiAppState":
        return cls(current_step=GuiStep.CONNECT_EMAIL)

    @property
    def dashboard_available(self) -> bool:
        return self.scan_summary is not None

    def with_mail_provider(self, provider: MailProviderChoice) -> "GuiAppState":
        return replace(self, mail_provider=provider, current_step=GuiStep.SCAN_CONSENT, scan_started=False)

    def start_scan(self) -> "GuiAppState":
        return replace(self, current_step=GuiStep.SCANNING, scan_started=True)

    def with_scan_summary(self, summary: ScanSummary) -> "GuiAppState":
        return replace(self, current_step=GuiStep.RESULTS, scan_summary=summary)


def _risk_label(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "Needs attention"
    return "Review recommended"


def _severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity, 0)
