from __future__ import annotations

from dataclasses import dataclass, field, replace
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
class ChecklistItem:
    title: str
    status: str
    detail: str
    tone: str = "safe"


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

    def account_reviews(self, username: str, limit: int | None = None) -> tuple[AccountReview, ...]:
        findings = self.findings[:limit] if limit is not None else self.findings
        return tuple(AccountReview.from_finding(finding, username) for finding in findings)

    @property
    def next_safest_action(self) -> str:
        if self.recommended is None:
            return "No urgent alerts were found. Review vault sync and keep monitoring this mailbox."
        service_name = self.recommended.service_name.title()
        if self.recommended.severity in {"critical", "high"}:
            return f"Start with {service_name}. Review the alert, confirm the site, then rotate only that account first."
        return f"Review {service_name} first, then rotate only if the alert matches activity you do not recognize."


@dataclass(frozen=True)
class RotationSession:
    account: AccountReview
    choices: tuple[PasswordCandidate, ...] | list[PasswordCandidate] = field(repr=False)
    selected_index: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "choices", tuple(self.choices))

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

    @property
    def cleanup_message(self) -> str:
        if not self.csv_path:
            return "Delete staged NordPass CSV files after import."
        return f"Delete staged NordPass CSV after import: {self.csv_path}"


@dataclass(frozen=True)
class GuiAppState:
    current_step: GuiStep
    protected_person_label: str = "Me"
    mail_provider: MailProviderChoice | None = None
    scan_started: bool = False
    scan_summary: ScanSummary | None = None
    selected_account: AccountReview | None = None
    rotation_session: RotationSession | None = field(default=None, repr=False)
    vault_status: VaultSyncStatus = VaultSyncStatus()
    password_exposure_count: int | None = None

    @classmethod
    def new(cls) -> "GuiAppState":
        return cls(current_step=GuiStep.CONNECT_EMAIL)

    @property
    def dashboard_available(self) -> bool:
        return self.scan_summary is not None

    def with_mail_provider(self, provider: MailProviderChoice) -> "GuiAppState":
        return replace(self, mail_provider=provider, current_step=GuiStep.SCAN_CONSENT, scan_started=False)

    def with_protected_person(self, label: str) -> "GuiAppState":
        return replace(self, protected_person_label=_normalize_person_label(label))

    @property
    def protected_person_prefix(self) -> str:
        return f"{self.protected_person_label}: "

    @property
    def first_run_checklist(self) -> tuple[ChecklistItem, ...]:
        email_ready = self.mail_provider is not None
        scan_ready = self.scan_summary is not None
        account_ready = self.selected_account is not None or (
            self.scan_summary is not None and self.scan_summary.accounts_needing_attention == 0
        )
        vault_ready = self.vault_status.verification == "verified"
        return (
            ChecklistItem(
                "Connect email",
                "done" if email_ready else "next",
                "Choose Gmail, Outlook, or Other Email so the app can scan authorized mailbox evidence.",
                "safe" if email_ready else "attention",
            ),
            ChecklistItem(
                "Run local scan",
                "done" if scan_ready else ("next" if email_ready else "waiting"),
                "Find security alerts and account signals without crawling unsafe password dumps.",
                "safe" if scan_ready else ("attention" if email_ready else "safe"),
            ),
            ChecklistItem(
                "Review one account",
                "done" if account_ready else ("next" if scan_ready else "waiting"),
                "Start with the highest-risk account and rotate one account at a time.",
                "safe" if account_ready else ("attention" if scan_ready else "safe"),
            ),
            ChecklistItem(
                "Check password exposure",
                "done" if self.password_exposure_count is not None else "available",
                _password_exposure_checklist_detail(self.password_exposure_count),
                "attention" if self.password_exposure_count and self.password_exposure_count > 0 else "safe",
            ),
            ChecklistItem(
                "Sync vaults",
                "done" if vault_ready else ("next" if self.rotation_session is not None else "waiting"),
                "Update Bitwarden, import the staged NordPass CSV, then verify both vaults match.",
                "safe" if vault_ready else ("attention" if self.rotation_session is not None else "safe"),
            ),
        )

    @property
    def consent_summary(self) -> str:
        return (
            "What we scan: account, login, password reset, and security alert emails that help identify websites tied "
            "to you and accounts that may need attention.\n\n"
            "What we protect: we never log plaintext passwords, OAuth tokens, full email contents, or private keys.\n\n"
            "What stays local: classification results and generated recovery data stay on this computer unless you "
            "choose to export them."
        )

    def start_scan(self) -> "GuiAppState":
        if self.mail_provider is None:
            raise ValueError("Choose a mail provider before starting the scan")
        return replace(self, current_step=GuiStep.SCANNING, scan_started=True)

    def with_scan_summary(self, summary: ScanSummary) -> "GuiAppState":
        return replace(self, current_step=GuiStep.RESULTS, scan_summary=summary)

    def complete_placeholder_scan(self) -> "GuiAppState":
        return self.with_scan_summary(ScanSummary.from_findings([], discovered_count=0))

    def show_results(self) -> "GuiAppState":
        if self.scan_summary is None:
            raise ValueError("A scan summary is required before returning to results")
        return replace(self, current_step=GuiStep.RESULTS)

    def show_account_review(self, account: AccountReview) -> "GuiAppState":
        if self.scan_summary is None:
            raise ValueError("Review scan results before opening an account review")
        return replace(self, current_step=GuiStep.ACCOUNT_REVIEW, selected_account=account)

    def start_guided_rotation(self, account: AccountReview, session: RotationSession) -> "GuiAppState":
        if self.scan_summary is None:
            raise ValueError("Review scan results before opening password rotation")
        return replace(self, current_step=GuiStep.ROTATION, selected_account=account, rotation_session=session)

    def show_guided_rotation_placeholder(self) -> "GuiAppState":
        if self.scan_summary is None:
            raise ValueError("Review scan results before opening password guidance")
        return replace(self, current_step=GuiStep.ROTATION, selected_account=None, rotation_session=None)

    def show_dashboard(self) -> "GuiAppState":
        if self.scan_summary is None:
            raise ValueError("A scan summary is required before opening the dashboard")
        return replace(self, current_step=GuiStep.DASHBOARD)

    def with_password_exposure_count(self, count: int) -> "GuiAppState":
        return replace(self, password_exposure_count=max(count, 0))


def _risk_label(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "Needs attention"
    return "Review recommended"


def _severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity, 0)


def _normalize_person_label(label: str) -> str:
    normalized = " ".join(label.strip().split())
    if not normalized:
        return "Me"
    return normalized[:40]


def _password_exposure_checklist_detail(count: int | None) -> str:
    if count is None:
        return "Use the free HIBP k-anonymous password check only for a password you type into the masked field."
    if count > 0:
        return "The checked password appears in breach corpuses. Rotate any account where you used it."
    return "The checked password was not found in HIBP Pwned Passwords."
