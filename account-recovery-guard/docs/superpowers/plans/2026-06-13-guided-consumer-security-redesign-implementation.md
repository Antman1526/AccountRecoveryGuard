# Guided Consumer Security Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the command-preview-first GUI with a calm guided consumer security assistant that connects email, asks for scan consent, summarizes risky accounts, guides password rotation, and explains Bitwarden/NordPass sync status.

**Architecture:** Keep the existing CLI/service modules as the lower-level execution layer. Add a focused GUI state/view-model layer and a PySide6 wizard/dashboard shell that calls those services without exposing commands in the primary path. Keep network and vault operations behind injectable facades so tests can use fakes.

**Tech Stack:** Python 3.11+, PySide6, pytest, existing `account_recovery_guard` modules (`oauth_mail`, `email_scanner`, `account_discovery`, `rotation`, `vaults`, `sync`, `secure_files`, `paths`), PyInstaller packaging scripts.

---

## File Structure

Create:

- `src/account_recovery_guard/gui_state.py` — dataclasses/enums for onboarding, scan, account review, rotation, and vault sync state.
- `src/account_recovery_guard/gui_services.py` — GUI-safe service facade over mail scanning, account discovery, rotation, and vault sync actions.
- `src/account_recovery_guard/gui_components.py` — reusable PySide6 widgets for cards, provider buttons, status pills, step headers, and password choices.
- `src/account_recovery_guard/gui_theme.py` — shared stylesheet and color tokens for the Calm Shield direction.
- `src/account_recovery_guard/gui_workers.py` — small `QThread`/worker helpers for running scan operations without freezing the UI.
- `tests/test_gui_state.py` — state transition and summary tests.
- `tests/test_gui_services.py` — fake-provider tests for scan summaries, rotation sessions, and vault status copy.
- `tests/test_gui_components.py` — import/smoke tests for reusable components when PySide6 is available.

Modify:

- `src/account_recovery_guard/gui.py` — replace current tab/dashboard-first implementation with first-run wizard, post-scan dashboard, scan results, rotation/sync screen, and advanced area.
- `src/account_recovery_guard/gui_workflow.py` — keep command helpers for advanced area and add plain-language recovery-stage copy used by the dashboard.
- `packaging/account_recovery_guard_entry.py` — keep current GUI entry import and verify it still launches `account_recovery_guard.gui:main`.
- `scripts/build_macos_dmg.sh` — add native DMG Applications shortcut and preserve README.
- `scripts/build_windows_exe.ps1` — keep EXE build; add release note file only if artifact workflow already uploads it.
- `README.md` — update GUI usage to describe the guided app flow.
- `.github/workflows/build-account-recovery-guard.yml` — add `README-Windows.txt` to the Windows artifact upload paths.

---

## Task 1: Add GUI State Model

**Files:**
- Create: `src/account_recovery_guard/gui_state.py`
- Create: `tests/test_gui_state.py`

- [ ] **Step 1: Write failing state tests**

Create `tests/test_gui_state.py`:

```python
from datetime import UTC, datetime

from account_recovery_guard.gui_state import (
    AccountReview,
    GuiAppState,
    MailProviderChoice,
    RotationSession,
    ScanSummary,
    VaultSyncStatus,
)
from account_recovery_guard.models import CompromisedAccountFinding, PasswordCandidate


def test_new_app_starts_in_email_connection_step():
    state = GuiAppState.new()

    assert state.current_step == "connect_email"
    assert state.mail_provider is None
    assert state.scan_summary is None
    assert state.dashboard_available is False


def test_provider_selection_moves_to_consent_without_scanning():
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL)

    assert state.current_step == "scan_consent"
    assert state.mail_provider == MailProviderChoice.GMAIL
    assert state.scan_started is False


def test_scan_summary_recommends_highest_risk_finding():
    finding = CompromisedAccountFinding(
        service_name="Dropbox",
        sender_domain="dropbox.com",
        sender="security@dropbox.com",
        subject="Suspicious login",
        timestamp=datetime(2026, 6, 13, tzinfo=UTC),
        severity="high",
        reasons=["suspicious activity", "new login/access alert"],
        reset_link="https://dropbox.com/reset",
        message_id="message-1",
    )
    summary = ScanSummary.from_findings([finding], discovered_count=12)

    assert summary.total_accounts_found == 12
    assert summary.accounts_needing_attention == 1
    assert summary.recommended.service_name == "Dropbox"
    assert summary.headline == "Your scan found 12 accounts"


def test_rotation_session_selects_one_password_without_revealing_all():
    candidates = [
        PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Aa1!" * 8, "note"),
        PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Bb2@" * 8, "note"),
    ]
    session = RotationSession(account=AccountReview.from_finding_stub("Dropbox", "me@example.com"), choices=candidates)

    selected = session.select_choice(2)

    assert selected.selected_index == 2
    assert selected.selected_candidate.password == "Bb2@" * 8
    assert all("Bb2@" not in row.display for row in selected.choice_summaries)


def test_vault_sync_status_guides_nordpass_import_honestly():
    status = VaultSyncStatus(bitwarden="updated", nordpass="csv_prepared", verification="pending")

    assert status.primary_message == "Bitwarden updated. Import the prepared NordPass CSV next."
    assert status.requires_csv_cleanup is True
```

- [ ] **Step 2: Run state tests and verify failure**

Run:

```bash
pytest tests/test_gui_state.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'account_recovery_guard.gui_state'`.

- [ ] **Step 3: Implement minimal state model**

Create `src/account_recovery_guard/gui_state.py`:

```python
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
```

- [ ] **Step 4: Run state tests and verify pass**

Run:

```bash
pytest tests/test_gui_state.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit state model**

```bash
git add src/account_recovery_guard/gui_state.py tests/test_gui_state.py
git commit -m "feat: add guided GUI state model"
```

---

## Task 2: Add GUI Service Facade

**Files:**
- Create: `src/account_recovery_guard/gui_services.py`
- Create: `tests/test_gui_services.py`

- [ ] **Step 1: Write failing service tests**

Create `tests/test_gui_services.py`:

```python
from email.message import EmailMessage

from account_recovery_guard.gui_services import GuiScanService, GuiRotationService, describe_provider_setup
from account_recovery_guard.gui_state import MailProviderChoice


class FakeMailProvider:
    def fetch_messages(self, days_back: int = 30):
        message = EmailMessage()
        message["Subject"] = "Suspicious login detected"
        message["From"] = "Dropbox Security <security@dropbox.com>"
        message["Date"] = "Sat, 13 Jun 2026 12:00:00 +0000"
        message.set_content("We noticed a suspicious login. Reset your password at https://dropbox.com/reset")
        return [message]


def test_describe_provider_setup_keeps_gmail_plain_language():
    setup = describe_provider_setup(MailProviderChoice.GMAIL)

    assert setup.title == "Continue with Gmail"
    assert "OAuth" not in setup.description
    assert setup.advanced is False


def test_describe_provider_setup_marks_other_email_advanced():
    setup = describe_provider_setup(MailProviderChoice.OTHER_EMAIL)

    assert setup.title == "Other email"
    assert setup.advanced is True
    assert "IMAP" in setup.technical_details


def test_scan_service_returns_guided_summary_from_provider_messages():
    service = GuiScanService(provider=FakeMailProvider())

    summary = service.scan(days_back=30)

    assert summary.accounts_needing_attention == 1
    assert summary.recommended is not None
    assert summary.recommended.service_name == "dropbox"
    assert summary.total_accounts_found >= 1


def test_rotation_service_builds_five_choices_for_account():
    rotation = GuiRotationService().start("Dropbox", "me@example.com", "https://dropbox.com")

    assert len(rotation.choices) == 5
    assert rotation.selected_index is None
    assert {choice.password for choice in rotation.choices}
```

- [ ] **Step 2: Run service tests and verify failure**

Run:

```bash
pytest tests/test_gui_services.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'account_recovery_guard.gui_services'`.

- [ ] **Step 3: Implement GUI service facade**

Create `src/account_recovery_guard/gui_services.py`:

```python
from __future__ import annotations

from dataclasses import dataclass

from .account_discovery import AccountDiscovery
from .email_scanner import EmailClassifier
from .gui_state import AccountReview, MailProviderChoice, RotationSession, ScanSummary, VaultSyncStatus
from .models import PasswordCandidate
from .oauth_mail import MailProvider
from .rotation import build_rotation_choices
from .vaults import BitwardenVault, NordPassImportVault, VaultError


@dataclass(frozen=True)
class ProviderSetupCopy:
    title: str
    description: str
    advanced: bool
    technical_details: str = ""


def describe_provider_setup(provider: MailProviderChoice) -> ProviderSetupCopy:
    if provider == MailProviderChoice.GMAIL:
        return ProviderSetupCopy(
            title="Continue with Gmail",
            description="Connect Gmail so Account Recovery Guard can scan account and security emails.",
            advanced=False,
        )
    if provider == MailProviderChoice.OUTLOOK:
        return ProviderSetupCopy(
            title="Continue with Outlook",
            description="Connect Outlook so Account Recovery Guard can scan account and security emails.",
            advanced=False,
        )
    return ProviderSetupCopy(
        title="Other email",
        description="Use this when your mailbox is not Gmail or Outlook.",
        advanced=True,
        technical_details="Advanced setup uses IMAP host, username, and an app password stored in the OS credential store.",
    )


class GuiScanService:
    def __init__(
        self,
        provider: MailProvider,
        classifier: EmailClassifier | None = None,
        discovery: AccountDiscovery | None = None,
    ) -> None:
        self.provider = provider
        self.classifier = classifier or EmailClassifier()
        self.discovery = discovery or AccountDiscovery()

    def scan(self, days_back: int = 30) -> ScanSummary:
        messages = self.provider.fetch_messages(days_back=days_back)
        findings = [finding for message in messages if (finding := self.classifier.classify(message))]
        accounts = self.discovery.discover(messages)
        discovered_count = max(len(accounts), len(findings))
        return ScanSummary.from_findings(findings, discovered_count=discovered_count)


class GuiRotationService:
    def start(self, service_name: str, username: str, url: str | None = None) -> RotationSession:
        account = AccountReview.from_finding_stub(service_name, username)
        return RotationSession(account=account, choices=build_rotation_choices(service_name, username, url))


class GuiVaultService:
    def __init__(
        self,
        bitwarden: BitwardenVault | None = None,
        nordpass: NordPassImportVault | None = None,
    ) -> None:
        self.bitwarden = bitwarden
        self.nordpass = nordpass or NordPassImportVault()

    def describe_preflight(self) -> VaultSyncStatus:
        if self.bitwarden is None:
            return VaultSyncStatus(bitwarden="not_configured", nordpass="import_needed", verification="pending")
        return VaultSyncStatus(bitwarden="connected", nordpass="import_needed", verification="pending")

    def write_bitwarden(self, candidate: PasswordCandidate) -> VaultSyncStatus:
        if self.bitwarden is None:
            return VaultSyncStatus(bitwarden="not_configured", nordpass="import_needed", verification="pending")
        try:
            self.bitwarden.upsert_login(candidate)
        except VaultError:
            return VaultSyncStatus(bitwarden="verification_failed", nordpass="import_needed", verification="pending")
        return VaultSyncStatus(bitwarden="updated", nordpass="import_needed", verification="pending")
```

- [ ] **Step 4: Run service tests and verify pass**

Run:

```bash
pytest tests/test_gui_services.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit service facade**

```bash
git add src/account_recovery_guard/gui_services.py tests/test_gui_services.py
git commit -m "feat: add GUI service facade"
```

---

## Task 3: Extract Theme and Reusable Components

**Files:**
- Create: `src/account_recovery_guard/gui_theme.py`
- Create: `src/account_recovery_guard/gui_components.py`
- Create: `tests/test_gui_components.py`
- Modify: `src/account_recovery_guard/gui.py`

- [ ] **Step 1: Write component smoke tests**

Create `tests/test_gui_components.py`:

```python
import os

import pytest

pytest.importorskip("PySide6")

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from account_recovery_guard.gui_components import ProviderButton, StepHeader, StatusPill
from account_recovery_guard.gui_theme import calm_shield_stylesheet


@pytest.fixture(scope="module")
def app():
    existing = QApplication.instance()
    return existing or QApplication([])


def test_theme_contains_primary_action_color():
    css = calm_shield_stylesheet()

    assert "#155f57" in css
    assert "primaryButton" in css


def test_step_header_renders_title_and_subtitle(app):
    header = StepHeader("Connect email safely", "We scan account and security emails locally.")

    assert header.title.text() == "Connect email safely"
    assert "locally" in header.subtitle.text()


def test_provider_button_has_accessible_label(app):
    button = ProviderButton("Continue with Gmail", "Recommended for Gmail accounts")

    assert button.text() == "Continue with Gmail"
    assert "Gmail" in button.toolTip()


def test_status_pill_exposes_status_text(app):
    pill = StatusPill("Needs attention", "attention")

    assert pill.text() == "Needs attention"
    assert pill.property("tone") == "attention"
```

- [ ] **Step 2: Run component tests and verify failure**

Run:

```bash
pytest tests/test_gui_components.py -q
```

Expected: FAIL with missing `gui_components` and `gui_theme` modules.

- [ ] **Step 3: Add Calm Shield theme**

Create `src/account_recovery_guard/gui_theme.py`:

```python
from __future__ import annotations


def calm_shield_stylesheet() -> str:
    return """
    QMainWindow, QWidget {
        background: #f4faf8;
        color: #173630;
        font-family: Arial;
        font-size: 14px;
    }
    QLabel#pageTitle {
        font-size: 30px;
        font-weight: 800;
        color: #15352f;
    }
    QLabel#pageSubtitle {
        color: #58716d;
        line-height: 1.4;
    }
    QFrame#card, QFrame#panel {
        background: #ffffff;
        border: 1px solid #dce9e5;
        border-radius: 16px;
    }
    QPushButton#primaryButton {
        background: #155f57;
        color: #ffffff;
        border: 1px solid #155f57;
        border-radius: 10px;
        padding: 11px 14px;
        font-weight: 800;
    }
    QPushButton#primaryButton:hover {
        background: #0f4d49;
    }
    QPushButton#secondaryButton {
        background: #ffffff;
        color: #155f57;
        border: 1px solid #aac8c2;
        border-radius: 10px;
        padding: 10px 14px;
        font-weight: 800;
    }
    QPushButton#providerButton {
        background: #ffffff;
        color: #15352f;
        border: 1px solid #cfe1dc;
        border-radius: 12px;
        padding: 13px 16px;
        font-weight: 800;
        text-align: left;
    }
    QLabel#statusPill[tone="attention"] {
        background: #fff1ed;
        color: #a23a2f;
        border: 1px solid #f4cbc3;
        border-radius: 999px;
        padding: 5px 10px;
        font-size: 12px;
        font-weight: 800;
    }
    QLabel#statusPill[tone="safe"] {
        background: #e4f4ef;
        color: #155f57;
        border: 1px solid #bfe1d8;
        border-radius: 999px;
        padding: 5px 10px;
        font-size: 12px;
        font-weight: 800;
    }
    """
```

- [ ] **Step 4: Add reusable PySide components**

Create `src/account_recovery_guard/gui_components.py`:

```python
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget


class StepHeader(QWidget):
    def __init__(self, title: str, subtitle: str, step_label: str | None = None) -> None:
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        text_col = QVBoxLayout()
        self.title = QLabel(title)
        self.title.setObjectName("pageTitle")
        self.title.setWordWrap(True)
        self.subtitle = QLabel(subtitle)
        self.subtitle.setObjectName("pageSubtitle")
        self.subtitle.setWordWrap(True)
        text_col.addWidget(self.title)
        text_col.addWidget(self.subtitle)
        layout.addLayout(text_col, 1)
        if step_label:
            pill = StatusPill(step_label, "safe")
            layout.addWidget(pill, alignment=Qt.AlignmentFlag.AlignTop)


class ProviderButton(QPushButton):
    def __init__(self, label: str, helper_text: str) -> None:
        super().__init__(label)
        self.setObjectName("providerButton")
        self.setToolTip(helper_text)
        self.setCursor(Qt.CursorShape.PointingHandCursor)


class StatusPill(QLabel):
    def __init__(self, text: str, tone: str = "safe") -> None:
        super().__init__(text)
        self.setObjectName("statusPill")
        self.setProperty("tone", tone)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)


class Card(QFrame):
    def __init__(self, title: str | None = None) -> None:
        super().__init__()
        self.setObjectName("card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(18, 16, 18, 16)
        self.body.setSpacing(10)
        if title:
            label = QLabel(title)
            label.setObjectName("sectionTitle")
            self.body.addWidget(label)
```

- [ ] **Step 5: Run component tests and verify pass**

Run:

```bash
pytest tests/test_gui_components.py -q
```

Expected: PASS, or SKIP only if PySide6 is not installed in the active environment.

- [ ] **Step 6: Update GUI to use theme**

In `src/account_recovery_guard/gui.py`, replace the inline `app.setStyleSheet("""...""")` block with:

```python
from .gui_theme import calm_shield_stylesheet

# inside main(), after QApplication is created:
app.setStyleSheet(calm_shield_stylesheet())
```

- [ ] **Step 7: Run GUI workflow and component tests**

Run:

```bash
pytest tests/test_gui_workflow.py tests/test_gui_components.py -q
```

Expected: PASS.

- [ ] **Step 8: Commit theme/components**

```bash
git add src/account_recovery_guard/gui_theme.py src/account_recovery_guard/gui_components.py src/account_recovery_guard/gui.py tests/test_gui_components.py
git commit -m "feat: add Calm Shield GUI components"
```

---

## Task 4: Implement First-Run Wizard and Consent Screens

**Files:**
- Modify: `src/account_recovery_guard/gui.py`
- Modify: `src/account_recovery_guard/gui_state.py`
- Modify: `tests/test_gui_state.py`

- [ ] **Step 1: Add state tests for consent gating**

Append to `tests/test_gui_state.py`:

```python
def test_scan_cannot_start_without_provider_selection():
    state = GuiAppState.new()

    try:
        state.start_scan()
    except ValueError as exc:
        assert "mail provider" in str(exc)
    else:
        raise AssertionError("Expected scan start to require a mail provider")


def test_consent_copy_explains_local_scan_boundaries():
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.OUTLOOK)

    assert "what we scan" in state.consent_summary.lower()
    assert "never log" in state.consent_summary.lower()
    assert "local" in state.consent_summary.lower()
```

- [ ] **Step 2: Run state tests and verify failure**

Run:

```bash
pytest tests/test_gui_state.py -q
```

Expected: FAIL because `start_scan()` does not guard provider selection and `consent_summary` does not exist.

- [ ] **Step 3: Add consent behavior to state model**

Modify `GuiAppState.start_scan()` and add `consent_summary`:

```python
    @property
    def consent_summary(self) -> str:
        return (
            "What we scan: security alerts, login warnings, password reset messages, and account messages. "
            "What we never log: plaintext passwords, OAuth tokens, full email contents, or private keys. "
            "Scan classification and generated recovery data stay local on this device."
        )

    def start_scan(self) -> "GuiAppState":
        if self.mail_provider is None:
            raise ValueError("A mail provider must be selected before scanning")
        return replace(self, current_step=GuiStep.SCANNING, scan_started=True)
```

- [ ] **Step 4: Replace first GUI page with wizard**

In `src/account_recovery_guard/gui.py`, restructure `MainWindow.__init__` so a new user sees a `QStackedWidget` with:

```python
self.state = GuiAppState.new()
self.stack.addWidget(self._connect_email_page())
self.stack.addWidget(self._scan_consent_page())
self.stack.addWidget(self._scan_progress_page())
self.stack.addWidget(self._results_page())
self.stack.addWidget(self._rotation_page())
self.stack.addWidget(self._dashboard_page())
```

Add imports:

```python
from .gui_components import Card, ProviderButton, StepHeader, StatusPill
from .gui_state import GuiAppState, GuiStep, MailProviderChoice
from .gui_services import describe_provider_setup
```

Implement `_connect_email_page()` with provider buttons:

```python
def _connect_email_page(self) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(42, 36, 42, 36)
    layout.setSpacing(18)
    layout.addWidget(StepHeader(
        "Connect email safely",
        "We scan account and security emails to find websites tied to you and identify accounts that may need attention.",
        "Step 1 of 3",
    ))
    trust = Card("Before you connect")
    for line in (
        "What we scan: security alerts, login warnings, password reset messages, and account messages.",
        "What we never log: plaintext passwords, OAuth tokens, full email contents, or private keys.",
        "What stays local: scan classification, generated passwords, staged vault data, and audit logs.",
    ):
        label = QLabel(line)
        label.setWordWrap(True)
        trust.body.addWidget(label)
    layout.addWidget(trust)
    for provider in (MailProviderChoice.GMAIL, MailProviderChoice.OUTLOOK, MailProviderChoice.OTHER_EMAIL):
        setup = describe_provider_setup(provider)
        button = ProviderButton(setup.title, setup.description)
        button.clicked.connect(lambda checked=False, selected=provider: self._select_provider(selected))
        layout.addWidget(button)
    layout.addStretch(1)
    return page
```

Implement `_select_provider()`:

```python
def _select_provider(self, provider: MailProviderChoice) -> None:
    self.state = self.state.with_mail_provider(provider)
    self.stack.setCurrentIndex(1)
```

Implement `_scan_consent_page()`:

```python
def _scan_consent_page(self) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(42, 36, 42, 36)
    layout.setSpacing(18)
    layout.addWidget(StepHeader("Review scan consent", "You control when scanning starts.", "Step 2 of 3"))
    card = Card("What happens next")
    summary = QLabel(GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL).consent_summary)
    summary.setWordWrap(True)
    card.body.addWidget(summary)
    layout.addWidget(card)
    actions = QHBoxLayout()
    back = QPushButton("Back")
    back.setObjectName("secondaryButton")
    back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
    start = QPushButton("Start scan")
    start.setObjectName("primaryButton")
    start.clicked.connect(self._start_scan_from_consent)
    actions.addWidget(back)
    actions.addWidget(start)
    actions.addStretch(1)
    layout.addLayout(actions)
    layout.addStretch(1)
    return page
```

Implement `_start_scan_from_consent()`:

```python
def _start_scan_from_consent(self) -> None:
    self.state = self.state.start_scan()
    self.stack.setCurrentIndex(2)
```

- [ ] **Step 5: Run tests**

Run:

```bash
pytest tests/test_gui_state.py tests/test_gui_workflow.py -q
```

Expected: PASS.

- [ ] **Step 6: Run GUI offscreen smoke test**

Run:

```bash
QT_QPA_PLATFORM=offscreen python - <<'PY'
from PySide6.QtWidgets import QApplication
from account_recovery_guard import gui

original_exec = QApplication.exec
QApplication.exec = lambda self: 0
try:
    raise SystemExit(gui.main())
finally:
    QApplication.exec = original_exec
PY
```

Expected: exit code 0.

- [ ] **Step 7: Commit first-run wizard**

```bash
git add src/account_recovery_guard/gui.py src/account_recovery_guard/gui_state.py tests/test_gui_state.py
git commit -m "feat: add guided email connection wizard"
```

---

## Task 5: Add Background Scan Worker and Guided Results

**Files:**
- Create: `src/account_recovery_guard/gui_workers.py`
- Modify: `src/account_recovery_guard/gui.py`
- Modify: `tests/test_gui_services.py`

- [ ] **Step 1: Add progress-stage test**

Append to `tests/test_gui_services.py`:

```python
from account_recovery_guard.gui_services import scan_progress_stages


def test_scan_progress_stages_are_plain_language():
    stages = scan_progress_stages()

    assert stages == [
        "Connecting to mailbox",
        "Reading recent account and security messages",
        "Finding websites tied to this email",
        "Looking for risk signals",
        "Preparing recommendations",
    ]
    assert all("IMAP" not in stage and "OAuth" not in stage for stage in stages)
```

- [ ] **Step 2: Run service tests and verify failure**

Run:

```bash
pytest tests/test_gui_services.py -q
```

Expected: FAIL because `scan_progress_stages` does not exist.

- [ ] **Step 3: Add progress-stage helper**

Append to `src/account_recovery_guard/gui_services.py`:

```python
def scan_progress_stages() -> list[str]:
    return [
        "Connecting to mailbox",
        "Reading recent account and security messages",
        "Finding websites tied to this email",
        "Looking for risk signals",
        "Preparing recommendations",
    ]
```

- [ ] **Step 4: Add scan worker**

Create `src/account_recovery_guard/gui_workers.py`:

```python
from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from .gui_services import GuiScanService, scan_progress_stages
from .gui_state import ScanSummary


class ScanWorker(QObject):
    progress = Signal(str)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, service: GuiScanService, days_back: int = 30) -> None:
        super().__init__()
        self.service = service
        self.days_back = days_back

    @Slot()
    def run(self) -> None:
        try:
            for stage in scan_progress_stages():
                self.progress.emit(stage)
            summary: ScanSummary = self.service.scan(days_back=self.days_back)
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.finished.emit(summary)
```

- [ ] **Step 5: Add scan progress and results pages**

In `src/account_recovery_guard/gui.py`, implement:

```python
def _scan_progress_page(self) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(42, 36, 42, 36)
    layout.setSpacing(18)
    layout.addWidget(StepHeader("Looking for account and security emails", "This can take a few minutes.", "Scanning"))
    self.scan_stage_label = QLabel("Ready to scan")
    self.scan_stage_label.setObjectName("pageSubtitle")
    layout.addWidget(self.scan_stage_label)
    layout.addStretch(1)
    return page

def _results_page(self) -> QWidget:
    page = QWidget()
    self.results_layout = QVBoxLayout(page)
    self.results_layout.setContentsMargins(42, 36, 42, 36)
    self.results_layout.setSpacing(18)
    self._render_empty_results()
    return page
```

Add:

```python
def _render_results(self) -> None:
    self._clear_layout(self.results_layout)
    summary = self.state.scan_summary
    if summary is None:
        self._render_empty_results()
        return
    self.results_layout.addWidget(StepHeader(summary.headline, summary.attention_text, "Step 3 of 3"))
    if summary.recommended:
        account = AccountReview.from_finding(summary.recommended, "you@example.com")
        card = Card(f"Start with {account.service_name}")
        reason = QLabel(", ".join(account.reasons) or "Review recommended")
        reason.setWordWrap(True)
        card.body.addWidget(StatusPill(account.risk_label, "attention"))
        card.body.addWidget(reason)
        button = QPushButton("Review account")
        button.setObjectName("primaryButton")
        button.clicked.connect(lambda: self._open_rotation_for_account(account))
        card.body.addWidget(button)
        self.results_layout.addWidget(card)
    view_all = QPushButton("View all accounts")
    view_all.setObjectName("secondaryButton")
    self.results_layout.addWidget(view_all)
    self.results_layout.addStretch(1)

def _render_empty_results(self) -> None:
    self.results_layout.addWidget(StepHeader("Scan results will appear here", "Start a scan to review account safety.", "Results"))

def _clear_layout(self, layout: QVBoxLayout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()
```

For this task, wire `_start_scan_from_consent()` to use a fake-safe empty summary if real provider construction is not complete:

```python
def _start_scan_from_consent(self) -> None:
    self.state = self.state.start_scan()
    self.stack.setCurrentIndex(2)
    self.scan_stage_label.setText("Preparing recommendations")
    self.state = self.state.with_scan_summary(ScanSummary.from_findings([], discovered_count=0))
    self._render_results()
    self.stack.setCurrentIndex(3)
```

Real provider construction is completed in Task 6.

- [ ] **Step 6: Run tests**

Run:

```bash
pytest tests/test_gui_services.py tests/test_gui_state.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit scan worker/results scaffold**

```bash
git add src/account_recovery_guard/gui_workers.py src/account_recovery_guard/gui.py src/account_recovery_guard/gui_services.py tests/test_gui_services.py
git commit -m "feat: add guided scan progress and results"
```

---

## Task 6: Wire Real Gmail, Outlook, and Advanced IMAP Provider Setup

**Files:**
- Modify: `src/account_recovery_guard/gui_services.py`
- Modify: `src/account_recovery_guard/gui.py`
- Modify: `tests/test_gui_services.py`

- [ ] **Step 1: Add provider factory tests**

Append to `tests/test_gui_services.py`:

```python
from account_recovery_guard.gui_services import MailProviderSettings, build_provider_or_error


def test_gmail_provider_factory_explains_missing_client_secret():
    settings = MailProviderSettings(provider=MailProviderChoice.GMAIL)

    provider, error = build_provider_or_error(settings)

    assert provider is None
    assert error is not None
    assert "Gmail setup file" in error.user_message
    assert "client_secret_file" in error.technical_details


def test_outlook_provider_factory_explains_missing_client_id():
    settings = MailProviderSettings(provider=MailProviderChoice.OUTLOOK)

    provider, error = build_provider_or_error(settings)

    assert provider is None
    assert error is not None
    assert "Outlook setup" in error.user_message
    assert "client_id" in error.technical_details
```

- [ ] **Step 2: Run factory tests and verify failure**

Run:

```bash
pytest tests/test_gui_services.py -q
```

Expected: FAIL because `MailProviderSettings` and `build_provider_or_error` do not exist.

- [ ] **Step 3: Implement provider settings and factory**

Append to `src/account_recovery_guard/gui_services.py`:

```python
from pathlib import Path

from .email_scanner import ImapEmailScanner, ImapMailboxConfig
from .oauth_mail import GmailApiMailProvider, GmailOAuthConfig, MicrosoftGraphMailProvider, GraphOAuthConfig
from .secure_store import get_secret


@dataclass(frozen=True)
class UserFacingSetupError:
    user_message: str
    technical_details: str


@dataclass(frozen=True)
class MailProviderSettings:
    provider: MailProviderChoice
    username: str = ""
    days_back: int = 30
    gmail_client_secret_file: str = ""
    graph_tenant_id: str = "common"
    graph_client_id: str = ""
    imap_host: str = ""
    imap_secret_name: str = ""


def build_provider_or_error(settings: MailProviderSettings) -> tuple[MailProvider | None, UserFacingSetupError | None]:
    if settings.provider == MailProviderChoice.GMAIL:
        if not settings.gmail_client_secret_file or not Path(settings.gmail_client_secret_file).exists():
            return None, UserFacingSetupError(
                "Gmail setup file is missing. Add the setup file in Advanced setup, then try again.",
                "Missing gmail_client_secret_file for GmailApiMailProvider.",
            )
        return GmailApiMailProvider(GmailOAuthConfig(settings.gmail_client_secret_file)), None
    if settings.provider == MailProviderChoice.OUTLOOK:
        if not settings.graph_client_id:
            return None, UserFacingSetupError(
                "Outlook setup is missing. Add the Outlook application ID in Advanced setup, then try again.",
                "Missing client_id for MicrosoftGraphMailProvider.",
            )
        return MicrosoftGraphMailProvider(GraphOAuthConfig(settings.graph_tenant_id, settings.graph_client_id)), None
    password = get_secret(settings.imap_secret_name) if settings.imap_secret_name else None
    if not settings.imap_host or not settings.username or not password:
        return None, UserFacingSetupError(
            "Other email setup is incomplete. Add host, username, and saved app password.",
            "Missing imap_host, username, or password secret for ImapEmailScanner.",
        )
    return ImapEmailScanner(ImapMailboxConfig(settings.imap_host, settings.username, password, days_back=settings.days_back)), None
```

- [ ] **Step 4: Update GUI consent start to use provider factory**

In `src/account_recovery_guard/gui.py`, store settings fields for advanced setup. In `_start_scan_from_consent()`:

```python
settings = MailProviderSettings(provider=self.state.mail_provider or MailProviderChoice.GMAIL)
provider, error = build_provider_or_error(settings)
if error:
    self._show_user_error(error.user_message, error.technical_details)
    return
service = GuiScanService(provider)
```

Add a simple `_show_user_error()`:

```python
def _show_user_error(self, message: str, technical_details: str) -> None:
    self.scan_stage_label.setText(message if hasattr(self, "scan_stage_label") else "")
    print(f"Technical details: {technical_details}", file=sys.stderr)
```

Then create and start `ScanWorker` with a `QThread` in a follow-up step after the factory tests pass.

- [ ] **Step 5: Run tests**

Run:

```bash
pytest tests/test_gui_services.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit provider factory**

```bash
git add src/account_recovery_guard/gui_services.py src/account_recovery_guard/gui.py tests/test_gui_services.py
git commit -m "feat: add guided mail provider setup"
```

---

## Task 7: Implement Calm Shield Rotation and Vault Sync Panel

**Files:**
- Modify: `src/account_recovery_guard/gui.py`
- Modify: `src/account_recovery_guard/gui_state.py`
- Modify: `tests/test_gui_state.py`

- [ ] **Step 1: Add rotation state tests**

Append to `tests/test_gui_state.py`:

```python
def test_vault_status_after_csv_prepared_warns_about_cleanup_path():
    status = VaultSyncStatus(bitwarden="updated", nordpass="csv_prepared", verification="pending", csv_path="/tmp/nordpass.csv")

    assert status.requires_csv_cleanup is True
    assert "/tmp/nordpass.csv" in status.cleanup_message
```

- [ ] **Step 2: Run state tests and verify failure**

Run:

```bash
pytest tests/test_gui_state.py -q
```

Expected: FAIL because `cleanup_message` does not exist.

- [ ] **Step 3: Add cleanup message**

In `VaultSyncStatus`, add:

```python
    @property
    def cleanup_message(self) -> str:
        if not self.csv_path:
            return "Delete staged NordPass CSV files after import."
        return f"Delete staged NordPass CSV after import: {self.csv_path}"
```

- [ ] **Step 4: Replace rotation page with Calm Shield panel**

In `src/account_recovery_guard/gui.py`, implement `_open_rotation_for_account(account: AccountReview)`:

```python
def _open_rotation_for_account(self, account: AccountReview) -> None:
    service = GuiRotationService()
    self.state = replace(self.state, selected_account=account, rotation_session=service.start(account.service_name, account.username, account.url), current_step=GuiStep.ROTATION)
    self._render_rotation_panel()
    self.stack.setCurrentIndex(4)
```

Import `replace` from `dataclasses`.

Implement `_render_rotation_panel()` with:

```python
def _render_rotation_panel(self) -> None:
    self._clear_layout(self.rotation_layout)
    session = self.state.rotation_session
    if session is None:
        self.rotation_layout.addWidget(StepHeader("No account selected", "Return to scan results to choose an account.", "Rotation"))
        return
    self.rotation_layout.addWidget(StepHeader(f"Rotate {session.account.service_name} password", "Choose one generated password, complete the reset, then verify both vaults.", "Secure account"))
    panel = Card("Choose one password")
    for summary in session.choice_summaries:
        button = QPushButton(f"Choice {summary.index}: {summary.display}    {summary.length} chars")
        button.setObjectName("secondaryButton")
        button.clicked.connect(lambda checked=False, index=summary.index: self._select_password_choice(index))
        panel.body.addWidget(button)
    self.rotation_layout.addWidget(panel)
    self.rotation_status_label = QLabel(self.state.vault_status.primary_message)
    self.rotation_status_label.setWordWrap(True)
    self.rotation_layout.addWidget(self.rotation_status_label)
    actions = QHBoxLayout()
    copy_button = QPushButton("Copy selected password")
    copy_button.setObjectName("primaryButton")
    copy_button.clicked.connect(self._copy_selected_rotation_password)
    reveal_button = QPushButton("Reveal selected")
    reveal_button.setObjectName("secondaryButton")
    reveal_button.clicked.connect(self._reveal_selected_rotation_password)
    actions.addWidget(copy_button)
    actions.addWidget(reveal_button)
    actions.addStretch(1)
    self.rotation_layout.addLayout(actions)
```

Add `_select_password_choice`, `_copy_selected_rotation_password`, `_reveal_selected_rotation_password`:

```python
def _select_password_choice(self, index: int) -> None:
    if self.state.rotation_session is None:
        return
    self.state = replace(self.state, rotation_session=self.state.rotation_session.select_choice(index))
    self._render_rotation_panel()

def _copy_selected_rotation_password(self) -> None:
    if self.state.rotation_session is None:
        return
    copied = copy_text(self.state.rotation_session.selected_candidate.password, clear_after_seconds=60)
    self.rotation_status_label.setText("Selected password copied. The clipboard clear timer is set for 60 seconds." if copied else "Clipboard copy is unavailable.")

def _reveal_selected_rotation_password(self) -> None:
    if self.state.rotation_session is None:
        return
    self.rotation_status_label.setText(self.state.rotation_session.selected_candidate.password)
```

- [ ] **Step 5: Add rotation page layout target**

Modify `_rotation_page()` to set `self.rotation_layout`:

```python
def _rotation_page(self) -> QWidget:
    page = QWidget()
    self.rotation_layout = QVBoxLayout(page)
    self.rotation_layout.setContentsMargins(42, 36, 42, 36)
    self.rotation_layout.setSpacing(18)
    self.rotation_layout.addWidget(StepHeader("Select an account to secure", "Scan results will recommend where to start.", "Rotation"))
    self.rotation_layout.addStretch(1)
    return page
```

- [ ] **Step 6: Run tests**

Run:

```bash
pytest tests/test_gui_state.py tests/test_rotation_safety.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit rotation panel**

```bash
git add src/account_recovery_guard/gui.py src/account_recovery_guard/gui_state.py tests/test_gui_state.py
git commit -m "feat: add guided rotation and vault sync panel"
```

---

## Task 8: Add Post-Onboarding Dashboard and Advanced Tools Area

**Files:**
- Modify: `src/account_recovery_guard/gui.py`
- Modify: `README.md`

- [ ] **Step 1: Add README expectation for dashboard**

Modify `README.md` GUI section to include:

```markdown
The desktop app opens with a guided first-run flow:

1. Connect Gmail or Outlook.
2. Review scan consent.
3. Review recommended accounts.
4. Rotate passwords and sync vaults.

After a scan exists, the app shows a dashboard with account safety summary, accounts needing attention, vault sync status, and advanced tools.
```

- [ ] **Step 2: Implement dashboard page**

In `src/account_recovery_guard/gui.py`, implement `_dashboard_page()`:

```python
def _dashboard_page(self) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(42, 36, 42, 36)
    layout.setSpacing(18)
    layout.addWidget(StepHeader("Account safety dashboard", "Review account risk, vault sync, and cleanup tasks.", "Dashboard"))
    summary_card = Card("Current status")
    self.dashboard_summary_label = QLabel("Connect email and run a scan to begin.")
    self.dashboard_summary_label.setWordWrap(True)
    summary_card.body.addWidget(self.dashboard_summary_label)
    layout.addWidget(summary_card)
    actions = QHBoxLayout()
    scan = QPushButton("Scan email")
    scan.setObjectName("primaryButton")
    scan.clicked.connect(lambda: self.stack.setCurrentIndex(0))
    verify = QPushButton("Verify vault sync")
    verify.setObjectName("secondaryButton")
    verify.clicked.connect(lambda: self.stack.setCurrentIndex(4))
    actions.addWidget(scan)
    actions.addWidget(verify)
    actions.addStretch(1)
    layout.addLayout(actions)
    layout.addStretch(1)
    return page
```

Add `_refresh_dashboard()`:

```python
def _refresh_dashboard(self) -> None:
    if not hasattr(self, "dashboard_summary_label"):
        return
    summary = self.state.scan_summary
    if summary is None:
        self.dashboard_summary_label.setText("Connect email and run a scan to begin.")
        return
    self.dashboard_summary_label.setText(f"{summary.headline}. {summary.attention_text}")
```

Call `_refresh_dashboard()` after scan summary is rendered.

- [ ] **Step 3: Add advanced tools disclosure page or button**

Add a secondary button in dashboard:

```python
advanced = QPushButton("Advanced tools")
advanced.setObjectName("secondaryButton")
advanced.clicked.connect(self._show_advanced_tools)
actions.addWidget(advanced)
```

Implement `_show_advanced_tools()` as a non-primary page or message panel:

```python
def _show_advanced_tools(self) -> None:
    self.dashboard_summary_label.setText(
        "Advanced tools include IMAP setup, CLI-equivalent commands, export/import utilities, and logs. "
        "These are available for troubleshooting and should not be needed for the normal guided flow."
    )
```

- [ ] **Step 4: Run tests**

Run:

```bash
pytest -q
```

Expected: PASS.

- [ ] **Step 5: Commit dashboard**

```bash
git add src/account_recovery_guard/gui.py README.md
git commit -m "feat: add post-scan dashboard"
```

---

## Task 9: Improve Native Packaging

**Files:**
- Modify: `scripts/build_macos_dmg.sh`
- Modify: `scripts/build_windows_exe.ps1`
- Modify: `README.md`

- [ ] **Step 1: Update macOS DMG script**

In `scripts/build_macos_dmg.sh`, after copying `AccountRecoveryGuard.app` into `$DMG_ROOT`, add an Applications symlink:

```bash
ln -s /Applications "$DMG_ROOT/Applications"
```

Ensure the script remains:

```bash
cp README.md "$DMG_ROOT/README.md"
```

- [ ] **Step 2: Add Windows release note artifact**

In `scripts/build_windows_exe.ps1`, after checksum generation, add:

```powershell
$ReleaseNote = @"
Account Recovery Guard for Windows

This build opens the guided desktop app. Windows may ask you to confirm the app until it is signed with an Authenticode certificate.
"@
$ReleaseNote | Out-File -Encoding utf8 dist\README-Windows.txt
```

- [ ] **Step 3: Update workflow artifact path**

In `.github/workflows/build-account-recovery-guard.yml`, add `dist/README-Windows.txt` to the Windows artifact upload paths.

Use:

```yaml
path: |
  account-recovery-guard/dist/AccountRecoveryGuard.exe
  account-recovery-guard/dist/AccountRecoveryGuard.exe.sha256
  account-recovery-guard/dist/README-Windows.txt
```

- [ ] **Step 4: Run macOS package build**

Run:

```bash
./scripts/build_macos_dmg.sh
```

Expected:

- `dist/AccountRecoveryGuard-macOS.dmg` exists.
- `dist/AccountRecoveryGuard-macOS.dmg.sha256` exists.
- DMG root includes `Applications` symlink before image creation.

- [ ] **Step 5: Verify macOS DMG**

Run:

```bash
hdiutil verify dist/AccountRecoveryGuard-macOS.dmg
cd dist && shasum -a 256 -c AccountRecoveryGuard-macOS.dmg.sha256
```

Expected: both commands pass.

- [ ] **Step 6: Commit packaging**

```bash
git add scripts/build_macos_dmg.sh scripts/build_windows_exe.ps1 README.md .github/workflows/build-account-recovery-guard.yml
git commit -m "chore: improve native package artifacts"
```

---

## Task 10: Final Verification and Release Artifacts

**Files:**
- Verify: no source file changes are expected in this task.
- Modify: files from earlier tasks only when a listed verification command fails and the failure identifies a concrete defect.

- [ ] **Step 1: Run full tests**

Run:

```bash
pytest -q
```

Expected: all tests pass.

- [ ] **Step 2: Run GUI offscreen smoke test**

Run:

```bash
QT_QPA_PLATFORM=offscreen python - <<'PY'
from PySide6.QtWidgets import QApplication
from account_recovery_guard import gui

original_exec = QApplication.exec
QApplication.exec = lambda self: 0
try:
    raise SystemExit(gui.main())
finally:
    QApplication.exec = original_exec
PY
```

Expected: exit code 0 when PySide6 is installed.

- [ ] **Step 3: Build macOS DMG**

Run:

```bash
./scripts/build_macos_dmg.sh
```

Expected:

- `dist/AccountRecoveryGuard-macOS.dmg`
- `dist/AccountRecoveryGuard-macOS.dmg.sha256`

- [ ] **Step 4: Trigger GitHub build for Windows EXE**

After pushing all implementation commits:

```bash
gh run list -R Antman1526/AccountRecoveryGuard --workflow build-account-recovery-guard.yml --limit 1
```

Expected: latest run for the pushed commit appears.

Watch it:

```bash
gh run watch <run-id> -R Antman1526/AccountRecoveryGuard --exit-status
```

Expected: test, macOS DMG, and Windows EXE jobs pass.

- [ ] **Step 5: Download artifacts**

Run:

```bash
rm -rf dist/github-artifacts-guided-redesign
mkdir -p dist/github-artifacts-guided-redesign
gh run download <run-id> -R Antman1526/AccountRecoveryGuard -D dist/github-artifacts-guided-redesign
```

Expected:

- `dist/github-artifacts-guided-redesign/AccountRecoveryGuard-macOS-dmg/AccountRecoveryGuard-macOS.dmg`
- `dist/github-artifacts-guided-redesign/AccountRecoveryGuard-Windows-exe/AccountRecoveryGuard.exe`

- [ ] **Step 6: Verify downloaded checksums**

Run:

```bash
cd dist/github-artifacts-guided-redesign/AccountRecoveryGuard-macOS-dmg
shasum -a 256 -c AccountRecoveryGuard-macOS.dmg.sha256
cd ../AccountRecoveryGuard-Windows-exe
actual=$(shasum -a 256 AccountRecoveryGuard.exe | awk '{print $1}')
expected=$(tr -d '\r' < AccountRecoveryGuard.exe.sha256 | awk '{print $1}')
test "$actual" = "$expected"
```

Expected: macOS checksum says OK; Windows hash comparison exits 0.

- [ ] **Step 7: Final commit if verification changes were needed**

If any verification fixes changed files:

```bash
git status --short
git add <changed-files>
git commit -m "fix: stabilize guided redesign packaging"
git push origin main
```

Expected: no uncommitted source changes remain after final verification.

---

## Self-Review Notes

Spec coverage:

- First-run onboarding wizard: Task 4.
- Gmail/Outlook primary connection paths and Other Email advanced path: Task 6.
- Consent before scanning: Task 4.
- Scan progress and guided results summary: Task 5.
- Account review and password rotation: Task 7.
- Five password choices: Task 7 using existing `build_rotation_choices`.
- Bitwarden/NordPass status and honest limitations: Task 7 and Task 8.
- Sync verification and CSV cleanup guidance: Task 7 and Task 8.
- Native macOS/Windows packaging: Task 9.
- Final artifacts: Task 10.

Known trade-off:

- The first implementation keeps provider setup lightweight and may still require advanced configuration files for Gmail/Outlook OAuth. The main path hides that complexity until needed and explains missing setup in plain language.
