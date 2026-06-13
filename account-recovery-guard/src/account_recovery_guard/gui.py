from __future__ import annotations

import sys
import webbrowser
from pathlib import Path

from .clipboard import copy_text
from .gui_workflow import build_command_preview, recovery_stages, suggested_next_actions
from .gui_theme import calm_shield_stylesheet
from .passkeys import passkey_guidance
from .paths import user_state_dir
from .rotation import build_rotation_choices, summarize_rotation_choices
from .secure_files import plaintext_file_warning


def main() -> int:
    try:
        from PySide6.QtCore import Qt, QThread, QTimer, Slot
        from PySide6.QtGui import QFont
        from PySide6.QtWidgets import (
            QApplication,
            QButtonGroup,
            QCheckBox,
            QComboBox,
            QFrame,
            QGridLayout,
            QGroupBox,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QListWidget,
            QMainWindow,
            QPushButton,
            QScrollArea,
            QSizePolicy,
            QSpinBox,
            QStackedWidget,
            QTextEdit,
            QVBoxLayout,
            QWidget,
        )
    except ImportError:
        print("PySide6 is not installed. Install GUI dependencies with: python -m pip install '.[gui]'", file=sys.stderr)
        return 2

    from .gui_components import Card, ProviderButton, StepHeader, StatusPill
    from .gui_services import (
        GuiScanService,
        GuiRotationService,
        MailProviderSettings,
        SETUP_DETAIL_MISSING_PROVIDER,
        SETUP_DETAIL_MISSING_PROVIDER_INSTANCE,
        SETUP_DETAIL_SCAN_FAILED,
        build_provider_or_error,
        controlled_setup_detail_for_log,
        describe_provider_setup,
        scan_progress_stages,
    )
    from .gui_state import AccountReview, GuiAppState, MailProviderChoice, ScanSummary
    from .gui_workers import ScanWorker

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.state = GuiAppState.new()
            self._scan_worker = None
            self._scan_thread = None
            self.setWindowTitle("Account Recovery Guard")
            self.resize(1180, 760)
            self.setMinimumSize(980, 660)

            root = QWidget()
            root_layout = QVBoxLayout(root)
            root_layout.setContentsMargins(0, 0, 0, 0)
            root_layout.setSpacing(0)

            self.stack = QStackedWidget()
            self.nav_group = QButtonGroup(self)
            self.nav_group.setExclusive(True)
            root_layout.addWidget(self.stack, 1)
            self.setCentralWidget(root)

            self.stack.addWidget(self._connect_email_page())
            self.stack.addWidget(self._scan_consent_page())
            self.stack.addWidget(self._scan_progress_page())
            self.stack.addWidget(self._results_page())
            self.stack.addWidget(self._guided_rotation_placeholder_page())
            self.stack.addWidget(self._dashboard_page())
            self.stack.setCurrentIndex(0)

        def _wizard_page(self) -> tuple[QScrollArea, QVBoxLayout]:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(42, 36, 42, 42)
            layout.setSpacing(18)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            scroll.setWidget(page)
            scroll.setObjectName("pageScroll")
            return scroll, layout

        def _body_label(self, text: str, object_name: str = "cardText") -> QLabel:
            label = QLabel(text)
            label.setObjectName(object_name)
            label.setWordWrap(True)
            return label

        def _connect_email_page(self) -> QScrollArea:
            page, layout = self._wizard_page()
            layout.addWidget(
                StepHeader(
                    "Connect email safely",
                    "Scan account and security emails to find websites tied to you and accounts that may need attention.",
                    "Step 1 of 3",
                )
            )

            trust = Card("Before you connect")
            for line in (
                "We scan account, login, password reset, and security alert emails.",
                "We never log plaintext passwords, OAuth tokens, full email contents, or private keys.",
                "Classification results and generated recovery data stay local unless you export them.",
            ):
                trust.body.addWidget(self._body_label(line, "listText"))
            layout.addWidget(trust)

            providers = Card("Choose your mail provider")
            for provider in (MailProviderChoice.GMAIL, MailProviderChoice.OUTLOOK, MailProviderChoice.OTHER_EMAIL):
                setup = describe_provider_setup(provider)
                button = ProviderButton(setup.title, setup.description)
                button.clicked.connect(lambda checked=False, selected=provider: self._select_provider(selected))
                providers.body.addWidget(button)
                description = setup.description
                if setup.technical_details:
                    description = f"{description} {setup.technical_details}"
                providers.body.addWidget(self._body_label(description))
            layout.addWidget(providers)
            layout.addStretch(1)
            return page

        def _select_provider(self, provider: MailProviderChoice) -> None:
            self.state = self.state.with_mail_provider(provider)
            self.stack.setCurrentIndex(1)

        def _scan_consent_page(self) -> QScrollArea:
            page, layout = self._wizard_page()
            layout.addWidget(
                StepHeader(
                    "Review scan consent",
                    "You control when scanning starts.",
                    "Step 2 of 3",
                )
            )

            consent = Card("What happens next")
            consent.body.addWidget(self._body_label(self.state.consent_summary))
            layout.addWidget(consent)

            setup = Card("Provider setup")
            self.setup_error_label = self._body_label("", "listText")
            self.setup_error_label.setVisible(False)
            setup.body.addWidget(self.setup_error_label)

            form = QGridLayout()
            form.setHorizontalSpacing(14)
            form.setVerticalSpacing(10)
            self.setup_username = QLineEdit("")
            self.setup_username.setPlaceholderText("you@example.com")
            self.setup_days_back = QSpinBox()
            self.setup_days_back.setRange(1, 3650)
            self.setup_days_back.setValue(30)
            self.setup_gmail_client_secret_file = QLineEdit("")
            self.setup_gmail_client_secret_file.setPlaceholderText("Path to Gmail setup JSON")
            self.setup_graph_tenant_id = QLineEdit("common")
            self.setup_graph_client_id = QLineEdit("")
            self.setup_graph_client_id.setPlaceholderText("Outlook application client ID")
            self.setup_imap_host = QLineEdit("")
            self.setup_imap_host.setPlaceholderText("imap.example.com")
            self.setup_imap_secret_name = QLineEdit("")
            self.setup_imap_secret_name.setPlaceholderText("Saved password secret name")

            fields = (
                ("Mailbox username", self.setup_username),
                ("Days to scan", self.setup_days_back),
                ("Gmail setup file", self.setup_gmail_client_secret_file),
                ("Outlook tenant", self.setup_graph_tenant_id),
                ("Outlook client ID", self.setup_graph_client_id),
                ("IMAP host", self.setup_imap_host),
                ("Saved IMAP secret name", self.setup_imap_secret_name),
            )
            for row, (label, widget) in enumerate(fields):
                form.addWidget(QLabel(label), row, 0)
                form.addWidget(widget, row, 1)
            setup.body.addLayout(form)
            setup.body.addWidget(
                self._body_label(
                    "Use a saved secret name for other email. Do not paste an IMAP password into this screen.",
                    "listText",
                )
            )
            layout.addWidget(setup)

            button_row = QHBoxLayout()
            back = QPushButton("Back")
            back.setObjectName("secondaryButton")
            back.setCursor(Qt.CursorShape.PointingHandCursor)
            back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
            start = QPushButton("Start scan")
            start.setObjectName("primaryButton")
            start.setCursor(Qt.CursorShape.PointingHandCursor)
            start.clicked.connect(self._start_scan_from_consent)
            button_row.addWidget(back)
            button_row.addStretch(1)
            button_row.addWidget(start)
            layout.addLayout(button_row)
            layout.addStretch(1)
            return page

        def _start_scan_from_consent(self) -> None:
            if hasattr(self, "setup_error_label"):
                self.setup_error_label.setVisible(False)
            if self.state.mail_provider is None:
                self._show_user_error("Choose a mail provider before starting the scan.", SETUP_DETAIL_MISSING_PROVIDER)
                return
            settings = MailProviderSettings(
                provider=self.state.mail_provider,
                username=self.setup_username.text(),
                days_back=self.setup_days_back.value(),
                gmail_client_secret_file=self.setup_gmail_client_secret_file.text(),
                graph_tenant_id=self.setup_graph_tenant_id.text(),
                graph_client_id=self.setup_graph_client_id.text(),
                imap_host=self.setup_imap_host.text(),
                imap_secret_name=self.setup_imap_secret_name.text(),
            )
            provider, error = build_provider_or_error(settings)
            if error is not None:
                self._show_user_error(error.user_message, error.technical_details)
                return
            if provider is None:
                self._show_user_error(
                    "The mail provider could not be prepared. Check setup and try again.",
                    SETUP_DETAIL_MISSING_PROVIDER_INSTANCE,
                )
                return
            self.state = self.state.start_scan()
            self.stack.setCurrentIndex(2)
            self.scan_stage_label.setText(scan_progress_stages()[0])
            thread = QThread(self)
            worker = ScanWorker(GuiScanService(provider), days_back=settings.days_back)
            self._scan_thread = thread
            self._scan_worker = worker
            worker.moveToThread(thread)
            thread.started.connect(worker.run)
            worker.progress.connect(self.scan_stage_label.setText)
            worker.finished.connect(self._finish_real_scan)
            worker.failed.connect(self._handle_scan_failure)
            worker.finished.connect(worker.release_sensitive_refs)
            worker.failed.connect(worker.release_sensitive_refs)
            worker.finished.connect(worker.deleteLater)
            worker.failed.connect(worker.deleteLater)
            worker.finished.connect(self._clear_scan_worker_refs)
            worker.failed.connect(self._clear_scan_worker_refs)
            worker.finished.connect(thread.quit)
            worker.failed.connect(thread.quit)
            thread.finished.connect(thread.deleteLater)
            thread.start()

        def _show_user_error(self, message: str, technical_details: str) -> None:
            if hasattr(self, "setup_error_label"):
                self.setup_error_label.setText(message)
                self.setup_error_label.setVisible(True)
            controlled_details = self._controlled_setup_details(technical_details)
            if controlled_details:
                print(f"Setup check: {controlled_details}", file=sys.stderr)

        def _controlled_setup_details(self, technical_details: str) -> str:
            return controlled_setup_detail_for_log(technical_details)

        @Slot()
        def _clear_scan_worker_refs(self) -> None:
            self._scan_worker = None
            self._scan_thread = None

        def _finish_real_scan(self, summary: ScanSummary) -> None:
            self.state = self.state.with_scan_summary(summary)
            self._render_results()
            self._refresh_dashboard()
            self.stack.setCurrentIndex(3)

        def _handle_scan_failure(self, message: str) -> None:
            self.stack.setCurrentIndex(1)
            self._show_user_error(message, SETUP_DETAIL_SCAN_FAILED)

        def _advance_placeholder_scan_stage(self) -> None:
            if self._placeholder_scan_stage_index >= len(self._placeholder_scan_stages):
                self._continue_to_placeholder_results()
                return
            self.scan_stage_label.setText(self._placeholder_scan_stages[self._placeholder_scan_stage_index])
            self._placeholder_scan_stage_index += 1
            QTimer.singleShot(450, self._advance_placeholder_scan_stage)

        def _scan_progress_page(self) -> QScrollArea:
            page, layout = self._wizard_page()
            layout.addWidget(
                StepHeader(
                    "Looking for account and security emails",
                    "This can take a few minutes.",
                    "Step 3 of 3",
                )
            )
            status_card = Card("Scan status")
            status_card.body.addWidget(StatusPill("Local scan", "safe"))
            self.scan_stage_label = self._body_label("Ready to scan", "listText")
            status_card.body.addWidget(self.scan_stage_label)
            layout.addWidget(status_card)
            layout.addStretch(1)
            return page

        def _continue_to_placeholder_results(self) -> None:
            self.state = self.state.complete_placeholder_scan()
            self._render_results()
            self._refresh_dashboard()
            self.stack.setCurrentIndex(3)

        def _results_page(self) -> QScrollArea:
            page, layout = self._wizard_page()
            self.results_layout = layout
            self._render_empty_results()
            return page

        def _render_results(self) -> None:
            summary = self.state.scan_summary
            if summary is None:
                self._render_empty_results()
                return
            self._clear_layout(self.results_layout)
            self.results_layout.addWidget(StepHeader(summary.headline, summary.attention_text, "Step 3 of 3"))
            if summary.recommended is None:
                self._render_empty_results(summary)
                return

            account = AccountReview.from_finding(summary.recommended, "you@example.com")
            card = Card(f"Start with {account.service_name}")
            card.body.addWidget(StatusPill(account.risk_label, "attention" if account.risk_label == "Needs attention" else "safe"))
            reason_text = " ".join(account.reasons) if account.reasons else "This account has signals worth reviewing first."
            card.body.addWidget(self._body_label(reason_text))
            button_row = QHBoxLayout()
            review = QPushButton("Review account")
            review.setObjectName("primaryButton")
            review.setCursor(Qt.CursorShape.PointingHandCursor)
            review.clicked.connect(lambda checked=False, selected=account: self._open_rotation_for_account(selected))
            all_accounts = QPushButton("All accounts list available after real scan")
            all_accounts.setObjectName("secondaryButton")
            all_accounts.setEnabled(False)
            all_accounts.setToolTip("The all-accounts list will be available when real scan providers are connected.")
            button_row.addWidget(review)
            button_row.addWidget(all_accounts)
            button_row.addStretch(1)
            card.body.addLayout(button_row)
            self.results_layout.addWidget(card)

            dashboard = QPushButton("View dashboard")
            dashboard.setObjectName("secondaryButton")
            dashboard.setCursor(Qt.CursorShape.PointingHandCursor)
            dashboard.clicked.connect(self._show_dashboard)
            self.results_layout.addWidget(dashboard, alignment=Qt.AlignmentFlag.AlignRight)
            self.results_layout.addStretch(1)

        def _render_empty_results(self, summary: ScanSummary | None = None) -> None:
            if hasattr(self, "results_layout"):
                self._clear_layout(self.results_layout)
                title = summary.headline if summary else "Review accounts needing attention"
                subtitle = summary.attention_text if summary else "Results will appear here after the scanner finishes."
                self.results_layout.addWidget(StepHeader(title, subtitle, "Step 3 of 3"))
                empty = Card("No accounts need attention" if summary else "No results yet")
                empty.body.addWidget(
                    self._body_label(
                        "No urgent account alerts were found. You can still review the dashboard summary and return here when another scan has results."
                        if summary
                        else "Scan results will appear here before any account-specific password guidance starts."
                    )
                )
                self.results_layout.addWidget(empty)
                if summary is None:
                    self.results_layout.addStretch(1)
                    return
                button_row = QHBoxLayout()
                rotate = QPushButton("Review password guidance")
                rotate.setObjectName("secondaryButton")
                rotate.setCursor(Qt.CursorShape.PointingHandCursor)
                rotate.clicked.connect(self._show_guided_rotation_placeholder)
                dashboard = QPushButton("View dashboard")
                dashboard.setObjectName("primaryButton")
                dashboard.setCursor(Qt.CursorShape.PointingHandCursor)
                dashboard.clicked.connect(self._show_dashboard)
                button_row.addWidget(rotate)
                button_row.addStretch(1)
                button_row.addWidget(dashboard)
                self.results_layout.addLayout(button_row)
                self.results_layout.addStretch(1)

        def _clear_layout(self, layout) -> None:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                child_layout = item.layout()
                if widget is not None:
                    widget.deleteLater()
                elif child_layout is not None:
                    self._clear_layout(child_layout)

        def _open_rotation_for_account(self, account: AccountReview) -> None:
            session = GuiRotationService().start(account.service_name, account.username, account.url)
            self.state = self.state.start_guided_rotation(account, session)
            self._render_rotation_panel()
            self.stack.setCurrentIndex(4)

        def _show_guided_rotation_placeholder(self) -> None:
            self.state = self.state.show_guided_rotation_placeholder()
            self._render_rotation_panel()
            self.stack.setCurrentIndex(4)

        def _show_results(self) -> None:
            if self.state.scan_summary is None:
                self.stack.setCurrentIndex(0)
                return
            self.state = self.state.show_results()
            self.stack.setCurrentIndex(3)

        def _show_dashboard(self) -> None:
            self._refresh_dashboard()
            if self.state.scan_summary is not None:
                self.state = self.state.show_dashboard()
            self.stack.setCurrentIndex(5)
            self._refresh_dashboard()

        def _guided_rotation_placeholder_page(self) -> QScrollArea:
            page, layout = self._wizard_page()
            self.rotation_layout = layout
            self._render_rotation_panel()
            return page

        def _render_rotation_panel(self) -> None:
            self._clear_layout(self.rotation_layout)
            account = self.state.selected_account
            session = self.state.rotation_session
            if account is None or session is None:
                self.rotation_layout.addWidget(
                    StepHeader(
                        "Password changes are guided here",
                        "Choose an account from scan results to generate masked password choices.",
                    )
                )
                guidance = Card("No account selected")
                for line in (
                    "Open scan results and choose Review account to start account-specific rotation.",
                    "Generated passwords remain masked in this guided path.",
                    self.state.vault_status.primary_message,
                ):
                    guidance.body.addWidget(self._body_label(line, "listText"))
                if self.state.vault_status.requires_csv_cleanup:
                    guidance.body.addWidget(self._body_label(self.state.vault_status.cleanup_message, "listText"))
                self.rotation_layout.addWidget(guidance)
                button_row = QHBoxLayout()
                back = QPushButton("Back to results")
                back.setObjectName("secondaryButton")
                back.setCursor(Qt.CursorShape.PointingHandCursor)
                back.clicked.connect(self._show_results)
                dashboard = QPushButton("View dashboard")
                dashboard.setObjectName("primaryButton")
                dashboard.setCursor(Qt.CursorShape.PointingHandCursor)
                dashboard.clicked.connect(self._show_dashboard)
                button_row.addWidget(back)
                button_row.addStretch(1)
                button_row.addWidget(dashboard)
                self.rotation_layout.addLayout(button_row)
                self.rotation_layout.addStretch(1)
                return

            self.rotation_layout.addWidget(
                StepHeader(
                    f"Rotate {account.service_name} password",
                    "Pick one masked password, change it on the provider reset page, then copy only the selected password.",
                    "Step 4 of 5",
                )
            )
            choices_card = Card("Masked password choices")
            choices_card.body.addWidget(
                self._body_label(
                    "Select one option. Plaintext passwords are not displayed in the guided flow.",
                    "listText",
                )
            )
            choices = QListWidget()
            choices.setObjectName("choiceList")
            choices.setMinimumHeight(178)
            for row in session.choice_summaries:
                selected = "selected" if row.index == session.selected_index else "available"
                choices.addItem(
                    f"Choice {row.index}: {row.display}    length {row.length}    upper {row.has_uppercase}    "
                    f"digit {row.has_digit}    symbol {row.has_symbol}    {selected}"
                )
            if session.selected_index is not None:
                choices.setCurrentRow(session.selected_index - 1)
            choices.currentRowChanged.connect(lambda row: self._select_password_choice(row + 1) if row >= 0 else None)
            choices_card.body.addWidget(choices)
            self.rotation_layout.addWidget(choices_card)

            vault_card = Card("Vault sync")
            vault_card.body.addWidget(self._body_label(self.state.vault_status.primary_message, "listText"))
            if self.state.vault_status.requires_csv_cleanup:
                vault_card.body.addWidget(self._body_label(self.state.vault_status.cleanup_message, "listText"))
            self.rotation_layout.addWidget(vault_card)

            actions = Card("Next action")
            self.rotation_status_label = self._body_label(
                "Select a masked password choice, complete the reset page, then copy the selected password.",
                "listText",
            )
            actions.body.addWidget(self.rotation_status_label)
            button_row = QHBoxLayout()
            copy = QPushButton("Copy selected password")
            copy.setObjectName("primaryButton")
            copy.setCursor(Qt.CursorShape.PointingHandCursor)
            copy.clicked.connect(self._copy_selected_rotation_password)
            button_row.addWidget(copy)
            if account.reset_link:
                reset = QPushButton("Open reset link")
                reset.setObjectName("secondaryButton")
                reset.setCursor(Qt.CursorShape.PointingHandCursor)
                reset.clicked.connect(lambda checked=False, link=account.reset_link: webbrowser.open(link))
                button_row.addWidget(reset)
            back = QPushButton("Back to results")
            back.setObjectName("secondaryButton")
            back.setCursor(Qt.CursorShape.PointingHandCursor)
            back.clicked.connect(self._show_results)
            button_row.addWidget(back)
            button_row.addStretch(1)
            actions.body.addLayout(button_row)
            self.rotation_layout.addWidget(actions)
            self.rotation_layout.addStretch(1)

        def _select_password_choice(self, index: int) -> None:
            session = self.state.rotation_session
            if session is None:
                return
            account = self.state.selected_account or session.account
            try:
                self.state = self.state.start_guided_rotation(account, session.select_choice(index))
            except ValueError:
                return
            self._render_rotation_panel()

        def _copy_selected_rotation_password(self) -> None:
            session = self.state.rotation_session
            if session is None:
                if hasattr(self, "rotation_status_label"):
                    self.rotation_status_label.setText("Choose an account from scan results before copying a password.")
                return
            try:
                selected = session.selected_candidate
            except ValueError:
                if hasattr(self, "rotation_status_label"):
                    self.rotation_status_label.setText("Select one masked password choice before copying.")
                return
            copied = copy_text(selected.password, clear_after_seconds=60)
            if hasattr(self, "rotation_status_label"):
                self.rotation_status_label.setText(
                    "Selected password copied. The clipboard clear timer is set for 60 seconds."
                    if copied
                    else "Clipboard copy is unavailable."
                )

        def _dashboard_page(self) -> QScrollArea:
            page, layout = self._wizard_page()
            layout.addWidget(
                StepHeader(
                    "Account safety dashboard",
                    "Review account risk, vault sync, and cleanup tasks.",
                    "Dashboard",
                )
            )

            status = Card("Current status")
            self.dashboard_summary_label = self._body_label("Connect email and run a scan to begin.", "listText")
            status.body.addWidget(self.dashboard_summary_label)
            layout.addWidget(status)

            actions = Card("Actions")
            action_row = QHBoxLayout()
            scan = QPushButton("Scan email")
            scan.setObjectName("primaryButton")
            scan.setCursor(Qt.CursorShape.PointingHandCursor)
            scan.clicked.connect(lambda: self.stack.setCurrentIndex(0))
            vault = QPushButton("Verify vault sync")
            vault.setObjectName("secondaryButton")
            vault.setCursor(Qt.CursorShape.PointingHandCursor)
            vault.clicked.connect(lambda: self.stack.setCurrentIndex(4))
            advanced = QPushButton("Advanced tools")
            advanced.setObjectName("secondaryButton")
            advanced.setCursor(Qt.CursorShape.PointingHandCursor)
            advanced.clicked.connect(self._show_advanced_tools)
            action_row.addWidget(scan)
            action_row.addWidget(vault)
            action_row.addWidget(advanced)
            action_row.addStretch(1)
            actions.body.addLayout(action_row)
            layout.addWidget(actions)

            layout.addStretch(1)
            return page

        def _refresh_dashboard(self) -> None:
            if not hasattr(self, "dashboard_summary_label"):
                return
            summary = self.state.scan_summary
            if summary is None:
                self.dashboard_summary_label.setText("Connect email and run a scan to begin.")
                return
            vault_text = self.state.vault_status.primary_message
            cleanup_text = (
                f" {self.state.vault_status.cleanup_message}"
                if self.state.vault_status.requires_csv_cleanup
                else ""
            )
            self.dashboard_summary_label.setText(f"{summary.headline}. {summary.attention_text} {vault_text}{cleanup_text}")

        def _show_advanced_tools(self) -> None:
            if not hasattr(self, "dashboard_summary_label"):
                return
            self.dashboard_summary_label.setText(
                "Advanced tools include IMAP setup, CLI-equivalent commands, export/import utilities, and logs. "
                "These are available for troubleshooting and should not be needed for the normal guided flow."
            )

        def _sidebar(self) -> QFrame:
            sidebar = QFrame()
            sidebar.setObjectName("sidebar")
            sidebar.setFixedWidth(270)
            layout = QVBoxLayout(sidebar)
            layout.setContentsMargins(22, 26, 22, 22)
            layout.setSpacing(12)

            title = QLabel("Account\nRecovery Guard")
            title.setObjectName("brandTitle")
            title.setWordWrap(True)
            subtitle = QLabel("Local-first password recovery and vault sync.")
            subtitle.setObjectName("brandSubtitle")
            subtitle.setWordWrap(True)
            layout.addWidget(title)
            layout.addWidget(subtitle)
            layout.addSpacing(18)

            for index, label in enumerate(("Dashboard", "Scan Mail", "Rotate", "Vault Sync", "Security")):
                button = QPushButton(label)
                button.setObjectName("navButton")
                button.setCheckable(True)
                button.setCursor(Qt.CursorShape.PointingHandCursor)
                button.clicked.connect(lambda checked=False, page=index: self.stack.setCurrentIndex(page))
                self.nav_group.addButton(button, index)
                layout.addWidget(button)

            layout.addStretch(1)
            trust = QLabel("No plaintext passwords are logged. OAuth tokens stay in the OS credential store.")
            trust.setObjectName("sidebarNote")
            trust.setWordWrap(True)
            layout.addWidget(trust)
            return sidebar

        def _scroll_page(self, title: str, subtitle: str) -> QScrollArea:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(34, 28, 34, 34)
            layout.setSpacing(20)

            heading = QLabel(title)
            heading.setObjectName("pageTitle")
            heading.setWordWrap(True)
            heading.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
            sub = QLabel(subtitle)
            sub.setObjectName("pageSubtitle")
            sub.setWordWrap(True)
            layout.addWidget(heading)
            layout.addWidget(sub)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            scroll.setWidget(page)
            scroll.setObjectName("pageScroll")
            scroll.content_layout = layout  # type: ignore[attr-defined]
            return scroll

        def _card(self, title: str, body: str, badge: str | None = None) -> QFrame:
            card = QFrame()
            card.setObjectName("card")
            layout = QVBoxLayout(card)
            layout.setContentsMargins(18, 16, 18, 16)
            layout.setSpacing(9)
            row = QHBoxLayout()
            heading = QLabel(title)
            heading.setObjectName("cardTitle")
            heading.setWordWrap(True)
            row.addWidget(heading, 1)
            if badge:
                pill = QLabel(badge)
                pill.setObjectName("badge")
                pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
                row.addWidget(pill)
            layout.addLayout(row)
            text = QLabel(body)
            text.setObjectName("cardText")
            text.setWordWrap(True)
            layout.addWidget(text)
            return card

        def _command_box(self) -> QTextEdit:
            preview = QTextEdit()
            preview.setObjectName("commandBox")
            preview.setReadOnly(True)
            preview.setMinimumHeight(96)
            preview.setFont(QFont("Menlo", 12))
            return preview

        def _copy_button(self, label: str, text_provider) -> QPushButton:
            button = QPushButton(label)
            button.setObjectName("secondaryButton")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda: copy_text(text_provider(), clear_after_seconds=0))
            return button

        def _home_page(self) -> QScrollArea:
            page = self._scroll_page(
                "Recover compromised accounts with both vaults kept in sync",
                "Scan account alerts, choose a new password, update Bitwarden, stage NordPass import, and verify the two vaults match.",
            )
            layout = page.content_layout  # type: ignore[attr-defined]

            flow_grid = QGridLayout()
            flow_grid.setSpacing(14)
            for index, stage in enumerate(recovery_stages()):
                card = self._card(stage.title, stage.detail, stage.status)
                command = QLabel(stage.command)
                command.setObjectName("commandLabel")
                card.layout().addWidget(command)
                flow_grid.addWidget(card, index // 2, index % 2)
            layout.addLayout(flow_grid)

            action_box = QFrame()
            action_box.setObjectName("panel")
            action_layout = QVBoxLayout(action_box)
            action_layout.setContentsMargins(22, 20, 22, 20)
            action_layout.setSpacing(10)
            action_title = QLabel("Suggested path")
            action_title.setObjectName("sectionTitle")
            action_layout.addWidget(action_title)
            for action in suggested_next_actions():
                label = QLabel("- " + action)
                label.setObjectName("listText")
                label.setWordWrap(True)
                action_layout.addWidget(label)
            layout.addWidget(action_box)

            status_grid = QGridLayout()
            status_grid.setSpacing(14)
            statuses = (
                ("Mail scan", "Gmail, Outlook, or IMAP"),
                ("Password choices", "Five generated options"),
                ("Bitwarden", "Official bw CLI write"),
                ("NordPass", "Supported CSV import"),
            )
            for index, (title, body) in enumerate(statuses):
                status_grid.addWidget(self._card(title, body, "ready"), 0, index)
            layout.addLayout(status_grid)
            layout.addStretch(1)
            return page

        def _mail_page(self) -> QScrollArea:
            page = self._scroll_page(
                "Scan email for hacked-account signals",
                "Build the safest scan command for Gmail, Outlook, or IMAP. Secrets are referenced by name and read from the OS credential store.",
            )
            layout = page.content_layout  # type: ignore[attr-defined]
            panel = QFrame()
            panel.setObjectName("panel")
            form = QGridLayout(panel)
            form.setContentsMargins(22, 20, 22, 20)
            form.setHorizontalSpacing(14)
            form.setVerticalSpacing(12)

            provider = QComboBox()
            provider.addItems(["Gmail API", "Microsoft Graph", "IMAP"])
            email = QLineEdit("you@example.com")
            host = QLineEdit("imap.example.com")
            secret_name = QLineEdit("mail-password-or-token")
            client_secret = QLineEdit("client_secret.json")
            tenant_id = QLineEdit("common")
            client_id = QLineEdit("")
            days = QSpinBox()
            days.setRange(1, 3650)
            days.setValue(30)
            preview = self._command_box()

            def update_preview() -> None:
                if provider.currentText() == "Gmail API":
                    command = build_command_preview(
                        "scan-gmail",
                        {"client_secret_file": client_secret.text(), "token_secret_name": secret_name.text(), "days": days.value()},
                    )
                elif provider.currentText() == "Microsoft Graph":
                    command = build_command_preview(
                        "scan-graph",
                        {"tenant_id": tenant_id.text(), "client_id": client_id.text(), "token_secret_name": secret_name.text(), "days": days.value()},
                    )
                else:
                    command = build_command_preview(
                        "scan-imap",
                        {"host": host.text(), "username": email.text(), "secret_name": secret_name.text(), "days": days.value(), "json": True},
                    )
                preview.setText(command)

            widgets = (
                ("Provider", provider),
                ("Mailbox username", email),
                ("IMAP host", host),
                ("Credential secret name", secret_name),
                ("Gmail client secret file", client_secret),
                ("Microsoft tenant", tenant_id),
                ("Microsoft client ID", client_id),
                ("Days to scan", days),
            )
            for row, (label, widget) in enumerate(widgets):
                form.addWidget(QLabel(label), row, 0)
                form.addWidget(widget, row, 1)
            provider.currentTextChanged.connect(update_preview)
            for widget in (email, host, secret_name, client_secret, tenant_id, client_id):
                widget.textChanged.connect(update_preview)
            days.valueChanged.connect(update_preview)
            form.addWidget(QLabel("Command preview"), len(widgets), 0)
            form.addWidget(preview, len(widgets), 1)
            copy = self._copy_button("Copy scan command", preview.toPlainText)
            form.addWidget(copy, len(widgets) + 1, 1, alignment=Qt.AlignmentFlag.AlignRight)
            layout.addWidget(panel)
            update_preview()
            return page

        def _advanced_rotation_page_unreachable_from_first_run(self) -> QScrollArea:
            page = self._scroll_page(
                "Rotate one risky account at a time",
                "Generate five strong passwords, select one, open the reset flow if available, then copy only the chosen password.",
            )
            layout = page.content_layout  # type: ignore[attr-defined]
            panel = QFrame()
            panel.setObjectName("panel")
            form = QGridLayout(panel)
            form.setContentsMargins(22, 20, 22, 20)
            form.setHorizontalSpacing(14)
            form.setVerticalSpacing(12)

            service = QLineEdit("Example")
            username = QLineEdit("you@example.com")
            url = QLineEdit("https://example.com")
            reset_link = QLineEdit("")
            open_reset = QCheckBox("Open reset link during rotation")
            copy_selected = QCheckBox("Copy selected password and clear clipboard after 60 seconds")
            copy_selected.setChecked(True)
            choices = QListWidget()
            choices.setObjectName("choiceList")
            choices.setMinimumHeight(176)
            result = QTextEdit()
            result.setObjectName("resultBox")
            result.setReadOnly(True)
            result.setMinimumHeight(82)
            preview = self._command_box()

            def update_preview() -> None:
                command = build_command_preview(
                    "rotate",
                    {
                        "service": service.text(),
                        "username": username.text(),
                        "url": url.text(),
                        "reset_link": reset_link.text(),
                        "open": open_reset.isChecked(),
                        "copy_selected": copy_selected.isChecked(),
                    },
                )
                preview.setText(command)

            def generate() -> None:
                generated = build_rotation_choices(service.text(), username.text(), url.text())
                choices.clear()
                choices.generated = generated  # type: ignore[attr-defined]
                for row in summarize_rotation_choices([candidate.password for candidate in generated]):
                    choices.addItem(
                        f"Choice {row.index}: {row.display}    length {row.length}    upper {row.has_uppercase}    digit {row.has_digit}    symbol {row.has_symbol}"
                    )
                result.setText("Five choices generated. Select one, complete the reset page, then copy the selected password.")

            def copy_password() -> None:
                generated = getattr(choices, "generated", [])
                index = choices.currentRow()
                if index < 0 or index >= len(generated):
                    result.setText("Select one generated password first.")
                    return
                copied = copy_text(generated[index].password, clear_after_seconds=60)
                result.setText("Selected password copied. The clipboard clear timer is set for 60 seconds." if copied else "Clipboard copy is unavailable.")

            for widget in (service, username, url, reset_link):
                widget.textChanged.connect(update_preview)
            open_reset.stateChanged.connect(update_preview)
            copy_selected.stateChanged.connect(update_preview)

            fields = (("Service", service), ("Username", username), ("Login URL", url), ("Reset link", reset_link))
            for row, (label, widget) in enumerate(fields):
                form.addWidget(QLabel(label), row, 0)
                form.addWidget(widget, row, 1)
            form.addWidget(open_reset, 4, 1)
            form.addWidget(copy_selected, 5, 1)
            generate_button = QPushButton("Generate 5 choices")
            generate_button.setObjectName("primaryButton")
            generate_button.clicked.connect(generate)
            copy_button = QPushButton("Copy selected password")
            copy_button.setObjectName("primaryButton")
            copy_button.clicked.connect(copy_password)
            button_row = QHBoxLayout()
            button_row.addWidget(generate_button)
            button_row.addWidget(copy_button)
            button_row.addStretch(1)
            form.addLayout(button_row, 6, 1)
            form.addWidget(QLabel("Password choices"), 7, 0)
            form.addWidget(choices, 7, 1)
            form.addWidget(QLabel("Status"), 8, 0)
            form.addWidget(result, 8, 1)
            form.addWidget(QLabel("CLI equivalent"), 9, 0)
            form.addWidget(preview, 9, 1)
            form.addWidget(self._copy_button("Copy rotate command", preview.toPlainText), 10, 1, alignment=Qt.AlignmentFlag.AlignRight)
            layout.addWidget(panel)
            update_preview()
            return page

        def _vault_page(self) -> QScrollArea:
            page = self._scroll_page(
                "Write to Bitwarden, import to NordPass, verify drift",
                "Bitwarden can be updated through the official bw CLI. NordPass personal vault sync uses the supported CSV import/export path.",
            )
            layout = page.content_layout  # type: ignore[attr-defined]

            write_panel = QFrame()
            write_panel.setObjectName("panel")
            write_form = QGridLayout(write_panel)
            write_form.setContentsMargins(22, 20, 22, 20)
            service = QLineEdit("Example")
            username = QLineEdit("you@example.com")
            url = QLineEdit("https://example.com")
            password_secret = QLineEdit("new-password-secret")
            nordpass_csv = QLineEdit(str(user_state_dir("account-recovery-guard") / "nordpass-import.csv"))
            write_preview = self._command_box()

            def update_write() -> None:
                write_preview.setText(
                    build_command_preview(
                        "write-vaults",
                        {
                            "service": service.text(),
                            "username": username.text(),
                            "url": url.text(),
                            "password_secret": password_secret.text(),
                            "nordpass_csv": nordpass_csv.text(),
                        },
                    )
                )

            for row, (label, widget) in enumerate(
                (
                    ("Service", service),
                    ("Username", username),
                    ("Login URL", url),
                    ("Password secret name", password_secret),
                    ("NordPass import CSV", nordpass_csv),
                )
            ):
                write_form.addWidget(QLabel(label), row, 0)
                write_form.addWidget(widget, row, 1)
                widget.textChanged.connect(update_write)
            write_form.addWidget(QLabel("Write command"), 5, 0)
            write_form.addWidget(write_preview, 5, 1)
            write_form.addWidget(self._copy_button("Copy write command", write_preview.toPlainText), 6, 1, alignment=Qt.AlignmentFlag.AlignRight)
            layout.addWidget(write_panel)

            verify_panel = QFrame()
            verify_panel.setObjectName("panel")
            verify_form = QGridLayout(verify_panel)
            verify_form.setContentsMargins(22, 20, 22, 20)
            bitwarden_export = QLineEdit("bitwarden-export.json")
            nordpass_export = QLineEdit("nordpass-export.csv")
            verify_preview = self._command_box()

            def update_verify() -> None:
                verify_preview.setText(
                    build_command_preview(
                        "vault-dashboard",
                        {"bitwarden_export": bitwarden_export.text(), "nordpass_export": nordpass_export.text()},
                    )
                )

            verify_form.addWidget(QLabel("Bitwarden export"), 0, 0)
            verify_form.addWidget(bitwarden_export, 0, 1)
            verify_form.addWidget(QLabel("NordPass export"), 1, 0)
            verify_form.addWidget(nordpass_export, 1, 1)
            verify_form.addWidget(QLabel("Drift command"), 2, 0)
            verify_form.addWidget(verify_preview, 2, 1)
            verify_form.addWidget(self._copy_button("Copy verify command", verify_preview.toPlainText), 3, 1, alignment=Qt.AlignmentFlag.AlignRight)
            bitwarden_export.textChanged.connect(update_verify)
            nordpass_export.textChanged.connect(update_verify)
            layout.addWidget(verify_panel)
            update_write()
            update_verify()
            return page

        def _security_page(self) -> QScrollArea:
            page = self._scroll_page(
                "Security boundaries and cleanup",
                "This tool keeps recovery local, but some steps stay intentionally manual because vaults, MFA, and reset pages are security controls.",
            )
            layout = page.content_layout  # type: ignore[attr-defined]

            limits = QGridLayout()
            limits.setSpacing(14)
            limit_cards = (
                ("Passkeys", "Store passkeys in your phone or OS account where the service supports it; do not export them through this app."),
                ("MFA", "The app can open reset links, but you complete MFA challenges yourself."),
                ("NordPass", "Personal-vault writes are staged as CSV because NordPass does not provide a public personal-vault CRUD API."),
                ("Logs", "Audit events record actions and counts, never plaintext passwords or token values."),
            )
            for index, (title, body) in enumerate(limit_cards):
                limits.addWidget(self._card(title, body, "guardrail"), index // 2, index % 2)
            layout.addLayout(limits)

            passkey_box = QGroupBox("Passkey guidance example")
            passkey_box.setObjectName("group")
            passkey_layout = QVBoxLayout(passkey_box)
            for step in passkey_guidance("github"):
                label = QLabel("- " + step)
                label.setObjectName("listText")
                label.setWordWrap(True)
                passkey_layout.addWidget(label)
            layout.addWidget(passkey_box)

            csv_warning = QLabel(plaintext_file_warning(Path("nordpass-import.csv")) or "No stale NordPass CSV detected in the current folder.")
            csv_warning.setObjectName("warningText")
            csv_warning.setWordWrap(True)
            layout.addWidget(csv_warning)
            return page

    app = QApplication(sys.argv)
    app.setStyleSheet(calm_shield_stylesheet())
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
