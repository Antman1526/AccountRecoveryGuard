import os
from pathlib import Path

import pytest

from account_recovery_guard.gui_theme import calm_shield_stylesheet

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication

    from account_recovery_guard.gui_components import ProviderButton, StepHeader, StatusPill
except ImportError:
    QApplication = None
    ProviderButton = None
    StepHeader = None
    StatusPill = None

pytestmark_widgets = pytest.mark.skipif(QApplication is None, reason="PySide6 is required for widget tests")


@pytest.fixture(scope="module")
def app():
    if QApplication is None:
        pytest.skip("PySide6 is required for widget tests")
    existing = QApplication.instance()
    return existing or QApplication([])


def test_theme_contains_primary_action_color():
    css = calm_shield_stylesheet()

    assert "#155f57" in css
    assert "primaryButton" in css


def test_theme_covers_existing_gui_object_names():
    css = calm_shield_stylesheet()

    expected_selectors = (
        "#sidebar",
        "#brandTitle",
        "#brandSubtitle",
        "#sidebarNote",
        "#navButton",
        "#pageScroll",
        "#sectionTitle",
        "#cardTitle",
        "#cardText",
        "#listText",
        "#badge",
        "#commandLabel",
        "#warningText",
        "#group",
        "#commandBox",
        "#resultBox",
        "#choiceList",
        "QLineEdit",
        "QComboBox",
        "QSpinBox",
        "QCheckBox",
        "QCheckBox::indicator",
    )

    missing = [selector for selector in expected_selectors if selector not in css]

    assert not missing


def test_advanced_rotation_copy_requires_official_page_confirmation():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "official_page_confirmed = QCheckBox" in source
    assert "official_page_confirmed.isChecked()" in source
    assert "copy_button.setEnabled(False)" in source
    assert "official_page_confirmed.stateChanged.connect" in source


def test_scan_start_button_is_disabled_until_consent_is_ready():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "self.setup_start_scan_button = start" in source
    assert "start.setEnabled(False)" in source
    assert "self.setup_scan_consent.stateChanged.connect" in source
    assert "self.setup_second_person_consent.stateChanged.connect" in source
    assert "scan_start_ready(" in source


def test_gui_helper_and_consent_copy_limits_scans_to_authorized_mailboxes():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "Only scan a mailbox you own or are explicitly helping with while that person is present." in source
    assert "Do not use this app to investigate someone else's accounts without permission." in source
    assert "I have permission to scan this authorized mailbox." in source


def test_password_exposure_result_uses_known_unknown_display_message():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "password_exposure_display_message" in source
    assert "status_label.setText(password_exposure_display_message(result.count, result.user_message))" in source


def test_linked_accounts_card_labels_inventory_as_not_exposure_findings():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert 'Card("Linked accounts from mailbox evidence")' in source
    assert 'StatusPill("not exposure findings", "safe")' in source
    assert "summary.linked_accounts_explanation" in source
    assert "Inventory only; rotate only if another risk signal applies." in source


def test_guided_rotation_actions_require_selected_password_choice():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "rotation_copy_ready(state != 0, selected)" in source
    assert "selected=session.selected_index is not None" in source
    assert "vault_sync_ready(changed.isChecked(), checked.isChecked(), selected)" in source


def test_advanced_rotation_command_preview_requires_explicit_reveal_flag():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert 'QCheckBox("Unsafe: reveal selected password in terminal")' in source
    assert '"reveal_selected": reveal_selected.isChecked()' in source


def test_advanced_rotation_page_copy_is_review_first():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert '"Review one risky account before rotating"' in source
    assert "Generate choices only after the account evidence supports a password change" in source
    assert '"Rotate one risky account at a time"' not in source


def test_first_launch_boundary_card_uses_check_not_find_claim():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert 'Card("What this app can check")' in source
    assert "self._exposure_boundary_card()" in source
    assert "def _exposure_boundary_card" in source
    assert "exposure_boundary_rows()" in source
    assert "review_scope_lines()" in source
    assert 'Card("What this app can safely find")' not in source
    assert "self._safe_exposure_boundary_card()" not in source
    assert "def _safe_exposure_boundary_card" not in source
    assert "safe_exposure_boundary_rows()" not in source
    assert "safe_recovery_scope_lines()" not in source


def test_first_launch_scope_card_uses_review_not_safety_claim():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert 'Card("Recovery review scope")' in source
    assert 'Card("Safe recovery scope")' not in source


def test_guided_rotation_header_is_review_first():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert 'f"Review {account.service_name} password change"' in source
    assert "Use a masked generated password only if the reviewed evidence supports rotation." in source
    assert 'f"Rotate {account.service_name} password"' not in source


def test_guided_rotation_status_keeps_official_page_boundary():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "use the official site or verified reset page, then copy the selected password" in source
    assert "complete the reset page, then copy" not in source


def test_reset_browser_copy_names_verified_link_not_protection_claim():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    worker_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui_workers.py"
    source = gui_source.read_text(encoding="utf-8") + worker_source.read_text(encoding="utf-8")

    assert "Open verified reset browser" in source
    assert "Opening verified reset browser with downloads blocked." in source
    assert "The verified reset browser could not open." in source
    assert "_open_verified_reset_browser" in source
    assert "Open protected reset browser" not in source
    assert "_open_protected_reset_browser" not in source
    assert "protected recovery browser" not in source


def test_gui_copy_does_not_claim_accounts_are_compromised():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "Recover compromised accounts" not in source
    assert "hacked-account" not in source
    assert "Review risky account signals" in source
    assert "Scan email for risky account signals" in source


def test_dashboard_copy_uses_risk_not_safety_claims():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert '"Account risk dashboard"' in source
    assert '"Review account risk, vault sync, and cleanup tasks."' in source
    assert '"Account safety dashboard"' not in source


def test_plain_english_plan_uses_review_not_protection_claim():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert 'Card("Plain-English review plan")' in source
    assert "build_review_plan" in source
    assert "self._review_plan_card" in source
    assert '"Next review action"' in source
    assert 'Card("Plain-English protection plan")' not in source
    assert "build_protection_plan" not in source
    assert "self._protection_plan_card" not in source
    assert '"Next safe action"' not in source


def test_checklist_copy_uses_review_not_protection_claim():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert 'Card("Review checklist")' in source
    assert 'QLabel("Review checklist")' in source
    assert "Review one mailbox at a time. For a second person" in source
    assert '"Protection checklist"' not in source
    assert "Protect one mailbox at a time" not in source


def test_helper_mode_copy_uses_review_not_protection_claim():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert 'Card("Who are you helping review?")' in source
    assert "review_subject_choice_label" in source
    assert "_set_review_subject_choice" in source
    assert "with_review_subject" in source
    assert '("Me", "Review my accounts")' in source
    assert 'Card("Who are you protecting?")' not in source
    assert "protected_person_choice_label" not in source
    assert "_set_protected_person_choice" not in source
    assert "with_protected_person" not in source
    assert '("Me", "Protect me")' not in source


def test_password_exposure_card_renders_reused_password_triage_steps():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "reused_password_triage_steps(self.state.password_exposure_count)" in source
    assert "Reused password triage" in source
    assert "Safe reuse triage" not in source
    assert "password_triage_note.setVisible(bool(password_triage_steps))" in source


def test_exposure_plan_preview_confirms_old_reused_password_scope():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert '"confirm_old_or_reused": bool(exposure_password_secret.text().strip())' in source


def test_password_check_panel_names_old_reused_scope_not_general_safety():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert 'QGroupBox("Check one old or reused password")' in source
    assert 'QGroupBox("Check one password safely")' not in source


def test_exposure_plan_panel_uses_review_not_safety_label():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert 'QGroupBox("Exposure review plan")' in source
    assert 'QGroupBox("Safe exposure plan")' not in source


def test_next_action_card_uses_review_not_safety_claim():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert 'Card("Next review action")' in source
    assert "summary.next_review_action" in source
    assert 'Card("Next safest action")' not in source
    assert "summary.next_safest_action" not in source


def test_exposure_plan_panel_reminds_cleanup_for_password_check_secret():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "Delete the temporary password-check secret after running the command." in source
    assert "arg secret-delete <secret-name>" in source


def test_exposure_plan_panel_names_paid_email_lookup_not_account_level_lookup():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "only if you decide the paid email-address lookup is worth it." in source
    assert "only if you decide the account-level breach lookup is worth it." not in source


def test_password_exposure_finish_refreshes_visible_triage_guidance():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "self._password_exposure_triage_widgets" in source
    assert "self._refresh_password_exposure_triage_guidance()" in source
    assert "triage_note.setVisible(bool(triage_steps))" in source


def test_connect_email_header_uses_review_not_safety_claim():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert '"Connect email for review"' in source
    assert '"Connect email safely"' not in source


def test_mail_scan_setup_copy_uses_scoped_command_not_safest_claim():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert (
        "Build a scoped scan command for Gmail, Outlook, or IMAP. "
        "Secrets are referenced by name and read from the OS credential store."
    ) in source
    assert "Build the safest scan command for Gmail, Outlook, or IMAP." not in source


@pytestmark_widgets
def test_step_header_renders_title_and_subtitle(app):
    header = StepHeader("Connect email for review", "We scan account and security emails locally.")

    assert header.title.text() == "Connect email for review"
    assert "locally" in header.subtitle.text()


@pytestmark_widgets
def test_provider_button_has_accessible_label(app):
    button = ProviderButton("Continue with Gmail", "Recommended for Gmail accounts")

    assert button.text() == "Continue with Gmail"
    assert "Gmail" in button.toolTip()


@pytestmark_widgets
def test_status_pill_exposes_status_text(app):
    pill = StatusPill("Needs attention", "attention")

    assert pill.text() == "Needs attention"
    assert pill.property("tone") == "attention"
