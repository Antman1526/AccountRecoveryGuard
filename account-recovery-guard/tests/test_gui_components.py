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


def test_guided_official_site_uses_protected_recovery_browser():
    gui_source = Path(__file__).parents[1] / "src" / "account_recovery_guard" / "gui.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "Open protected official site" in source
    assert "def _open_protected_official_site" in source
    assert "self._open_protected_recovery_browser(account.url, account.url)" in source
    assert "webbrowser.open(link)" not in source


@pytestmark_widgets
def test_step_header_renders_title_and_subtitle(app):
    header = StepHeader("Connect email safely", "We scan account and security emails locally.")

    assert header.title.text() == "Connect email safely"
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
