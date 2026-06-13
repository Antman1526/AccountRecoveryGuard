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
