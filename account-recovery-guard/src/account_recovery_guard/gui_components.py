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
