from __future__ import annotations


def calm_shield_stylesheet() -> str:
    return """
    QMainWindow, QWidget {
        background: #f4faf8;
        color: #173630;
        font-family: Arial;
        font-size: 14px;
    }
    QFrame#sidebar {
        background: #e8f3f0;
        border-right: 1px solid #cfe1dc;
    }
    QLabel#brandTitle {
        background: transparent;
        color: #15352f;
        font-size: 24px;
        font-weight: 800;
    }
    QLabel#brandSubtitle, QLabel#sidebarNote {
        background: transparent;
        color: #58716d;
        line-height: 1.35;
    }
    QLabel#sidebarNote {
        background: #f8fcfb;
        border: 1px solid #cfe1dc;
        border-radius: 12px;
        padding: 12px;
        font-size: 12px;
    }
    QPushButton#navButton {
        background: transparent;
        color: #234a43;
        border: 1px solid transparent;
        border-radius: 10px;
        padding: 11px 13px;
        text-align: left;
        font-weight: 700;
    }
    QPushButton#navButton:hover {
        background: #f8fcfb;
        border-color: #cfe1dc;
    }
    QPushButton#navButton:checked {
        background: #155f57;
        color: #ffffff;
        border-color: #155f57;
    }
    QScrollArea#pageScroll {
        background: #f4faf8;
        border: 0;
    }
    QScrollArea#pageScroll > QWidget > QWidget {
        background: #f4faf8;
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
    QLabel#sectionTitle, QLabel#cardTitle {
        background: transparent;
        color: #15352f;
        font-size: 17px;
        font-weight: 800;
    }
    QLabel#cardText, QLabel#listText {
        background: transparent;
        color: #45625d;
        line-height: 1.35;
    }
    QLabel#badge {
        background: #e4f4ef;
        color: #155f57;
        border: 1px solid #bfe1d8;
        border-radius: 999px;
        padding: 4px 9px;
        font-size: 12px;
        font-weight: 800;
    }
    QLabel#commandLabel {
        background: #f3f8f6;
        color: #275149;
        border: 1px solid #dce9e5;
        border-radius: 8px;
        padding: 7px 9px;
        font-family: Menlo;
        font-size: 12px;
    }
    QLabel#warningText {
        background: #fff1ed;
        color: #8f352c;
        border: 1px solid #f4cbc3;
        border-radius: 12px;
        padding: 12px;
        font-weight: 700;
    }
    QGroupBox#group {
        background: #ffffff;
        border: 1px solid #dce9e5;
        border-radius: 16px;
        margin-top: 14px;
        padding: 16px 14px 14px 14px;
        color: #15352f;
        font-weight: 800;
    }
    QGroupBox#group::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 8px;
        color: #15352f;
        background: #f4faf8;
    }
    QTextEdit#commandBox, QTextEdit#resultBox {
        background: #f8fcfb;
        color: #173630;
        border: 1px solid #cfe1dc;
        border-radius: 12px;
        padding: 10px;
        selection-background-color: #bfe1d8;
    }
    QListWidget#choiceList {
        background: #ffffff;
        color: #173630;
        border: 1px solid #cfe1dc;
        border-radius: 12px;
        padding: 6px;
        outline: 0;
    }
    QListWidget#choiceList::item {
        border-radius: 8px;
        padding: 8px;
    }
    QListWidget#choiceList::item:selected {
        background: #e4f4ef;
        color: #155f57;
    }
    QLineEdit, QComboBox, QSpinBox {
        background: #ffffff;
        color: #173630;
        border: 1px solid #cfe1dc;
        border-radius: 10px;
        padding: 8px 10px;
        min-height: 22px;
    }
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
        border: 1px solid #155f57;
    }
    QComboBox::drop-down {
        border: 0;
        width: 28px;
    }
    QCheckBox {
        background: transparent;
        color: #234a43;
        spacing: 9px;
    }
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border: 1px solid #9fc4bc;
        border-radius: 5px;
        background: #ffffff;
    }
    QCheckBox::indicator:checked {
        background: #155f57;
        border-color: #155f57;
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
