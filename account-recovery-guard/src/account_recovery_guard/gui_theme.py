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
