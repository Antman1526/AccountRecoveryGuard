from __future__ import annotations

import sys
from pathlib import Path

from .passkeys import passkey_guidance
from .rotation import build_rotation_choices, summarize_rotation_choices
from .secure_files import plaintext_file_warning


def main() -> int:
    try:
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import (
            QApplication,
            QGridLayout,
            QGroupBox,
            QLabel,
            QLineEdit,
            QListWidget,
            QMainWindow,
            QPushButton,
            QTabWidget,
            QTextEdit,
            QVBoxLayout,
            QWidget,
        )
    except ImportError:
        print("PySide6 is not installed. Install GUI dependencies with: python -m pip install '.[gui]'", file=sys.stderr)
        return 2

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("Account Recovery Guard")
            self.resize(980, 680)
            tabs = QTabWidget()
            tabs.addTab(self._overview_tab(), "Overview")
            tabs.addTab(self._rotation_tab(), "Rotation")
            tabs.addTab(self._vault_tab(), "Vault Drift")
            tabs.addTab(self._security_tab(), "Security")
            self.setCentralWidget(tabs)

        def _overview_tab(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            summary = QTextEdit()
            summary.setReadOnly(True)
            summary.setText(
                "Use the CLI commands for live inbox and vault operations until OAuth consent is configured.\n\n"
                "Recommended flow:\n"
                "1. discover-imap or OAuth mail adapter\n"
                "2. breach-check\n"
                "3. rotate\n"
                "4. import NordPass CSV\n"
                "5. verify-sync\n"
            )
            layout.addWidget(summary)
            return page

        def _rotation_tab(self) -> QWidget:
            page = QWidget()
            layout = QGridLayout(page)
            self.service = QLineEdit("Example")
            self.username = QLineEdit("you@example.com")
            self.url = QLineEdit("https://example.com")
            choices = QListWidget()
            reveal = QTextEdit()
            reveal.setReadOnly(True)
            reveal.setPlaceholderText("Selected password appears here only after you generate and choose it.")

            def generate() -> None:
                generated = build_rotation_choices(self.service.text(), self.username.text(), self.url.text())
                choices.clear()
                choices.generated = generated  # type: ignore[attr-defined]
                for row in summarize_rotation_choices([candidate.password for candidate in generated]):
                    choices.addItem(
                        f"{row.index}. {row.display}  length={row.length}  upper={row.has_uppercase} digit={row.has_digit} symbol={row.has_symbol}"
                    )

            def reveal_selected() -> None:
                generated = getattr(choices, "generated", [])
                index = choices.currentRow()
                if index < 0 or index >= len(generated):
                    reveal.setText("Select one generated password first.")
                    return
                reveal.setText(generated[index].password)

            layout.addWidget(QLabel("Service"), 0, 0)
            layout.addWidget(self.service, 0, 1)
            layout.addWidget(QLabel("Username"), 1, 0)
            layout.addWidget(self.username, 1, 1)
            layout.addWidget(QLabel("URL"), 2, 0)
            layout.addWidget(self.url, 2, 1)
            generate_button = QPushButton("Generate 5 Choices")
            generate_button.clicked.connect(generate)
            layout.addWidget(generate_button, 3, 0, 1, 2)
            layout.addWidget(choices, 4, 0, 1, 2)
            reveal_button = QPushButton("Reveal Selected")
            reveal_button.clicked.connect(reveal_selected)
            layout.addWidget(reveal_button, 5, 0, 1, 2)
            layout.addWidget(reveal, 6, 0, 1, 2)
            return page

        def _vault_tab(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            text = QTextEdit()
            text.setReadOnly(True)
            text.setText(
                "Vault drift dashboard is powered by verify-sync and build_vault_dashboard().\n\n"
                "Statuses: in_sync, drift, bitwarden_only, nordpass_only.\n"
                "Export NordPass CSV after import, then run verify-sync from the CLI."
            )
            layout.addWidget(text)
            return page

        def _security_tab(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            passkey_box = QGroupBox("Passkey Guidance")
            passkey_layout = QVBoxLayout(passkey_box)
            for step in passkey_guidance("github"):
                label = QLabel(step)
                label.setWordWrap(True)
                passkey_layout.addWidget(label)
            csv_warning = QLabel(plaintext_file_warning(Path("nordpass-import.csv")) or "No stale NordPass CSV detected in this folder.")
            csv_warning.setWordWrap(True)
            csv_warning.setAlignment(Qt.AlignmentFlag.AlignTop)
            layout.addWidget(passkey_box)
            layout.addWidget(csv_warning)
            return page

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
