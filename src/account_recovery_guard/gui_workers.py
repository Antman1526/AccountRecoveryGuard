from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from .gui_services import SAFE_SCAN_FAILURE_MESSAGE, GuiPasswordExposureService, GuiScanService, scan_progress_stages
from .reset_orchestrator import ResetLinkSafetyError, open_reset_link_window


class ScanWorker(QObject):
    progress = Signal(str)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, service: GuiScanService, days_back: int = 30) -> None:
        super().__init__()
        self.service: GuiScanService | None = service
        self.days_back = days_back

    @Slot()
    def run(self) -> None:
        try:
            for stage in scan_progress_stages():
                self.progress.emit(stage)
            if self.service is None:
                raise RuntimeError("scan service unavailable")
            summary = self.service.scan(self.days_back)
        except Exception:
            self.failed.emit(SAFE_SCAN_FAILURE_MESSAGE)
            return
        self.finished.emit(summary)

    @Slot()
    def release_sensitive_refs(self) -> None:
        self.service = None


class PasswordExposureWorker(QObject):
    finished = Signal(object)

    def __init__(self, service: GuiPasswordExposureService, password: str, confirmed_old_or_reused: bool = False) -> None:
        super().__init__()
        self.service: GuiPasswordExposureService | None = service
        self.password: str | None = password
        self.confirmed_old_or_reused = confirmed_old_or_reused

    @Slot()
    def run(self) -> None:
        service = self.service
        password = self.password or ""
        self.password = None
        if service is None:
            self.finished.emit(GuiPasswordExposureService().check_password(""))
            return
        self.finished.emit(service.check_password(password, self.confirmed_old_or_reused))

    @Slot()
    def release_sensitive_refs(self) -> None:
        self.service = None
        self.password = None


class ResetBrowserWorker(QObject):
    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, reset_link: str, expected_domain_or_url: str | None) -> None:
        super().__init__()
        self.reset_link: str | None = reset_link
        self.expected_domain_or_url = expected_domain_or_url

    @Slot()
    def run(self) -> None:
        try:
            open_reset_link_window(self.reset_link or "", self.expected_domain_or_url)
        except ResetLinkSafetyError:
            self.failed.emit("Reset link was not opened. Use the official website or app instead.")
            return
        except Exception:
            self.failed.emit("The verified reset browser could not open. Use the official website or app instead.")
            return
        self.finished.emit("Verified reset browser closed. Confirm the new password works before preparing vault sync.")

    @Slot()
    def release_sensitive_refs(self) -> None:
        self.reset_link = None
        self.expected_domain_or_url = None
