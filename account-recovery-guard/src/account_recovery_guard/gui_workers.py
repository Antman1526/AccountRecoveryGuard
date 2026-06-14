from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from .gui_services import SAFE_SCAN_FAILURE_MESSAGE, GuiPasswordExposureService, GuiScanService, scan_progress_stages


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

    def __init__(self, service: GuiPasswordExposureService, password: str) -> None:
        super().__init__()
        self.service: GuiPasswordExposureService | None = service
        self.password: str | None = password

    @Slot()
    def run(self) -> None:
        service = self.service
        password = self.password or ""
        self.password = None
        if service is None:
            self.finished.emit(GuiPasswordExposureService().check_password(""))
            return
        self.finished.emit(service.check_password(password))

    @Slot()
    def release_sensitive_refs(self) -> None:
        self.service = None
        self.password = None
