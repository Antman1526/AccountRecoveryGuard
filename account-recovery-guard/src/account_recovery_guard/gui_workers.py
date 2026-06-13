from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from .gui_services import GuiScanService, sanitize_scan_error, scan_progress_stages


class ScanWorker(QObject):
    progress = Signal(str)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, service: GuiScanService, days_back: int = 30) -> None:
        super().__init__()
        self.service = service
        self.days_back = days_back

    @Slot()
    def run(self) -> None:
        try:
            for stage in scan_progress_stages():
                self.progress.emit(stage)
            summary = self.service.scan(self.days_back)
        except Exception as exc:
            self.failed.emit(sanitize_scan_error(str(exc)))
            return
        self.finished.emit(summary)
