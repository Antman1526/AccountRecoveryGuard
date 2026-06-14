from __future__ import annotations

from pathlib import Path
from time import time

from .paths import user_state_dir


DEFAULT_APP_NAME = "account-recovery-guard"
DEFAULT_NORDPASS_IMPORT_CSV = "nordpass-import.csv"


def csv_expiration_warning(age_seconds: float, ttl_seconds: int = 300) -> str | None:
    if age_seconds > ttl_seconds:
        return f"Plaintext CSV is older than {ttl_seconds} seconds; import or delete it now."
    return None


def plaintext_file_warning(path: Path, ttl_seconds: int = 300) -> str | None:
    if not path.exists():
        return None
    return csv_expiration_warning(time() - path.stat().st_mtime, ttl_seconds)


def default_nordpass_import_csv_path(app_name: str = DEFAULT_APP_NAME) -> Path:
    return user_state_dir(app_name) / DEFAULT_NORDPASS_IMPORT_CSV


def staged_nordpass_csv_warning(ttl_seconds: int = 300, app_name: str = DEFAULT_APP_NAME) -> tuple[Path, str] | None:
    path = default_nordpass_import_csv_path(app_name)
    warning = plaintext_file_warning(path, ttl_seconds)
    if warning is None:
        return None
    return path, warning


def delete_file(path: Path) -> bool:
    return secure_delete_file(path)


def secure_delete_file(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        size = path.stat().st_size
        with path.open("r+b") as handle:
            handle.write(b"\x00" * size)
            handle.flush()
    except OSError:
        pass
    path.unlink()
    return True
