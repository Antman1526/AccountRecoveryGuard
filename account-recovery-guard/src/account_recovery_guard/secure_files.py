from __future__ import annotations

from pathlib import Path
from time import time


def csv_expiration_warning(age_seconds: float, ttl_seconds: int = 300) -> str | None:
    if age_seconds > ttl_seconds:
        return f"Plaintext CSV is older than {ttl_seconds} seconds; import or delete it now."
    return None


def plaintext_file_warning(path: Path, ttl_seconds: int = 300) -> str | None:
    if not path.exists():
        return None
    return csv_expiration_warning(time() - path.stat().st_mtime, ttl_seconds)


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
