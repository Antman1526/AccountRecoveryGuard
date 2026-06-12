from __future__ import annotations

import os
import sys
from pathlib import Path


def user_state_dir(app_name: str) -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / app_name


def user_log_path(app_name: str) -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / app_name
    return user_state_dir(app_name) / "logs"
