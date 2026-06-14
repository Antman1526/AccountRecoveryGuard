from __future__ import annotations

import platform
import subprocess
import threading
from shutil import which


def copy_text(text: str, clear_after_seconds: int = 60) -> bool:
    copied = _copy_once(text)
    if copied and clear_after_seconds > 0:
        timer = threading.Timer(clear_after_seconds, clear_clipboard_if_unchanged, args=(text,))
        timer.daemon = True
        timer.start()
    return copied


def clear_clipboard_if_unchanged(expected_text: str) -> bool:
    current_text = _paste_once()
    if current_text is not None and current_text != expected_text:
        return False
    return _copy_once("")


def _copy_once(text: str) -> bool:
    system = platform.system().lower()
    if system == "darwin":
        return _run_copy_command(["pbcopy"], text)
    if system == "windows":
        return _run_copy_command(["clip"], text)
    if which("xclip"):
        return _run_copy_command(["xclip", "-selection", "clipboard"], text)
    if which("wl-copy"):
        return _run_copy_command(["wl-copy"], text)
    return False


def _paste_once() -> str | None:
    system = platform.system().lower()
    if system == "darwin":
        return _run_paste_command(["pbpaste"])
    if system == "windows":
        return _run_paste_command(["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"])
    if which("xclip"):
        return _run_paste_command(["xclip", "-selection", "clipboard", "-o"])
    if which("wl-paste"):
        return _run_paste_command(["wl-paste", "--no-newline"])
    return None


def _run_copy_command(command: list[str], text: str) -> bool:
    if which(command[0]) is None:
        return False
    try:
        result = subprocess.run(
            command,
            input=text,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _run_paste_command(command: list[str]) -> str | None:
    if which(command[0]) is None:
        return None
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout
