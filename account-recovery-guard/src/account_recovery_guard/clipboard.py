from __future__ import annotations

import platform
import subprocess
import threading
from shutil import which


def copy_text(text: str, clear_after_seconds: int = 60) -> bool:
    copied = _copy_once(text)
    if copied and clear_after_seconds > 0:
        timer = threading.Timer(clear_after_seconds, _copy_once, args=("",))
        timer.daemon = True
        timer.start()
    return copied


def _copy_once(text: str) -> bool:
    system = platform.system().lower()
    if system == "darwin" and which("pbcopy"):
        subprocess.run(["pbcopy"], input=text, text=True, check=False)
        return True
    if system == "windows" and which("clip"):
        subprocess.run(["clip"], input=text, text=True, check=False)
        return True
    if which("xclip"):
        subprocess.run(["xclip", "-selection", "clipboard"], input=text, text=True, check=False)
        return True
    if which("wl-copy"):
        subprocess.run(["wl-copy"], input=text, text=True, check=False)
        return True
    return False
