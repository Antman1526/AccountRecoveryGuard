from __future__ import annotations

import shlex
from typing import Any


def build_command_preview(command: str, options: dict[str, Any]) -> str:
    parts = ["account-recovery-guard", command]
    for key, value in options.items():
        flag = "--" + key.replace("_", "-")
        if isinstance(value, bool):
            if value:
                parts.append(flag)
            continue
        if value is None or value == "":
            continue
        parts.extend([flag, str(value)])
    return " ".join(shlex.quote(part) for part in parts)
