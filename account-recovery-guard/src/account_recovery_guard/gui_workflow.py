from __future__ import annotations

from dataclasses import dataclass
import shlex
from typing import Any


@dataclass(frozen=True)
class RecoveryStage:
    title: str
    status: str
    detail: str
    command: str


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


def recovery_stages() -> list[RecoveryStage]:
    return [
        RecoveryStage(
            title="Connect mailboxes",
            status="guided",
            detail="Use Gmail, Outlook, or IMAP with OAuth/app passwords stored in the OS credential store.",
            command="scan-gmail, scan-graph, scan-imap",
        ),
        RecoveryStage(
            title="Find risky accounts",
            status="automated",
            detail="Classify risky mailbox signals and build a safe exposure plan from breach intelligence.",
            command="discover-imap, breach-check, exposure-plan",
        ),
        RecoveryStage(
            title="Rotate passwords",
            status="human approval",
            detail="Generate five strong choices, open the reset workflow, and copy only the selected password.",
            command="rotate",
        ),
        RecoveryStage(
            title="Sync both vaults",
            status="manual",
            detail="Write Bitwarden through the official bw CLI and stage a NordPass import CSV for their supported import flow.",
            command="write-vaults",
        ),
        RecoveryStage(
            title="Verify and clean up",
            status="required",
            detail="Compare Bitwarden and NordPass exports, flag drift, and remove plaintext NordPass CSV staging files.",
            command="verify-sync, csv-status",
        ),
    ]


def suggested_next_actions() -> list[str]:
    return [
        "Start with a mailbox scan so the app can identify risky account alerts.",
        "Rotate one account at a time and choose from five generated passwords.",
        "Update Bitwarden first, import the staged NordPass CSV, then verify both vaults match.",
        "Delete staged CSV files after import because NordPass uses a plaintext import/export workflow.",
    ]
