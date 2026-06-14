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


@dataclass(frozen=True)
class ReadinessRow:
    title: str
    status: str
    detail: str
    tone: str = "safe"


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


def password_exposure_prompt_lines(count: int | None = None) -> list[str]:
    lines = [
        "Check an old password you may have reused. The app uses the free HIBP k-anonymous range check.",
        "Do not check a new generated password; save new passwords directly in your vaults.",
        "The plaintext password is cleared from the field and is never logged; only a hash prefix is sent.",
        "This does not search the whole web, dark-web dumps, private forums, or unsafe paste sites.",
    ]
    if count is None:
        return lines
    if count > 0:
        return lines + ["If it is found, rotate only the accounts where you reused that password."]
    return lines + ["If it is not found, still rotate accounts with suspicious mailbox alerts."]


def safe_recovery_scope_lines() -> list[str]:
    return [
        "The safe path is mailbox evidence plus the free HIBP k-anonymous password check.",
        "The app does not crawl the whole web, dark-web dumps, private forums, or paste sites for plaintext passwords.",
        "That boundary protects you from unsafe sources, unreliable results, and exposing credentials further.",
        "Start by scanning one authorized mailbox, then rotate only accounts with clear risk signals or reused exposed passwords.",
    ]


def consumer_readiness_rows(checks) -> list[ReadinessRow]:
    check_by_name = {check.name: check for check in checks}
    rows = []
    for name in (
        "OS credential store",
        "Bitwarden CLI",
        "Desktop GUI",
        "Reset browser helper",
        "Free password exposure check",
        "Staged NordPass CSV cleanup",
        "Bitwarden session",
        "NordPass sync",
        "HIBP email-breach lookup",
    ):
        check = check_by_name.get(name)
        if check is None:
            continue
        rows.append(
            ReadinessRow(
                title=name,
                status=_readiness_status_label(check.status),
                detail=check.detail,
                tone=_readiness_tone(check.status),
            )
        )
    return rows


def _readiness_status_label(status: str) -> str:
    return {
        "ready": "ready",
        "action_needed": "needs setup",
        "manual_required": "manual",
        "paid_optional": "paid optional",
    }.get(status, "review")


def _readiness_tone(status: str) -> str:
    if status == "action_needed":
        return "attention"
    return "safe"
