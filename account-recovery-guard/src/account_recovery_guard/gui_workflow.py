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


@dataclass(frozen=True)
class ProtectionPlan:
    headline: str
    known: str
    unknown: str
    next_action: str
    guardrail: str
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


def build_protection_plan(
    scan_summary=None,
    password_exposure_count: int | None = None,
    vault_status=None,
) -> ProtectionPlan:
    csv_cleanup_needed = bool(getattr(vault_status, "requires_csv_cleanup", False))
    if scan_summary is None:
        return ProtectionPlan(
            headline="Start with one authorized mailbox",
            known="No mailbox scan has run yet.",
            unknown="The app cannot know which accounts need attention until it reviews authorized account and security emails.",
            next_action="Connect Gmail, Outlook, or another email provider and run the local scan.",
            guardrail="Stay on the safe path: mailbox evidence plus the free HIBP k-anonymous password check.",
            tone="attention",
        )

    if csv_cleanup_needed:
        return ProtectionPlan(
            headline="Finish vault cleanup",
            known="A NordPass import CSV was staged for manual import.",
            unknown="The app cannot prove NordPass matches Bitwarden until you import the CSV, export from NordPass, and verify drift.",
            next_action="Import the CSV into NordPass, verify both vaults, then delete the staged CSV.",
            guardrail="The CSV contains plaintext passwords because NordPass import requires it; keep it local and remove it after import.",
            tone="attention",
        )

    if password_exposure_count is not None and password_exposure_count > 0:
        return ProtectionPlan(
            headline="A reused password needs attention",
            known="The checked old password appears in HIBP Pwned Passwords.",
            unknown="The app does not know every account where you used that password.",
            next_action="Rotate only the accounts where you reused it, starting with the highest-risk alert or most important account.",
            guardrail="This is not a whole-web search; it is a free k-anonymous breach-corpus check.",
            tone="attention",
        )

    if scan_summary.accounts_needing_attention > 0:
        service = scan_summary.recommended.service_name.title() if scan_summary.recommended else "the first account"
        return ProtectionPlan(
            headline="Review the highest-risk alert first",
            known=scan_summary.attention_text,
            unknown="Mailbox alerts are risk signals, not proof that every listed account was taken over.",
            next_action=f"Start with {service}. Confirm activity on the official site, then rotate that one account if needed.",
            guardrail="Use official websites or verified reset links; complete MFA yourself.",
            tone="attention",
        )

    if password_exposure_count == 0:
        known = "No urgent mailbox alerts were found, and the checked password was not found in HIBP Pwned Passwords."
    else:
        known = "No urgent mailbox alerts were found in this scan."
    return ProtectionPlan(
        headline="No urgent alerts found",
        known=known,
        unknown="This does not prove every account is safe or that private breach data does not exist.",
        next_action="Keep passwords unique, check any old reused password, and rescan later if new security emails arrive.",
        guardrail="The app avoids unsafe paste sites, dark-web dumps, private forums, and random pages with plaintext passwords.",
        tone="safe",
    )


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
