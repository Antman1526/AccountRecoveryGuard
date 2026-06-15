from __future__ import annotations

from dataclasses import dataclass
import shlex
from typing import Any
from urllib.parse import urlsplit, urlunsplit

SECRET_REFERENCE_KEYS = {
    "hibp_secret",
    "password_secret",
    "secret_name",
    "token_secret_name",
}

SECRET_REFERENCE_PLACEHOLDER = "<save-secret-in-os-credential-store-first>"
URL_TOKEN_KEYS = {"reset_link"}
DIRECT_SECRET_FILE_KEYS = {"client_secret_file"}


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
class SafetyBoundaryRow:
    title: str
    status: str
    detail: str
    tone: str = "safe"


@dataclass(frozen=True)
class ReviewPlan:
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
        parts.extend([flag, safe_preview_value(key, value)])
    return " ".join(shlex.quote(part) for part in parts)


def safe_preview_value(key: str, value: Any) -> str:
    text = str(value)
    if key in SECRET_REFERENCE_KEYS and looks_like_direct_secret(text):
        return SECRET_REFERENCE_PLACEHOLDER
    if key in DIRECT_SECRET_FILE_KEYS and looks_like_pasted_secret_file(text):
        return SECRET_REFERENCE_PLACEHOLDER
    if key in URL_TOKEN_KEYS:
        return redact_url_tokens_for_preview(text)
    return text


def redact_url_tokens_for_preview(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return "<redacted-reset-link>"
    query = "<redacted>" if parts.query else ""
    fragment = "<redacted>" if parts.fragment else ""
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, fragment))


def looks_like_pasted_secret_file(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    lowered = text.lower()
    secret_markers = (
        '"client_secret"',
        "'client_secret'",
        "client_secret=",
        "client-secret=",
        "private_key",
        "refresh_token",
        "access_token",
    )
    return any(marker in lowered for marker in secret_markers)


def looks_like_direct_secret(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    compact = "".join(text.split())
    if _looks_like_google_app_password(text):
        return True
    if any(ch.isspace() for ch in text):
        return True
    if "=" in text:
        return True
    classes = sum(
        (
            any(ch.islower() for ch in text),
            any(ch.isupper() for ch in text),
            any(ch.isdigit() for ch in text),
            any(not ch.isalnum() for ch in text),
        )
    )
    return len(compact) >= 12 and classes >= 3


def _looks_like_google_app_password(value: str) -> bool:
    compact = "".join(value.split())
    return len(compact) == 16 and compact.isalnum()


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
            detail="Classify risky mailbox signals and build an exposure review plan from authorized mailbox evidence and optional HIBP email lookup.",
            command="discover-imap, breach-check, exposure-plan",
        ),
        RecoveryStage(
            title="Review and rotate",
            status="human approval",
            detail="After a confirmed risk signal, generate five strong choices, open the reset workflow, and copy only the selected password.",
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
        "Review the account evidence first, then rotate only if the signal supports it.",
        "Update Bitwarden first, import the staged NordPass CSV, then verify both vaults match.",
        "Delete staged CSV files after import because NordPass uses a plaintext import/export workflow.",
    ]


def password_exposure_prompt_lines(count: int | None = None) -> list[str]:
    lines = [
        "Check an old password you may have reused. The app uses the free HIBP k-anonymous range check.",
        "Do not check a new generated password; save new passwords directly in your vaults.",
        "The plaintext password is cleared from the field and is never logged; only a hash prefix is sent.",
        "If you check the same password again during this app session, the app reuses the local result instead of sending it again.",
        "This does not search the whole web, dark-web dumps, private forums, or unsafe paste sites.",
    ]
    if count is None:
        return lines
    if count > 0:
        return lines + ["If it is found, rotate only the accounts where you reused that password."]
    return lines + ["If it is not found, review suspicious mailbox alerts and rotate only if the official service flow shows risk."]


def reused_password_triage_steps(count: int | None = None) -> list[str]:
    if not count or count <= 0:
        return []
    return [
        "Do not paste this password into search engines, paste sites, dark-web lookups, or random breach-check pages.",
        "Use your own password manager search, reuse report, or memory to list accounts where this old password was used.",
        "Start with email, banking, cloud storage, password managers, and any account with a suspicious mailbox alert.",
        "Rotate one account at a time on the official site or app, then save a unique generated password and verify sign-in.",
        "If helping a second person, keep them present while deciding which of their accounts used that password.",
    ]


def password_exposure_result_summary(count: int | None = None) -> str:
    if count is None:
        return (
            "Known: no password has been checked yet. Unknown: the app cannot infer where a reused password "
            "was used until you compare it with your own accounts."
        )
    if count > 0:
        return (
            f"Known: this old password appears {count} time(s) in HIBP Pwned Passwords. Unknown: the app "
            "does not know every site where you reused it. Next: Review where you reused it, then rotate only "
            "those accounts one at a time."
        )
    return (
        "Known: this password was not found in HIBP Pwned Passwords. Unknown: private breach dumps and "
        "sources outside HIBP may still exist. Next: keep this password unique or replace it if any mailbox "
        "alert looks suspicious."
    )


def password_exposure_display_message(count: int | None, service_message: str) -> str:
    summary = password_exposure_result_summary(count)
    message = " ".join(service_message.strip().split())
    triage_steps = reused_password_triage_steps(count)
    triage = ""
    if triage_steps:
        triage = "\n\nReused password triage:\n" + "\n".join(
            f"{index}. {step}" for index, step in enumerate(triage_steps, start=1)
        )
    if not message:
        return f"{summary}{triage}"
    return f"{message}\n\n{summary}{triage}"


def password_exposure_ready(password_text: str, confirmed_old_or_reused: bool) -> bool:
    return bool(password_text) and confirmed_old_or_reused


def scan_start_ready(
    scan_permission_confirmed: bool,
    second_person_required: bool = False,
    second_person_confirmed: bool = False,
) -> bool:
    if not scan_permission_confirmed:
        return False
    if second_person_required and not second_person_confirmed:
        return False
    return True


def password_exposure_blocked_message(password_text: str, confirmed_old_or_reused: bool) -> str:
    if not password_text:
        return "Enter an old or reused password to check. The field will be cleared after the check."
    if not confirmed_old_or_reused:
        return "Confirm this is an old or reused password before checking. Do not check a new generated password."
    return "Ready for the free HIBP k-anonymous password check."


def rotation_copy_confirmation_text(reset_link_is_trusted: bool) -> str:
    if reset_link_is_trusted:
        return "I am on the verified reset page or the official app."
    return "I am on the official website or app, not a suspicious email link."


def rotation_copy_ready(page_confirmed: bool, selected_password_ready: bool) -> bool:
    return page_confirmed and selected_password_ready


def vault_sync_confirmation_texts() -> tuple[str, str]:
    return (
        "I changed this password on the official website or app.",
        "I confirmed the new password works by signing in or completing the provider's success step.",
    )


def vault_sync_ready(
    changed_on_service: bool,
    sign_in_confirmed: bool,
    selected_password_ready: bool = True,
) -> bool:
    return changed_on_service and sign_in_confirmed and selected_password_ready


def review_scope_lines() -> list[str]:
    return [
        "The review path is mailbox evidence plus the free HIBP k-anonymous password check.",
        "The app does not crawl the whole web, dark-web dumps, private forums, or paste sites for plaintext passwords.",
        "That boundary helps avoid unsafe sources, unreliable results, and exposing credentials further.",
        "Start by scanning one authorized mailbox, then rotate only accounts with clear risk signals or reused exposed passwords.",
    ]


def exposure_boundary_rows() -> list[SafetyBoundaryRow]:
    return [
        SafetyBoundaryRow(
            title="What this can check",
            status="review path",
            detail=(
                "Authorized mailbox evidence, likely linked accounts, security alerts, and whether one old or "
                "reused password appears in HIBP Pwned Passwords."
            ),
        ),
        SafetyBoundaryRow(
            title="What this cannot promise",
            status="not all sites",
            detail=(
                "No normal app can reliably find every website where a password is exposed. Private breach "
                "datasets, dark-web dumps, criminal forums, and paid intelligence sources are outside this local "
                "review workflow."
            ),
            tone="attention",
        ),
        SafetyBoundaryRow(
            title="How it avoids extra harm",
            status="local first",
            detail=(
                "Plaintext passwords are cleared from masked fields, never logged, and new generated passwords "
                "should not be checked against breach services."
            ),
        ),
        SafetyBoundaryRow(
            title="Best use for 1-2 people",
            status="one at a time",
            detail=(
                "Review one mailbox at a time. Only help a second person when they are present, asked for help, "
                "and can approve the scan."
            ),
        ),
    ]


def build_review_plan(
    scan_summary=None,
    password_exposure_count: int | None = None,
    vault_status=None,
) -> ReviewPlan:
    csv_cleanup_needed = bool(getattr(vault_status, "requires_csv_cleanup", False))
    if scan_summary is None:
        return ReviewPlan(
            headline="Start with one authorized mailbox",
            known="No mailbox scan has run yet.",
            unknown="The app cannot know which accounts need attention until it reviews authorized account and security emails.",
            next_action="Connect Gmail, Outlook, or another email provider and run the local scan.",
            guardrail="Stay on the review path: mailbox evidence plus the free HIBP k-anonymous password check.",
            tone="attention",
        )

    if csv_cleanup_needed:
        return ReviewPlan(
            headline="Finish vault cleanup",
            known="A NordPass import CSV was staged for manual import.",
            unknown="The app cannot prove NordPass matches Bitwarden until you import the CSV, export from NordPass, and verify drift.",
            next_action="Import the CSV into NordPass, verify both vaults, then delete the staged CSV.",
            guardrail="The CSV contains plaintext passwords because NordPass import requires it; keep it local and remove it after import.",
            tone="attention",
        )

    if password_exposure_count is not None and password_exposure_count > 0:
        return ReviewPlan(
            headline="A reused password needs attention",
            known="The checked old password appears in HIBP Pwned Passwords.",
            unknown="The app does not know every account where you used that password.",
            next_action="Rotate only the accounts where you reused it, starting with the highest-risk alert or most important account.",
            guardrail="This is not a whole-web search; it is a free k-anonymous breach-corpus check.",
            tone="attention",
        )

    if scan_summary.accounts_needing_attention > 0:
        service = scan_summary.recommended.service_name.title() if scan_summary.recommended else "the first account"
        return ReviewPlan(
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
    return ReviewPlan(
        headline="No urgent alerts found",
        known=known,
        unknown="This does not prove every account is risk-free or that private breach data does not exist.",
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
