from __future__ import annotations

import argparse
import json
from pathlib import Path

from .account_discovery import AccountDiscovery
from .audit import AuditLogger
from .breach_checker import HibpBreachChecker
from .email_scanner import ImapEmailScanner, ImapMailboxConfig
from .models import PasswordCandidate, VaultEntry
from .passwords import PasswordPolicy, fingerprint_password, generate_passphrase, generate_password
from .paths import user_state_dir
from .reset_orchestrator import PasswordResetOrchestrator, open_reset_link
from .rotation import build_rotation_choices
from .secure_store import get_secret, set_secret
from .sync import compare_vault_entries
from .vaults import BitwardenVault, NordPassImportVault


def main() -> None:
    parser = argparse.ArgumentParser(prog="arg", description="Local account recovery and password rotation assistant.")
    sub = parser.add_subparsers(dest="command", required=True)

    secret = sub.add_parser("secret", help="Store an OS-keychain secret")
    secret.add_argument("name")
    secret.add_argument("value")

    scan = sub.add_parser("scan-imap", help="Scan an IMAP mailbox for risky account alerts")
    scan.add_argument("--host", required=True)
    scan.add_argument("--username", required=True)
    scan.add_argument("--secret-name", required=True, help="Keychain secret containing the IMAP password/app password")
    scan.add_argument("--days", type=int, default=30)
    scan.add_argument("--folder", default="INBOX")
    scan.add_argument("--json", action="store_true")

    discover = sub.add_parser("discover-imap", help="Discover likely linked accounts from mailbox signals")
    discover.add_argument("--host", required=True)
    discover.add_argument("--username", required=True)
    discover.add_argument("--secret-name", required=True)
    discover.add_argument("--days", type=int, default=365)
    discover.add_argument("--folder", default="INBOX")
    discover.add_argument("--json", action="store_true")

    breach = sub.add_parser("breach-check", help="Check an email address against Have I Been Pwned")
    breach.add_argument("--email", required=True)
    breach.add_argument("--hibp-secret", required=True, help="OS-keychain secret containing the HIBP API key")
    breach.add_argument("--json", action="store_true")

    generate = sub.add_parser("generate-password", help="Generate a replacement password")
    generate.add_argument("--length", type=int, default=32)
    generate.add_argument("--passphrase", action="store_true")
    generate.add_argument("--words", type=int, default=6)

    workflow = sub.add_parser("workflow", help="Create a manual reset workflow from a finding JSON file")
    workflow.add_argument("finding_json")
    workflow.add_argument("--open", action="store_true", help="Open extracted reset link in Playwright for manual completion")

    rotate = sub.add_parser("rotate", help="Pick from five passwords, complete reset manually, then update vaults")
    rotate.add_argument("--service", required=True)
    rotate.add_argument("--username", required=True)
    rotate.add_argument("--url")
    rotate.add_argument("--reset-link")
    rotate.add_argument("--length", type=int, default=32)
    rotate.add_argument("--nordpass-csv", default=str(default_data_path() / "nordpass-import.csv"))
    rotate.add_argument("--skip-bitwarden", action="store_true")
    rotate.add_argument("--open", action="store_true", help="Open reset link in Playwright before vault write")

    write = sub.add_parser("write-vaults", help="Write Bitwarden and stage NordPass import CSV")
    write.add_argument("--service", required=True)
    write.add_argument("--username", required=True)
    write.add_argument("--url")
    write.add_argument("--password-secret", required=True, help="Keychain secret containing the new password")
    write.add_argument("--note", default="Rotated by Account Recovery Guard")
    write.add_argument("--nordpass-csv", default=str(default_data_path() / "nordpass-import.csv"))
    write.add_argument("--skip-bitwarden", action="store_true")

    verify = sub.add_parser("verify-sync", help="Compare Bitwarden entry with a NordPass export CSV")
    verify.add_argument("--service", required=True)
    verify.add_argument("--username", required=True)
    verify.add_argument("--url")
    verify.add_argument("--nordpass-export", required=True)

    args = parser.parse_args()
    if args.command == "secret":
        set_secret(args.name, args.value)
        print(f"Stored secret '{args.name}' in the OS credential store.")
    elif args.command == "scan-imap":
        _scan_imap(args)
    elif args.command == "discover-imap":
        _discover_imap(args)
    elif args.command == "breach-check":
        _breach_check(args)
    elif args.command == "generate-password":
        if args.passphrase:
            print(generate_passphrase(word_count=args.words))
        else:
            print(generate_password(PasswordPolicy(length=args.length)))
    elif args.command == "workflow":
        _workflow(args)
    elif args.command == "rotate":
        _rotate(args)
    elif args.command == "write-vaults":
        _write_vaults(args)
    elif args.command == "verify-sync":
        _verify_sync(args)


def _scan_imap(args: argparse.Namespace) -> None:
    password = get_secret(args.secret_name)
    if not password:
        raise SystemExit(f"Secret '{args.secret_name}' was not found. Store it with: arg secret {args.secret_name} <value>")
    findings = ImapEmailScanner(
        ImapMailboxConfig(
            host=args.host,
            username=args.username,
            password=password,
            days_back=args.days,
            folder=args.folder,
        )
    ).scan()
    AuditLogger().write("email_scan", host=args.host, username=args.username, days=args.days, finding_count=len(findings))
    if args.json:
        print(json.dumps([_finding_to_dict(finding) for finding in findings], indent=2, default=str))
        return
    for finding in findings:
        print(f"[{finding.severity}] {finding.service_name} via {finding.sender_domain}: {finding.subject}")
        if finding.reset_link:
            print(f"  reset: {finding.reset_link}")
        print(f"  reasons: {', '.join(finding.reasons)}")


def _discover_imap(args: argparse.Namespace) -> None:
    password = get_secret(args.secret_name)
    if not password:
        raise SystemExit(f"Secret '{args.secret_name}' was not found.")
    scanner = ImapEmailScanner(
        ImapMailboxConfig(
            host=args.host,
            username=args.username,
            password=password,
            days_back=args.days,
            folder=args.folder,
        )
    )
    accounts = AccountDiscovery().discover(scanner.fetch_messages())
    AuditLogger().write("account_discovery", host=args.host, username=args.username, days=args.days, account_count=len(accounts))
    if args.json:
        print(json.dumps([account.__dict__ for account in accounts], indent=2))
        return
    for account in accounts:
        print(f"[{account.confidence}] {account.service_name} ({account.sender_domain}) messages={account.message_count}")
        print(f"  reasons: {', '.join(account.reasons)}")


def _breach_check(args: argparse.Namespace) -> None:
    api_key = get_secret(args.hibp_secret)
    if not api_key:
        raise SystemExit(f"Secret '{args.hibp_secret}' was not found.")
    breaches = HibpBreachChecker(api_key).breaches_for_account(args.email)
    AuditLogger().write("hibp_breach_check", email=args.email, breach_count=len(breaches))
    if args.json:
        print(json.dumps({"email": args.email, "breaches": [breach.__dict__ for breach in breaches]}, indent=2))
        return
    if not breaches:
        print(f"No HIBP breaches returned for {args.email}.")
        return
    print(f"HIBP returned {len(breaches)} breach(es) for {args.email}:")
    for breach in breaches:
        print(f"  - {breach.name}")


def _workflow(args: argparse.Namespace) -> None:
    data = json.loads(Path(args.finding_json).read_text(encoding="utf-8"))
    finding = _finding_from_dict(data)
    plan = PasswordResetOrchestrator().build_workflow(finding)
    for index, step in enumerate(plan.steps, start=1):
        print(f"{index}. {step}")
    if args.open and plan.reset_link:
        open_reset_link(plan.reset_link)


def _rotate(args: argparse.Namespace) -> None:
    choices = build_rotation_choices(args.service, args.username, args.url, count=5, length=args.length)
    print("Generated five local password candidates. They are shown once; do not paste them into chat or logs.")
    for index, candidate in enumerate(choices, start=1):
        print(f"{index}. {candidate.password}")
    selection = input("Select password 1-5, or q to abort: ").strip().lower()
    if selection == "q":
        raise SystemExit("Rotation aborted.")
    try:
        selected = choices[int(selection) - 1]
    except (ValueError, IndexError) as exc:
        raise SystemExit("Invalid password selection.") from exc
    if args.open and args.reset_link:
        open_reset_link(args.reset_link)
    confirmation = input("After changing the password on the service, type ROTATED to update vaults: ").strip()
    if confirmation != "ROTATED":
        raise SystemExit("Vault write skipped because rotation was not confirmed.")
    if not args.skip_bitwarden:
        entry = BitwardenVault().upsert_login(selected)
        AuditLogger().write("bitwarden_upsert", service=args.service, username=args.username, url=args.url)
        print(f"Bitwarden updated: {entry.service_name} / {entry.username} / {entry.password_fingerprint}")
    csv_path = NordPassImportVault().stage_import([selected], Path(args.nordpass_csv))
    AuditLogger().write("nordpass_import_staged", service=args.service, username=args.username, path=str(csv_path))
    print(f"NordPass import CSV staged at: {csv_path}")
    print("Import the CSV into NordPass, export NordPass, then run verify-sync.")


def _write_vaults(args: argparse.Namespace) -> None:
    password = get_secret(args.password_secret)
    if not password:
        raise SystemExit(f"Secret '{args.password_secret}' was not found.")
    candidate = PasswordCandidate(
        service_name=args.service,
        username=args.username,
        url=args.url,
        password=password,
        note=args.note,
    )
    if not args.skip_bitwarden:
        entry = BitwardenVault().upsert_login(candidate)
        AuditLogger().write("bitwarden_upsert", service=args.service, username=args.username, url=args.url)
        print(f"Bitwarden updated: {entry.service_name} / {entry.username} / {entry.password_fingerprint}")
    csv_path = NordPassImportVault().stage_import([candidate], Path(args.nordpass_csv))
    AuditLogger().write("nordpass_import_staged", service=args.service, username=args.username, path=str(csv_path))
    print(f"NordPass import CSV staged at: {csv_path}")
    print("Import this CSV in NordPass, then delete it after verification.")


def _verify_sync(args: argparse.Namespace) -> None:
    bitwarden_entry = BitwardenVault().read_entry(args.service, args.username, args.url)
    if not bitwarden_entry:
        raise SystemExit("No matching Bitwarden entry found.")
    nordpass_entries = NordPassImportVault().read_export(Path(args.nordpass_export))
    matching = next(
        (
            entry
            for entry in nordpass_entries
            if entry.service_name == args.service and entry.username == args.username
        ),
        None,
    )
    if not matching:
        matching = VaultEntry(args.service, args.username, args.url, fingerprint_password(""))
    report = compare_vault_entries(bitwarden_entry, matching)
    AuditLogger().write("sync_verified", service=args.service, username=args.username, in_sync=report.in_sync)
    print(json.dumps(report.__dict__, indent=2))


def _finding_to_dict(finding) -> dict[str, object]:
    return {
        "service_name": finding.service_name,
        "sender_domain": finding.sender_domain,
        "sender": finding.sender,
        "subject": finding.subject,
        "timestamp": finding.timestamp.isoformat() if finding.timestamp else None,
        "severity": finding.severity,
        "reasons": finding.reasons,
        "reset_link": finding.reset_link,
        "message_id": finding.message_id,
    }


def _finding_from_dict(data: dict[str, object]):
    from datetime import datetime

    from .models import CompromisedAccountFinding

    timestamp = data.get("timestamp")
    parsed_timestamp = datetime.fromisoformat(str(timestamp)) if timestamp else None
    return CompromisedAccountFinding(
        service_name=str(data.get("service_name") or "unknown"),
        sender_domain=str(data.get("sender_domain") or ""),
        sender=str(data.get("sender") or ""),
        subject=str(data.get("subject") or ""),
        timestamp=parsed_timestamp,
        severity=str(data.get("severity") or "medium"),  # type: ignore[arg-type]
        reasons=[str(reason) for reason in data.get("reasons", [])],
        reset_link=str(data.get("reset_link")) if data.get("reset_link") else None,
        message_id=str(data.get("message_id")) if data.get("message_id") else None,
    )


def default_data_path() -> Path:
    path = user_state_dir("account-recovery-guard")
    path.mkdir(parents=True, exist_ok=True)
    return path


if __name__ == "__main__":
    main()
