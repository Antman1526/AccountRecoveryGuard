from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .account_discovery import AccountDiscovery
from .audit import AuditLogger
from .breach_checker import HibpBreachChecker
from .clipboard import copy_text
from .domain_safety import safe_reset_link_matches_domain
from .email_scanner import ImapEmailScanner, ImapMailboxConfig
from .exposure import ExposureReport, build_exposure_report
from .gui import main as gui_main
from .live_vault_test import build_live_test_candidate, preflight, summarize_preflight
from .models import PasswordCandidate, VaultEntry
from .passkeys import passkey_guidance
from .passwords import PasswordPolicy, fingerprint_password, generate_passphrase, generate_password
from .paths import user_state_dir
from .readiness import build_readiness_checks
from .reset_orchestrator import PasswordResetOrchestrator, ResetLinkSafetyError, open_reset_link
from .rotation import build_rotation_choices, summarize_rotation_choices
from .secure_files import default_nordpass_import_csv_path, delete_file, plaintext_file_warning
from .sync import build_vault_dashboard, compare_vault_entries
from .vaults import BitwardenVault, NordPassImportVault


def main() -> None:
    parser = argparse.ArgumentParser(prog="arg", description="Local account recovery and password rotation assistant.")
    sub = parser.add_subparsers(dest="command", required=True)

    secret = sub.add_parser("secret", help="Store an OS-keychain secret")
    secret.add_argument("name")
    secret.add_argument(
        "value",
        nargs="?",
        help="Secret value. Safer: omit this and enter the secret at the hidden prompt.",
    )
    secret.add_argument("--stdin", action="store_true", help="Read the secret value from stdin for scripted setup")

    sub.add_parser("gui", help="Launch the desktop dashboard")

    setup_check = sub.add_parser("setup-check", help="Show free setup readiness and paid-optional blockers")
    setup_check.add_argument("--hibp-secret", help="Optional HIBP key secret name to check without revealing the key")
    setup_check.add_argument("--json", action="store_true")

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

    scan_gmail_app_password = sub.add_parser(
        "scan-gmail-app-password",
        help="Scan Gmail with a Google app password stored in the OS credential store",
    )
    scan_gmail_app_password.add_argument("--username", required=True)
    scan_gmail_app_password.add_argument("--secret-name", required=True, help="Keychain secret containing the Gmail app password")
    scan_gmail_app_password.add_argument("--days", type=int, default=30)
    scan_gmail_app_password.add_argument(
        "--recent-inbox",
        action="store_true",
        help="Scan only recent INBOX messages. By default this scans Gmail All Mail.",
    )
    scan_gmail_app_password.add_argument("--json", action="store_true")

    scan_gmail = sub.add_parser("scan-gmail", help="Scan Gmail with OAuth and the Gmail API")
    scan_gmail.add_argument("--client-secret-file", required=True)
    scan_gmail.add_argument("--token-secret-name", default="gmail-oauth-token")
    scan_gmail.add_argument("--days", type=int, default=30)
    scan_gmail.add_argument("--json", action="store_true")

    scan_graph = sub.add_parser("scan-graph", help="Scan Outlook/Microsoft 365 with Microsoft Graph device-code auth")
    scan_graph.add_argument("--tenant-id", default="common")
    scan_graph.add_argument("--client-id", required=True)
    scan_graph.add_argument("--token-secret-name", default="graph-oauth-token")
    scan_graph.add_argument("--days", type=int, default=30)
    scan_graph.add_argument("--json", action="store_true")

    breach = sub.add_parser("breach-check", help="Check an email address against Have I Been Pwned")
    breach.add_argument("--email", required=True)
    breach.add_argument("--hibp-secret", required=True, help="OS-keychain secret containing the HIBP API key")
    breach.add_argument(
        "--allow-paid-email-lookup",
        action="store_true",
        help="Required confirmation because HIBP breached-account lookup requires a paid API key and sends the email address to HIBP",
    )
    breach.add_argument("--json", action="store_true")

    pwned_password = sub.add_parser("pwned-password", help="Check a password against the free HIBP Pwned Passwords k-anonymity API")
    pwned_password.add_argument("--password-secret", required=True)
    pwned_password.add_argument("--hibp-secret", help="Deprecated; not needed for the free Pwned Passwords range API")

    exposure = sub.add_parser(
        "exposure-plan",
        help="Safely combine mailbox findings and HIBP checks into a prioritized password-rotation plan",
    )
    exposure.add_argument("--email", required=True)
    exposure.add_argument("--hibp-secret", help="Optional OS-keychain secret containing a paid HIBP key for email breach lookup")
    exposure.add_argument(
        "--allow-paid-email-lookup",
        action="store_true",
        help="Required with --hibp-secret because HIBP account breach lookup is paid and sends the email address to HIBP",
    )
    exposure.add_argument("--password-secret", help="Optional OS-keychain secret containing a password to check with HIBP k-anonymity")
    exposure.add_argument("--accounts-json", help="Optional JSON output from discover-imap")
    exposure.add_argument("--findings-json", help="Optional JSON output from scan-imap, scan-gmail-app-password, scan-gmail, or scan-graph")
    exposure.add_argument("--json", action="store_true")

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
    rotate.add_argument("--nordpass-csv", default=str(default_nordpass_import_csv_path()))
    rotate.add_argument("--skip-bitwarden", action="store_true")
    rotate.add_argument("--open", action="store_true", help="Open reset link in Playwright before vault write")
    rotate.add_argument("--reveal-all", action="store_true", help="Unsafe: print every generated plaintext choice")
    rotate.add_argument("--copy-selected", action="store_true", help="Copy selected password to clipboard and clear it after 60 seconds")

    write = sub.add_parser("write-vaults", help="Write Bitwarden and stage NordPass import CSV")
    write.add_argument("--service", required=True)
    write.add_argument("--username", required=True)
    write.add_argument("--url")
    write.add_argument("--password-secret", required=True, help="Keychain secret containing the new password")
    write.add_argument("--note", default="Rotated by Account Recovery Guard")
    write.add_argument("--nordpass-csv", default=str(default_nordpass_import_csv_path()))
    write.add_argument("--skip-bitwarden", action="store_true")

    verify = sub.add_parser("verify-sync", help="Compare Bitwarden entry with a NordPass export CSV")
    verify.add_argument("--service", required=True)
    verify.add_argument("--username", required=True)
    verify.add_argument("--url")
    verify.add_argument("--nordpass-export", required=True)

    dashboard = sub.add_parser("vault-dashboard", help="Show all Bitwarden/NordPass drift rows from export files")
    dashboard.add_argument("--bitwarden-export", required=True)
    dashboard.add_argument("--nordpass-export", required=True)

    live = sub.add_parser("vault-live-test", help="Safely test Bitwarden write and NordPass import staging with a marked test entry")
    live.add_argument("--username", required=True)
    live.add_argument("--nordpass-csv", default=str(default_data_path() / "arg-live-test-nordpass-import.csv"))
    live.add_argument("--nordpass-export")
    live.add_argument("--skip-bitwarden", action="store_true")
    live.add_argument("--yes", action="store_true", help="Do not prompt; required for non-interactive test writes")

    passkey = sub.add_parser("passkey-guidance", help="Show safe passkey enrollment guidance")
    passkey.add_argument("--service", required=True)

    csv = sub.add_parser("csv-status", help="Warn about or delete staged plaintext NordPass CSV files")
    csv.add_argument(
        "path",
        nargs="?",
        help="CSV path to inspect. Defaults to the app's staged NordPass import CSV.",
    )
    csv.add_argument("--ttl-seconds", type=int, default=300)
    csv.add_argument("--delete", action="store_true")

    args = parser.parse_args()
    if args.command == "secret":
        _set_secret(args.name, _secret_value_from_args(args))
        print(f"Stored secret '{args.name}' in the OS credential store.")
    elif args.command == "gui":
        raise SystemExit(gui_main())
    elif args.command == "setup-check":
        _setup_check(args)
    elif args.command == "scan-imap":
        _scan_imap(args)
    elif args.command == "discover-imap":
        _discover_imap(args)
    elif args.command == "scan-gmail-app-password":
        _scan_gmail_app_password(args)
    elif args.command == "scan-gmail":
        from .oauth_mail import GmailApiMailProvider, GmailOAuthConfig

        provider = GmailApiMailProvider(GmailOAuthConfig(args.client_secret_file, args.token_secret_name))
        _classify_messages(provider.fetch_messages(args.days), args)
    elif args.command == "scan-graph":
        from .oauth_mail import GraphOAuthConfig, MicrosoftGraphMailProvider

        provider = MicrosoftGraphMailProvider(GraphOAuthConfig(args.tenant_id, args.client_id, args.token_secret_name))
        _classify_messages(provider.fetch_messages(args.days), args)
    elif args.command == "breach-check":
        _breach_check(args)
    elif args.command == "pwned-password":
        _pwned_password(args)
    elif args.command == "exposure-plan":
        _exposure_plan(args)
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
    elif args.command == "vault-dashboard":
        _vault_dashboard(args)
    elif args.command == "vault-live-test":
        _vault_live_test(args)
    elif args.command == "passkey-guidance":
        for step in passkey_guidance(args.service):
            print(f"- {step}")
    elif args.command == "csv-status":
        _csv_status(args)


def get_secret(name: str) -> str | None:
    from .secure_store import get_secret as read_secret

    return read_secret(name)


def _set_secret(name: str, value: str) -> None:
    from .secure_store import set_secret

    set_secret(name, value)


def _secret_value_from_args(args: argparse.Namespace) -> str:
    if args.stdin and args.value is not None:
        raise SystemExit("Use either a positional secret value or --stdin, not both.")
    if args.stdin:
        value = sys.stdin.read().rstrip("\n")
    elif args.value is not None:
        value = args.value
    else:
        value = getpass.getpass("Secret value (input hidden): ")
    if not value:
        raise SystemExit("Secret value cannot be empty.")
    return value


def _scan_imap(args: argparse.Namespace) -> None:
    password = get_secret(args.secret_name)
    if not password:
        raise SystemExit(f"Secret '{args.secret_name}' was not found. Store it with: arg secret {args.secret_name}")
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
    _print_findings(findings, args.json)


def _setup_check(args: argparse.Namespace) -> None:
    checks = build_readiness_checks(args.hibp_secret)
    AuditLogger().write("setup_check", check_count=len(checks))
    if args.json:
        print(json.dumps([check.__dict__ for check in checks], indent=2))
        return
    print("Free setup readiness")
    for check in checks:
        print(f"- [{check.status}] {check.name}: {check.detail}")


def _classify_messages(messages, args: argparse.Namespace) -> None:
    from .email_scanner import EmailClassifier

    classifier = EmailClassifier()
    findings = [finding for message in messages if (finding := classifier.classify(message))]
    AuditLogger().write("oauth_email_scan", days=args.days, finding_count=len(findings))
    _print_findings(findings, args.json)


def _print_findings(findings, as_json: bool) -> None:
    if as_json:
        print(json.dumps([_finding_to_dict(finding) for finding in findings], indent=2, default=str))
        return
    for finding in findings:
        print(f"[{finding.severity}] {finding.service_name} via {finding.sender_domain}: {finding.subject}")
        if finding.reset_link:
            print(f"  reset: {_redact_url_for_display(finding.reset_link)}")
        print(f"  reasons: {', '.join(finding.reasons)}")


def _redact_url_for_display(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return "redacted reset link"

    display = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    if parts.query:
        display += "?<redacted>"
    if parts.fragment:
        display += "#<redacted>"
    return display


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


def _scan_gmail_app_password(args: argparse.Namespace) -> None:
    password = get_secret(args.secret_name)
    if not password:
        raise SystemExit(
            f"Secret '{args.secret_name}' was not found. Store a Google app password with: "
            f"arg secret {args.secret_name}"
        )
    scanner = ImapEmailScanner(
        ImapMailboxConfig(
            host="imap.gmail.com",
            username=args.username,
            password="".join(password.split()),
            days_back=max(args.days, 1) if args.recent_inbox else 0,
            folder="INBOX" if args.recent_inbox else "[Gmail]/All Mail",
        )
    )
    findings = scanner.scan()
    AuditLogger().write(
        "gmail_app_password_scan",
        username=args.username,
        scope="recent_inbox" if args.recent_inbox else "all_mail",
        days=args.days,
        finding_count=len(findings),
    )
    _print_findings(findings, args.json)


def _breach_check(args: argparse.Namespace) -> None:
    if not getattr(args, "allow_paid_email_lookup", False):
        raise SystemExit(
            "Free-only mode: breach-check uses the paid HIBP email-breach lookup. Add "
            "--allow-paid-email-lookup only after you decide to use that paid path. The free pwned-password "
            "check does not need this."
        )
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


def _pwned_password(args: argparse.Namespace) -> None:
    password = get_secret(args.password_secret)
    if not password:
        raise SystemExit(f"Secret '{args.password_secret}' was not found.")
    count = HibpBreachChecker().pwned_password_count(password)
    AuditLogger().write("hibp_pwned_password_check", count=count)
    if count:
        print(f"Password appears {count} time(s) in HIBP Pwned Passwords. Do not use it.")
    else:
        print("Password was not found in HIBP Pwned Passwords.")


def _exposure_plan(args: argparse.Namespace) -> None:
    checker = HibpBreachChecker()
    breaches = []
    email_breach_lookup_status = "not_run"
    if args.hibp_secret:
        if not args.allow_paid_email_lookup:
            raise SystemExit(
                "Free-only mode: omit --hibp-secret, or add --allow-paid-email-lookup after you decide to use "
                "the paid HIBP email-breach lookup. The free password check does not need this."
            )
        api_key = get_secret(args.hibp_secret)
        if not api_key:
            raise SystemExit(f"Secret '{args.hibp_secret}' was not found.")
        checker = HibpBreachChecker(api_key)
        breaches = checker.breaches_for_account(args.email)
        email_breach_lookup_status = "checked"
    pwned_count = None
    if args.password_secret:
        password = get_secret(args.password_secret)
        if not password:
            raise SystemExit(f"Secret '{args.password_secret}' was not found.")
        pwned_count = checker.pwned_password_count(password)
    accounts = _load_discovered_accounts(Path(args.accounts_json)) if args.accounts_json else []
    findings = _load_findings(Path(args.findings_json)) if args.findings_json else []
    report = build_exposure_report(args.email, breaches, accounts, findings, pwned_count, email_breach_lookup_status)
    AuditLogger().write(
        "exposure_plan",
        email=args.email,
        breach_count=report.breach_count,
        password_pwned_count=report.password_pwned_count,
        rotation_count=report.rotation_count,
    )
    if args.json:
        print(json.dumps(_exposure_report_to_dict(report), indent=2, default=str))
        return
    _print_exposure_report(report)


def _workflow(args: argparse.Namespace) -> None:
    data = json.loads(Path(args.finding_json).read_text(encoding="utf-8"))
    finding = _finding_from_dict(data)
    plan = PasswordResetOrchestrator().build_workflow(finding)
    for index, step in enumerate(plan.steps, start=1):
        print(f"{index}. {step}")
    if args.open and plan.reset_link and plan.automation_available:
        _open_reset_link_or_exit(plan.reset_link, finding.sender_domain)
    elif args.open and plan.reset_link:
        print("Reset link was not opened because it failed safety checks. Use the official site or app instead.")


def _rotate(args: argparse.Namespace) -> None:
    choices = build_rotation_choices(args.service, args.username, args.url, count=5, length=args.length)
    print("Generated five local password candidates. Passwords are masked by default.")
    summaries = summarize_rotation_choices([candidate.password for candidate in choices])
    for summary, candidate in zip(summaries, choices):
        display = candidate.password if args.reveal_all else summary.display
        print(
            f"{summary.index}. {display}  length={summary.length} "
            f"upper={summary.has_uppercase} lower={summary.has_lowercase} digit={summary.has_digit} symbol={summary.has_symbol}"
        )
    selection = input("Select password 1-5, or q to abort: ").strip().lower()
    if selection == "q":
        raise SystemExit("Rotation aborted.")
    try:
        selected = choices[int(selection) - 1]
    except (ValueError, IndexError) as exc:
        raise SystemExit("Invalid password selection.") from exc
    if args.copy_selected:
        if copy_text(selected.password, clear_after_seconds=60):
            print("Selected password copied to clipboard; clipboard clear scheduled in 60 seconds. Plaintext was not printed.")
        else:
            raise SystemExit("Clipboard copy is not available on this platform/session. Plaintext was not printed; rerun without --copy-selected to reveal manually.")
    else:
        print(f"Selected password: {selected.password}")
    if args.open and args.reset_link and safe_reset_link_matches_domain(args.reset_link, args.url):
        _open_reset_link_or_exit(args.reset_link, args.url)
    elif args.open and args.reset_link:
        print("Reset link was not opened because it failed safety checks. Use the official site or app instead.")
    confirmation = input(
        "After changing the password and confirming the new password works, type ROTATED to update vaults: "
    ).strip()
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


def _open_reset_link_or_exit(reset_link: str, expected_domain_or_url: str | None) -> None:
    try:
        open_reset_link(reset_link, expected_domain_or_url)
    except ResetLinkSafetyError as exc:
        raise SystemExit(f"Reset link was not opened: {exc} Use the official site or app instead.") from exc


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


def _vault_dashboard(args: argparse.Namespace) -> None:
    bitwarden_entries = NordPassImportVault().read_export(Path(args.bitwarden_export))
    nordpass_entries = NordPassImportVault().read_export(Path(args.nordpass_export))
    rows = build_vault_dashboard(bitwarden_entries, nordpass_entries)
    for row in rows:
        print(f"[{row.status}] {row.service_name} / {row.username}")
        if row.differences:
            print(f"  differences: {', '.join(row.differences)}")


def _vault_live_test(args: argparse.Namespace) -> None:
    export_path = Path(args.nordpass_export) if args.nordpass_export else None
    preflight_result = preflight(export_path)
    summary = summarize_preflight(preflight_result)
    blockers = [blocker for blocker in summary.blockers if not (args.skip_bitwarden and blocker in {"Bitwarden CLI not found", "BW_SESSION is not set"})]
    if blockers:
        raise SystemExit("Live vault test blocked: " + "; ".join(blockers))

    candidate = build_live_test_candidate(args.username)
    print(f"Prepared marked test entry: {candidate.service_name} / {candidate.username}")
    if not args.yes:
        confirmation = input("Type LIVE-TEST to write the marked test entry and stage NordPass CSV: ").strip()
        if confirmation != "LIVE-TEST":
            raise SystemExit("Live vault test aborted.")

    if not args.skip_bitwarden:
        entry = BitwardenVault().upsert_login(candidate)
        AuditLogger().write("bitwarden_live_test_upsert", service=entry.service_name, username=entry.username)
        print(f"Bitwarden test entry written: {entry.service_name} / {entry.password_fingerprint}")

    csv_path = NordPassImportVault().stage_import([candidate], Path(args.nordpass_csv))
    AuditLogger().write("nordpass_live_test_import_staged", service=candidate.service_name, username=candidate.username, path=str(csv_path))
    print(f"NordPass test import CSV staged at: {csv_path}")
    print("Import that CSV into NordPass, export NordPass, then run verify-sync for the marked service.")


def _csv_status(args: argparse.Namespace) -> None:
    path = Path(args.path) if args.path else default_nordpass_import_csv_path()
    if args.delete:
        deleted = delete_file(path)
        print("Deleted." if deleted else "File not found.")
        return
    message = plaintext_file_warning(path, args.ttl_seconds) or "CSV is not stale or does not exist."
    print(f"{message} Location: {path}")


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


def _exposure_report_to_dict(report: ExposureReport) -> dict[str, object]:
    return {
        "email_address": report.email_address,
        "breach_count": report.breach_count,
        "email_breach_lookup_status": report.email_breach_lookup_status,
        "password_pwned_count": report.password_pwned_count,
        "rotation_count": report.rotation_count,
        "safety_boundary": report.safety_boundary,
        "recommendations": [
            {
                "service_name": item.service_name,
                "sender_domain": item.sender_domain,
                "priority": item.priority,
                "rotate": item.rotate,
                "reasons": list(item.reasons),
            }
            for item in report.recommendations
        ],
    }


def _print_exposure_report(report: ExposureReport) -> None:
    print(f"Safe exposure plan for {report.email_address}")
    print(report.safety_boundary)
    if report.email_breach_lookup_status == "checked":
        print(f"HIBP breaches for email: {report.breach_count}")
    else:
        print("HIBP email breach lookup: not run; this requires an optional paid HIBP API key")
    if report.password_pwned_count is None:
        print("Password exposure check: not run")
    elif report.password_pwned_count:
        print(f"Password exposure check: found {report.password_pwned_count} time(s); rotate any account using it")
    else:
        print("Password exposure check: not found in HIBP Pwned Passwords")
    if not report.recommendations:
        print("No services were available to prioritize. Run a mailbox scan/discovery and pass the JSON outputs.")
        return
    print("Rotation priorities:")
    for item in report.recommendations:
        action = "ROTATE" if item.rotate else "review"
        domain = f" ({item.sender_domain})" if item.sender_domain else ""
        print(f"- [{item.priority}] {action}: {item.service_name}{domain}")
        for reason in item.reasons:
            print(f"  reason: {reason}")


def _load_discovered_accounts(path: Path):
    from .models import DiscoveredAccount

    data = json.loads(path.read_text(encoding="utf-8"))
    accounts = []
    for item in data:
        accounts.append(
            DiscoveredAccount(
                service_name=str(item.get("service_name", "")),
                sender_domain=str(item.get("sender_domain", "")),
                message_count=int(item.get("message_count", 0)),
                confidence=item.get("confidence", "low"),
                reasons=[str(reason) for reason in item.get("reasons", [])],
            )
        )
    return accounts


def _load_findings(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    return [_finding_from_dict(item) for item in data]


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
