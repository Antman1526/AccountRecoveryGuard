# Security Policy

## Security Boundary

AccountRecoveryGuard is a local-first account recovery assistant, not antivirus software.

It helps reduce account-takeover risk by scanning authorized mailboxes for security alerts, guiding password rotation, generating unique passwords, and keeping Bitwarden/NordPass records consistent.

It does not protect a device that already has malware, a keylogger, remote-control tooling, or hostile browser extensions running as the current user. On an infected device, any local password manager, clipboard, browser session, or recovery tool can be observed or manipulated.

## Malware And Installer Trust

Use these controls before running release artifacts:

- Download installers only from `https://github.com/Antman1526/AccountRecoveryGuard`.
- Verify the provided SHA-256 checksum before opening an artifact.
- Inspect the JSON manifest next to each artifact for filename, size, SHA-256, git commit, run ID, platform, and signing status.
- Prefer signed and notarized macOS builds and signed Windows builds for distribution.
- Keep Microsoft Defender, Gatekeeper, XProtect, and any trusted endpoint protection enabled.
- Treat unsigned PyInstaller `.exe` files as development artifacts; antivirus products may quarantine or delete them because unsigned bundled executables are commonly abused.
- Do not bypass a malware warning unless you have verified the artifact source, checksum, and signing status.

## Built-In Protections

- Secrets are stored in macOS Keychain or Windows Credential Manager through `keyring`.
- Normal Gmail passwords are not accepted; Gmail uses Google app passwords or advanced OAuth setup.
- Bitwarden master passwords and `BW_SESSION` are not stored by the app.
- Passwords, tokens, authorization headers, cookies, and email bodies are redacted from audit logs.
- Password reset automation remains manual-safe and does not bypass MFA, CAPTCHA, passkeys, or device approval.
- Exposure checks use authorized mailbox evidence, optional paid HIBP email-breach lookup, and k-anonymous HIBP password checks. The free HIBP Pwned Passwords range check does not require an API key, while optional HIBP email-breach lookup requires a paid key. The app does not crawl dark-web dumps, paste sites, criminal forums, or random pages for plaintext passwords.
- NordPass CSV import files are treated as sensitive plaintext files and should be deleted after import.
- GitHub Actions runs tests, dependency vulnerability auditing, and artifact checksum generation.
- Build scripts verify generated checksums and emit release artifact manifests.

## Release Checklist

Before publishing or sharing installers:

1. Run the full test suite.
2. Run dependency auditing with `pip-audit`.
3. Build from GitHub Actions or a clean local checkout.
4. Verify generated SHA-256 checksums.
5. Confirm the generated JSON manifest points to the expected git commit and run ID.
6. Sign and notarize the macOS `.dmg` when a Developer ID certificate is available.
7. Sign the Windows `.exe` when a code-signing certificate is available.
8. Scan artifacts with the platform's built-in protection before distribution.
9. Publish checksums, manifests, and release notes with every release.

## Reporting Security Issues

Do not open public issues containing passwords, tokens, mailbox contents, vault exports, or other secrets.

Report security problems privately to the repository owner, then include:

- affected version or commit,
- operating system,
- minimal reproduction steps,
- expected behavior,
- actual behavior,
- whether any secrets may have been exposed.
