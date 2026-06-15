# Account Recovery Guard Guided Consumer Security Redesign

Date: 2026-06-13

## Confirmed Intent

Account Recovery Guard should feel like a calm, protective, guided consumer security assistant. Its first job is to help a less technical user connect email, scan for website accounts and compromise signals, then guide password rotation and Bitwarden/NordPass vault sync.

The first launch experience should not feel like a technical dashboard or command builder. The user should understand within seconds:

1. Connect email first.
2. The app scans for website accounts and risky account/security emails.
3. The app recommends which accounts need attention.
4. The app helps rotate passwords and keep Bitwarden and NordPass aligned.

## Target User

The primary user is a less technical person. They may understand Gmail, Outlook, Bitwarden, and NordPass as products, but they should not need to understand OAuth client secrets, IMAP host names, CLI commands, CSV schema details, or vault drift terminology before they can start.

The experience should be plain-language, reassuring, and explicit about privacy boundaries.

## Product Scope

This redesign goes beyond visual polish. It defines a real guided app experience that replaces command-preview-first screens with app-driven flows and clear state.

In scope:

- First-run onboarding wizard.
- Gmail and Outlook connection as primary paths.
- Other Email/IMAP as a secondary advanced path.
- Consent screen before scanning.
- Scan progress and guided results summary.
- Account review and password rotation flow.
- Five generated password choices.
- Bitwarden write status.
- NordPass import/export status and honest limitations.
- Sync verification and CSV cleanup guidance.
- Platform-native packaging expectations for macOS and Windows.

Out of scope:

- Fully automated password resets without user approval.
- Browser-extension scraping of NordPass or websites.
- Pretending NordPass personal vaults have a public direct-write API.
- Making CLI commands the main UI.
- Enterprise/admin dashboard behavior as the first screen.

## Design Direction

### Visual Tone

The app should feel calm and protective, not alarming or overly technical.

Use:

- Soft off-white and pale green surfaces.
- Deep green primary actions.
- Restrained amber for caution.
- Restrained red only for clear attention states.
- Rounded but controlled corners: roughly 10px for controls, 14-18px for larger panels.
- Subtle borders and very light shadows.
- Plain, reassuring microcopy.

Avoid:

- Dark hacker/security aesthetics.
- Overuse of red breach language.
- Exposed command-line language in the primary path.
- Dense data grids on first launch.
- Decorative gradients/orbs that do not support trust.

### Recommended Screens

The selected visual and UX direction is:

- First launch: A2, Trust-first wizard.
- Scan results: B2, Guided summary plus next best action.
- Rotation/sync: C2a, Calm Shield guided action panel.

## First-Run Flow

### Step 1: Connect Email for Review

The first visible screen should be a trust-first email connection screen.

Primary content:

- Title: "Connect email for review"
- Plain-language explanation: the app scans security alerts, login warnings, reset emails, and account messages to find websites tied to the user and identify accounts that may need attention.
- Privacy summary:
  - What we scan: security alerts, login warnings, password reset messages, and account messages.
  - What we never log: plaintext passwords, OAuth tokens, full email contents, or private keys.
  - What stays local: scan classification, generated passwords, staged vault data, and audit logs.

Primary actions:

- Continue with Gmail
- Continue with Outlook
- Other email

Behavior:

- Gmail and Outlook are the primary paths.
- Other Email opens an Advanced setup flow for IMAP/app-password setup.
- OAuth and credential setup details are not shown on the first screen unless the user chooses Advanced setup.
- If a required OAuth client or configuration is missing, the app explains the missing setup in plain language and offers a technical details disclosure.

### Step 2: Consent Before Scan

After a provider is selected and connection is ready, show a short consent screen before scanning.

The screen should answer:

- What will be scanned.
- What will not be scanned or logged.
- Whether anything leaves the device.
- How the user can stop or disconnect.

Primary action:

- Start scan

Secondary action:

- Back

The scan must not begin silently before this consent moment.

### Step 3: Scan Progress

During scanning, show a calm progress state.

Recommended copy:

- "Looking for account and security emails..."
- "Checking for login alerts, reset messages, and breach notifications."

Progress should show human-readable stages:

- Connecting to mailbox.
- Reading recent account/security messages.
- Finding websites tied to this email.
- Looking for risk signals.
- Preparing recommendations.

Do not show raw message bodies, tokens, or technical protocol logs in the main UI.

## Post-Scan Results

Default layout: Guided summary plus next best action.

Primary summary:

- "Your scan found X accounts."
- "Y accounts need attention."
- "We will guide you through one at a time."

Recommended account panel:

- Service name.
- Risk label.
- Plain-language reason.
- Timestamp or source summary when useful.
- Primary action: Review account.

Secondary actions:

- View all accounts.
- Scan another mailbox.
- Export report, if safe and redacted.

Risk language should be careful. Prefer "Needs attention" or "Review recommended" over dramatic breach language unless the evidence is explicit.

## Account Review Flow

Each flagged account gets a review screen.

It should show:

- Service name and website.
- Associated email/username.
- Why it was flagged.
- Evidence categories, not raw email dumps.
- Recommended action.
- Whether password rotation is available as a guided flow.

Primary action:

- Secure this account

Secondary actions:

- Mark reviewed.
- Skip for now.
- Open website manually.

## Password Rotation Flow

Default layout: Calm Shield guided action panel.

The screen should show:

- Selected service/account.
- Risk state.
- Recommended next step.
- Five generated password choices.
- Selected password state.
- Reset page action.
- Bitwarden status.
- NordPass status.
- Verification status.

Primary action logic:

1. Generate five password choices.
2. User selects one.
3. User copies selected password with timed clipboard clearing.
4. User opens/uses the reset page.
5. User confirms reset is complete.
6. App writes or stages vault updates.
7. App prompts for verification.

Security behavior:

- Do not print plaintext passwords in logs.
- Do not reveal all passwords by default.
- Make "Reveal selected" secondary and deliberate.
- Prefer "Copy selected password" with a clear clipboard timeout.
- If clipboard copy is unavailable, fail closed and do not display plaintext as a fallback without a deliberate reveal action.

## Vault Sync Flow

The UI should honestly explain the difference between Bitwarden and NordPass.

Bitwarden:

- Can be updated through the official Bitwarden CLI.
- Requires the user to be logged in/unlocked.
- Status states:
  - Not configured.
  - Connected.
  - Write ready.
  - Updated.
  - Verification failed.

NordPass:

- Personal vault direct-write API is not available.
- The app stages a NordPass import CSV using the supported import/export workflow.
- The app should guide the user to import into NordPass and then export for verification.
- Status states:
  - Import needed.
  - CSV prepared.
  - Waiting for import.
  - Export needed for verification.
  - Verified.
  - Drift found.

Plaintext CSV handling:

- Treat staged NordPass CSV files as sensitive.
- Show file location.
- Warn that the file should be deleted after import.
- Provide a cleanup action.

## Dashboard After Onboarding

The dashboard should appear after a scan exists or after onboarding is completed.

Dashboard sections:

- Account safety summary.
- Accounts needing attention.
- Recently reviewed accounts.
- Vault sync state.
- Last scan date.
- Quick actions:
  - Scan email.
  - Review next account.
  - Verify vault sync.
  - Clean up staged CSV files.

The dashboard should not be the first-launch default for a new user.

## Navigation Model

First run:

- Wizard steps only.
- No large sidebar of unrelated tools.

After first scan:

- Dashboard.
- Accounts.
- Vault Sync.
- Settings.

Advanced/tools area:

- IMAP setup.
- CLI-equivalent commands.
- Export/import utilities.
- Logs.

Advanced tools should be available but not prominent.

## Platform-Specific Packaging

### macOS

The DMG should feel native.

Recommended packaging:

- `AccountRecoveryGuard.app`
- Applications shortcut.
- Short "Before you start" README.
- Clean DMG layout.

App behavior:

- macOS-friendly spacing and titlebar behavior.
- Native file pickers and dialogs.
- No Windows installer language.

Release trust:

- Signing and notarization should be a release requirement before public distribution.
- Gatekeeper anxiety is especially harmful for a security app.

### Windows

The Windows app should feel native.

Short-term:

- Standalone EXE is acceptable for internal/test builds.
- First-run copy may explain that Windows can ask for confirmation until the app is signed.

Long-term:

- Prefer installer with Start Menu shortcut and uninstall support.
- Authenticode signing should be a release requirement before broad distribution.

App behavior:

- Native file dialogs.
- Windows-appropriate default file paths.
- No macOS-specific packaging language.

## Accessibility Requirements

- Body text should be at least 14px equivalent.
- Primary actions must meet WCAG AA contrast.
- Do not rely only on color for risk states.
- Buttons should have clear labels, not icons only.
- Error states should explain what happened and what the user can do next.
- Avoid dense jargon.
- Maintain keyboard navigation for wizard controls.
- Password reveal must be explicit and reversible.

## Empty, Loading, and Error States

Empty state:

- "Connect your email to begin."
- Explain why email is needed.
- Show provider buttons.

Loading state:

- Show current scan stage.
- Avoid generic spinner-only states.

Connection error:

- Plain explanation.
- Suggested fix.
- Retry action.
- Technical details disclosure.

No risky accounts found:

- Reassuring summary.
- Show number of accounts found.
- Offer to scan another mailbox or verify vault sync.

Vault error:

- Explain whether Bitwarden or NordPass needs action.
- Do not expose raw CLI output in the main message.
- Put raw output behind "Technical details."

## Implementation Implications

The current GUI is command-preview-heavy. The redesign requires introducing app state and real guided flows.

Likely implementation units:

- Onboarding state model.
- Mail provider connection state.
- Scan consent and progress controller.
- Scan result view model.
- Account review view model.
- Rotation session state.
- Vault sync state.
- Platform-aware packaging polish.

The CLI can remain available and power the underlying operations, but the GUI should call application services directly where practical instead of making users copy commands.

## Success Criteria

The redesign is successful when:

- A less technical user can explain the app's purpose after 5 seconds.
- The first visible action is connecting email.
- Users understand what the scan checks before it runs.
- Users are not exposed to OAuth/IMAP/CLI complexity unless they choose Advanced setup.
- Scan results clearly show the next account to review.
- Password rotation presents five choices without unsafe password exposure.
- Bitwarden and NordPass limitations are clear without sounding broken.
- macOS and Windows packages feel native enough that installation does not undermine trust.
