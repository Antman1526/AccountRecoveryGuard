# Security Review

Date: 2026-06-13

## Scope

Reviewed Account Recovery Guard local CLI/GUI flows, Bitwarden/NordPass vault handling, OAuth token storage, HIBP checks, clipboard behavior, staged CSV lifecycle, audit logging, and packaging workflows.

## Findings

No critical issues are currently open in the reviewed code.

Resolved during review:

- `rotate --copy-selected` no longer falls back to printing the selected plaintext password when clipboard copy is unavailable.
- `csv-status --delete` now overwrites file contents before unlinking where the filesystem permits it.
- `vault-live-test` was added so live vault testing uses a clearly marked `ARG-LIVE-TEST-*` entry and fails closed when Bitwarden CLI or `BW_SESSION` are unavailable.
- README token-storage documentation was corrected to reflect implemented Gmail/Graph OS secure-store token handling.

## Residual Risks

- NordPass personal vault automation still depends on plaintext CSV import/export because no official personal-vault CRUD API is available.
- Plaintext passwords can still appear on screen when the user intentionally reveals a selected rotation password or uses the GUI reveal button.
- Secure deletion cannot be guaranteed on SSDs, journaling filesystems, cloud-synced folders, or backup systems.
- Unsigned builds may trigger OS warnings until Apple Developer ID and Windows code-signing certificates are configured.
- Live Bitwarden write testing requires `bw` and `BW_SESSION`; this machine did not have either available during review.

## Verification

- Unit tests: `21 passed`
- CLI help includes live-vault test and workflow commands.
- Bitwarden live-test path fails closed without `bw`/`BW_SESSION`.
- NordPass staging path created a marked test CSV with mode `0600`.
