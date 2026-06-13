from __future__ import annotations

PASSKEY_READY_SERVICES = {
    "adobe",
    "amazon",
    "apple",
    "bitwarden",
    "dropbox",
    "github",
    "google",
    "microsoft",
    "paypal",
    "yahoo",
}


def passkey_guidance(service_name: str) -> list[str]:
    normalized = service_name.lower()
    steps = [
        "Complete password rotation first; do not enroll a passkey on a suspicious or unverified page.",
        "Open the official account security settings for the service.",
        "Use the service's own passkey enrollment flow and approve with your device authenticator.",
        "Save the passkey in Bitwarden or NordPass only through their official passkey prompts.",
    ]
    if normalized in PASSKEY_READY_SERVICES:
        steps.insert(0, f"{service_name} is commonly passkey-capable; verify support in its account security settings.")
    else:
        steps.insert(0, f"No local allowlist match for {service_name}; check the official security settings manually.")
    return steps
