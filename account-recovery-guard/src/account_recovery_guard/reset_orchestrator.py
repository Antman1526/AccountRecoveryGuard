from __future__ import annotations

import asyncio
from urllib.parse import unquote, urlparse

from .domain_safety import safe_reset_link_matches_domain
from .models import CompromisedAccountFinding, ResetWorkflow


BLOCKED_RECOVERY_DOWNLOAD_EXTENSIONS = {
    ".7z",
    ".apk",
    ".app",
    ".bat",
    ".cmd",
    ".com",
    ".dmg",
    ".exe",
    ".iso",
    ".jar",
    ".msi",
    ".pkg",
    ".ps1",
    ".rar",
    ".scr",
    ".sh",
    ".vbs",
    ".wsf",
    ".zip",
}


class ResetLinkSafetyError(ValueError):
    pass


class PasswordResetOrchestrator:
    def build_workflow(self, finding: CompromisedAccountFinding) -> ResetWorkflow:
        safe_reset_link = safe_reset_link_matches_domain(finding.reset_link, finding.sender_domain)
        steps = [
            f"Open the official site for {finding.service_name} directly or use the vetted reset link.",
            "Complete MFA challenges yourself; this tool never tries to bypass MFA, CAPTCHA, or risk checks.",
            "Set the generated replacement password only after confirming the site URL and TLS lock.",
            "Save the new credential to Bitwarden and stage the NordPass import package.",
            "Export NordPass after import and run sync verification.",
        ]
        if not finding.reset_link:
            steps.insert(0, "No reset link was extracted; start from the service's official account recovery page.")
        elif not safe_reset_link:
            steps.insert(0, "The extracted reset link failed safety checks; start from the service's official account recovery page.")
        return ResetWorkflow(
            service_name=finding.service_name,
            reset_link=finding.reset_link,
            steps=steps,
            automation_available=safe_reset_link,
        )

    async def open_reset_link_for_manual_completion(
        self,
        reset_link: str,
        expected_domain_or_url: str | None = None,
        wait_for_enter: bool = True,
    ) -> None:
        from playwright.async_api import async_playwright

        validated_link = validate_browser_reset_link(reset_link, expected_domain_or_url)
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=False)
            context = await browser.new_context(accept_downloads=False)
            await context.route("**/*", _block_recovery_downloads)
            page = await context.new_page()
            page.on("download", lambda download: asyncio.create_task(_cancel_download(download)))
            try:
                await page.goto(validated_link, wait_until="domcontentloaded", timeout=30_000)
                print(
                    "Browser opened with recovery downloads blocked. Complete the reset manually, "
                    + (
                        "then return here and press Enter."
                        if wait_for_enter
                        else "then close the recovery browser window when finished."
                    )
                )
                if wait_for_enter:
                    await asyncio.to_thread(input)
                else:
                    await page.wait_for_event("close", timeout=0)
            finally:
                await context.close()
                await browser.close()


def open_reset_link(reset_link: str, expected_domain_or_url: str | None = None) -> None:
    asyncio.run(PasswordResetOrchestrator().open_reset_link_for_manual_completion(reset_link, expected_domain_or_url))


def open_reset_link_window(reset_link: str, expected_domain_or_url: str | None = None) -> None:
    asyncio.run(
        PasswordResetOrchestrator().open_reset_link_for_manual_completion(
            reset_link,
            expected_domain_or_url,
            wait_for_enter=False,
        )
    )


def validate_browser_reset_link(reset_link: str, expected_domain_or_url: str | None = None) -> str:
    parsed = urlparse(reset_link)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ResetLinkSafetyError("Reset links opened by the browser helper must use HTTPS.")
    if parsed.username or parsed.password:
        raise ResetLinkSafetyError("Reset links opened by the browser helper cannot include embedded credentials.")
    if expected_domain_or_url and not safe_reset_link_matches_domain(reset_link, expected_domain_or_url):
        raise ResetLinkSafetyError("Reset link failed domain or redirect safety checks.")
    return reset_link


def is_blocked_recovery_download_url(url: str) -> bool:
    parsed = urlparse(url)
    path = unquote(parsed.path).lower()
    return any(path.endswith(extension) for extension in BLOCKED_RECOVERY_DOWNLOAD_EXTENSIONS)


async def _block_recovery_downloads(route) -> None:
    if is_blocked_recovery_download_url(route.request.url):
        await route.abort()
        return
    await route.continue_()


async def _cancel_download(download) -> None:
    try:
        await download.cancel()
    except Exception:
        return
