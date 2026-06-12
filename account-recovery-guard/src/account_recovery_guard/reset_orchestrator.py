from __future__ import annotations

import asyncio

from .models import CompromisedAccountFinding, ResetWorkflow


class PasswordResetOrchestrator:
    def build_workflow(self, finding: CompromisedAccountFinding) -> ResetWorkflow:
        steps = [
            f"Open the official site for {finding.service_name} directly or use the vetted reset link.",
            "Complete MFA challenges yourself; this tool never tries to bypass MFA, CAPTCHA, or risk checks.",
            "Set the generated replacement password only after confirming the site URL and TLS lock.",
            "Save the new credential to Bitwarden and stage the NordPass import package.",
            "Export NordPass after import and run sync verification.",
        ]
        if not finding.reset_link:
            steps.insert(0, "No reset link was extracted; start from the service's official account recovery page.")
        return ResetWorkflow(
            service_name=finding.service_name,
            reset_link=finding.reset_link,
            steps=steps,
            automation_available=bool(finding.reset_link),
        )

    async def open_reset_link_for_manual_completion(self, reset_link: str) -> None:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=False)
            page = await browser.new_page()
            await page.goto(reset_link, wait_until="domcontentloaded", timeout=30_000)
            print("Browser opened. Complete the reset manually, then return here and press Enter.")
            await asyncio.to_thread(input)
            await browser.close()


def open_reset_link(reset_link: str) -> None:
    asyncio.run(PasswordResetOrchestrator().open_reset_link_for_manual_completion(reset_link))
