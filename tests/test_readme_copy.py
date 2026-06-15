from pathlib import Path


def test_public_project_descriptions_name_exposure_risk_scope():
    root = Path(__file__).parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")

    assert "Local-first account recovery and exposure-risk assistant for macOS and Windows." in readme
    assert "Local-first account recovery and exposure-risk assistant for Bitwarden and NordPass." in pyproject
    assert "Local-first account recovery and password rotation assistant for macOS and Windows." not in readme
    assert "Local-first account recovery and password rotation assistant for Bitwarden and NordPass." not in pyproject


def test_readme_architecture_uses_risk_signal_language_without_confirmed_compromise_claims():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "Compromised account findings" not in readme
    assert 'Findings["Account risk signals"]' in readme


def test_readme_dashboard_copy_uses_risk_not_safety_claims():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "the dashboard shows an account risk summary" in readme
    assert "the dashboard shows an account safety summary" not in readme


def test_readme_plain_english_plan_uses_review_not_protection_claim():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "Read a plain-English review plan that separates what the app knows" in readme
    assert "the next review action" in readme
    assert "Read a plain-English protection plan" not in readme
    assert "the next safe action" not in readme


def test_readme_gui_checklist_uses_review_not_protection_claim():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "Follow a review checklist for email connection, local scan, account review" in readme
    assert "See the review boundary on first launch" in readme
    assert "Review one mailbox at a time; run a separate scan for a second person" in readme
    assert "Extract readable `http`/`https` links from HTML email buttons" in readme
    assert (
        'Interpret scan results with uncertainty: mailbox findings are risk signals, and "no urgent alerts" '
        "does not prove every password is risk-free."
    ) in readme
    assert "Follow a protection checklist" not in readme
    assert "Protect one mailbox at a time" not in readme
    assert "See the safe recovery boundary on first launch" not in readme
    assert "Read safe `http`/`https` links from HTML email buttons" not in readme
    assert "Interpret scan results safely" not in readme
    assert '"no urgent alerts" does not prove every password is safe' not in readme


def test_readme_next_action_uses_review_not_safety_claim():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "Review a clear next review action plus the accounts needing attention found by the scan." in readme
    assert "Review a clear next safest action" not in readme


def test_readme_rotate_guidance_does_not_claim_selected_password_reveals_by_default():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "reveals only the selected password" not in readme
    assert "reveals only the one you choose" not in readme
    assert "`--copy-selected` is the recommended path" in readme
    assert "`--reveal-selected`" in readme


def test_readme_threat_model_uses_risk_reduction_not_absolute_protection_claims():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "Protects against reused passwords" not in readme
    assert "Helps reduce risk from reused passwords" in readme


def test_readme_describes_exposure_plan_as_alternative_not_whole_web_replacement():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert 'safe replacement for "search the whole web for my password"' not in readme
    assert "scoped review alternative to trying to search the whole web for a password" in readme
    assert "safe alternative to trying to search the whole web for a password" not in readme
    assert "does not crawl paste sites, dark-web sources, criminal forums, or random web pages" in readme


def test_readme_exposure_sources_name_hibp_not_generic_breach_intelligence():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "The app uses HIBP results and authorized mailbox evidence to prioritize accounts for review." in readme
    assert "reputable breach intelligence" not in readme
    assert "breach intelligence." not in readme


def test_readme_hibp_email_lookup_does_not_overstate_dataset_coverage():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "This tells you whether HIBP returns breach records for the email address." in readme
    assert "This tells you whether the email address appeared in known breach datasets." not in readme


def test_readme_passkey_guidance_names_official_enrollment_boundary():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "Use `passkey-guidance --service <name>` for official enrollment guidance." in readme
    assert "Use `passkey-guidance --service <name>` for safe enrollment steps." not in readme


def test_readme_passkey_section_does_not_claim_safe_creation():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "this CLI cannot create or enroll passkeys for third-party websites on your behalf" in readme
    assert "this CLI cannot safely create passkeys for third-party websites on your behalf" not in readme


def test_readme_breach_check_intro_names_paid_email_lookup_scope():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert (
        "The `breach-check` command uses the paid HIBP breached-account endpoint "
        "for an email-address lookup."
    ) in readme
    assert (
        "The `breach-check` command integrates with Have I Been Pwned (HIBP) "
        "for account-level breach checks."
    ) not in readme


def test_readme_install_commands_use_current_project_root():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "cd /Users/Antman/Desktop/AccountRecoveryGuard" in readme
    assert r"cd $HOME\Desktop\AccountRecoveryGuard" in readme
    assert "cd /Users/Antman/Desktop/AccountRecoveryGuard/account-recovery-guard" not in readme
    assert r"cd $HOME\Desktop\AccountRecoveryGuard\account-recovery-guard" not in readme


def test_readme_password_exposure_examples_use_old_reused_secret_names():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "arg secret old-reused-password" in readme
    assert "--password-secret old-reused-password" in readme
    assert "--confirm-old-or-reused" in readme
    assert "arg secret-delete old-reused-password" in readme
    assert "Delete that temporary old-password secret after the check." in readme
    assert "Do not check a new generated password" in readme
    assert "--password-secret candidate-password" not in readme


def test_readme_exposure_plan_section_uses_review_not_safety_label():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "Create an exposure review plan from mailbox scan JSON plus the free password check:" in readme
    assert "Create a safe exposure plan from mailbox scan JSON plus the free password check:" not in readme


def test_readme_file_map_uses_exposure_review_not_safety_label():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "exposure.py                     Exposure review report combining mailbox evidence and HIBP results." in readme
    assert "test_exposure.py                Verifies exposure-review recommendations and boundaries." in readme
    assert "exposure.py                     Safe exposure report combining mailbox evidence and HIBP results." not in readme
    assert "test_exposure.py                Verifies safe exposure-plan recommendations and boundaries." not in readme


def test_readme_reset_workflow_names_verified_link_boundary_not_manual_safety():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert 'Reset workflow builder\\nverified-link Playwright opener' in readme
    assert "reset_orchestrator.py           Verified-link password reset workflow and Playwright opener." in readme
    assert 'Reset workflow builder\\nmanual-safe Playwright opener' not in readme
    assert "reset_orchestrator.py           Manual-safe password reset workflow and Playwright opener." not in readme


def test_readme_live_vault_file_map_names_marked_test_entry_not_safety_claim():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "test_live_vault.py              Verifies live-vault preflight and marked test entry construction." in readme
    assert "test_live_vault.py              Verifies live-vault preflight and safe test entry construction." not in readme


def test_readme_nordpass_limitation_uses_supported_path_not_safest_claim():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "CSV import/export is the supported path used here today." in readme
    assert "CSV import/export is the safest supported path today." not in readme


def test_readme_gui_rotation_guidance_is_review_first():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "Review the account evidence first, then rotate with masked choices only when the signal supports it" in readme
    assert "Rotate passwords with masked choices, then prepare vault sync" not in readme


def test_readme_cli_rotate_section_is_review_first():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "After reviewing account evidence, change one password with five local password choices" in readme
    assert "Rotate with five local password choices" not in readme


def test_readme_passkey_guidance_is_not_rotation_first():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

    assert "When account review leads you to rotate a password" in readme
    assert "During password rotation" not in readme
