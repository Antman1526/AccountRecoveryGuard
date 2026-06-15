from account_recovery_guard.passkeys import passkey_guidance


def test_passkey_guidance_is_review_first_not_rotation_first():
    steps = passkey_guidance("GitHub")
    text = " ".join(steps)

    assert "If account review shows a password change is needed, finish that password change first" in text
    assert "do not enroll a passkey on a suspicious or unverified page" in text
    assert "Complete password rotation first" not in text
