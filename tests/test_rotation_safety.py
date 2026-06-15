from account_recovery_guard.rotation import mask_password, summarize_rotation_choices


def test_summarize_rotation_choices_masks_passwords_by_default():
    rows = summarize_rotation_choices(["Abcdef123!@#", "Zyxwvu987$%^"])

    assert rows[0].display == "Ab*********#"
    assert rows[0].index == 1
    assert rows[0].length == 12
    assert "Abcdef123!@#" not in repr(rows)
