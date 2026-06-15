from account_recovery_guard.rotation import build_rotation_choices


def test_build_rotation_choices_returns_five_unique_passwords():
    choices = build_rotation_choices(service_name="Example", username="me@example.com", count=5)

    assert len(choices) == 5
    assert len({choice.password for choice in choices}) == 5
    assert all(choice.service_name == "Example" for choice in choices)
