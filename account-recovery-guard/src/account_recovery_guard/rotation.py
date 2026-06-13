from __future__ import annotations

from .models import PasswordCandidate, RotationChoiceSummary
from .passwords import PasswordPolicy, generate_password


def build_rotation_choices(
    service_name: str,
    username: str,
    url: str | None = None,
    count: int = 5,
    length: int = 32,
) -> list[PasswordCandidate]:
    if count < 1:
        raise ValueError("At least one password choice is required")
    seen: set[str] = set()
    choices: list[PasswordCandidate] = []
    while len(choices) < count:
        password = generate_password(PasswordPolicy(length=length))
        if password in seen:
            continue
        seen.add(password)
        choices.append(
            PasswordCandidate(
                service_name=service_name,
                username=username,
                url=url,
                password=password,
                note="Rotated by Account Recovery Guard",
            )
        )
    return choices


def mask_password(password: str) -> str:
    if len(password) <= 5:
        return "*" * len(password)
    return password[:2] + ("*" * (len(password) - 3)) + password[-1]


def summarize_rotation_choices(passwords: list[str]) -> list[RotationChoiceSummary]:
    return [
        RotationChoiceSummary(
            index=index,
            display=mask_password(password),
            length=len(password),
            has_uppercase=any(char.isupper() for char in password),
            has_lowercase=any(char.islower() for char in password),
            has_digit=any(char.isdigit() for char in password),
            has_symbol=any(not char.isalnum() for char in password),
        )
        for index, password in enumerate(passwords, start=1)
    ]
