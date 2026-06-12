from __future__ import annotations

from .models import PasswordCandidate
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
