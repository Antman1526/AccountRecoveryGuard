from __future__ import annotations

import keyring

SERVICE_NAME = "account-recovery-guard"


def set_secret(name: str, value: str) -> None:
    keyring.set_password(SERVICE_NAME, name, value)


def get_secret(name: str) -> str | None:
    return keyring.get_password(SERVICE_NAME, name)


def delete_secret(name: str) -> None:
    try:
        keyring.delete_password(SERVICE_NAME, name)
    except keyring.errors.PasswordDeleteError:
        return
