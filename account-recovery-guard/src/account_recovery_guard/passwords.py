from __future__ import annotations

import secrets
import string
from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordPolicy:
    length: int = 32
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: bool = True
    symbol_alphabet: str = "!@#$%^&*()-_=+[]{}:,.?"


WORDLIST = (
    "anchor",
    "basil",
    "cinder",
    "delta",
    "ember",
    "fable",
    "glacier",
    "harbor",
    "indigo",
    "jupiter",
    "kernel",
    "lantern",
    "matrix",
    "nectar",
    "onyx",
    "prairie",
    "quartz",
    "rivet",
    "summit",
    "timber",
    "umbra",
    "velvet",
    "willow",
    "xenon",
    "yonder",
    "zenith",
)


def generate_password(policy: PasswordPolicy | None = None) -> str:
    policy = policy or PasswordPolicy()
    required_sets: list[str] = []
    if policy.uppercase:
        required_sets.append(string.ascii_uppercase)
    if policy.lowercase:
        required_sets.append(string.ascii_lowercase)
    if policy.digits:
        required_sets.append(string.digits)
    if policy.symbols:
        required_sets.append(policy.symbol_alphabet)

    if not required_sets:
        raise ValueError("At least one character class must be enabled")
    if policy.length < len(required_sets):
        raise ValueError("Password length is too short for required character classes")

    alphabet = "".join(required_sets)
    chars = [secrets.choice(charset) for charset in required_sets]
    chars.extend(secrets.choice(alphabet) for _ in range(policy.length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(word_count: int = 6, separator: str = "-") -> str:
    if word_count < 4:
        raise ValueError("Use at least four words for a passphrase")
    if not separator:
        raise ValueError("Separator cannot be empty")
    return separator.join(secrets.choice(WORDLIST) for _ in range(word_count))


def fingerprint_password(password: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(password.encode("utf-8")).hexdigest()
