from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from time import sleep
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class HibpBreach:
    name: str


class BreachCheckError(RuntimeError):
    pass


class HibpBreachChecker:
    base_url = "https://haveibeenpwned.com/api/v3"

    def __init__(self, api_key: str, user_agent: str = "account-recovery-guard/0.1", delay_seconds: float = 1.6):
        if not api_key:
            raise ValueError("HIBP API key is required for breached account checks")
        self.api_key = api_key
        self.user_agent = user_agent
        self.delay_seconds = delay_seconds

    def breaches_for_account(self, email_address: str) -> list[HibpBreach]:
        url = f"{self.base_url}/breachedaccount/{quote(email_address, safe='')}?truncateResponse=true"
        request = Request(
            url,
            headers={
                "hibp-api-key": self.api_key,
                "user-agent": self.user_agent,
            },
            method="GET",
        )
        try:
            with urlopen(request, timeout=20) as response:
                payload = response.read()
        except HTTPError as exc:
            if exc.code == 404:
                return []
            if exc.code == 429:
                raise BreachCheckError("HIBP rate limit exceeded; wait and retry") from exc
            raise BreachCheckError(f"HIBP returned HTTP {exc.code}") from exc
        finally:
            sleep(self.delay_seconds)
        return parse_hibp_breaches(payload)

    def pwned_password_count(self, password: str) -> int:
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        request = Request(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"user-agent": self.user_agent, "add-padding": "true"},
            method="GET",
        )
        with urlopen(request, timeout=20) as response:
            payload = response.read()
        return parse_pwned_password_suffixes(payload, suffix)


def parse_hibp_breaches(payload: bytes) -> list[HibpBreach]:
    data = json.loads(payload.decode("utf-8"))
    breaches: list[HibpBreach] = []
    for item in data:
        if isinstance(item, dict) and item.get("Name"):
            breaches.append(HibpBreach(name=str(item["Name"])))
    return breaches


def parse_pwned_password_suffixes(payload: bytes, wanted_suffix: str) -> int:
    wanted = wanted_suffix.upper()
    for raw_line in payload.decode("utf-8", errors="replace").splitlines():
        if ":" not in raw_line:
            continue
        suffix, count = raw_line.split(":", 1)
        if suffix.strip().upper() == wanted:
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0
