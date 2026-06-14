from __future__ import annotations

from urllib.parse import urlparse


COMMON_SECOND_LEVEL_SUFFIXES = {
    "ac.uk",
    "co.jp",
    "co.nz",
    "co.uk",
    "com.au",
    "com.br",
    "gov.uk",
    "net.au",
    "org.uk",
}


def https_url_matches_domain(url: str | None, expected_domain_or_url: str | None) -> bool:
    if not url or not expected_domain_or_url:
        return False
    parsed_url = urlparse(url)
    if parsed_url.scheme != "https":
        return False
    url_host = normalize_host(parsed_url.hostname)
    expected_host = host_from_domain_or_url(expected_domain_or_url)
    if not url_host or not expected_host:
        return False
    if url_host == expected_host or url_host.endswith("." + expected_host):
        return True
    return registrable_domain_guess(url_host) == registrable_domain_guess(expected_host)


def host_from_domain_or_url(value: str | None) -> str:
    if not value:
        return ""
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    return normalize_host(urlparse(candidate).hostname)


def normalize_host(host: str | None) -> str:
    if not host:
        return ""
    normalized = host.strip().lower().rstrip(".")
    if normalized.startswith("www."):
        return normalized[4:]
    return normalized


def registrable_domain_guess(host: str) -> str:
    parts = [part for part in normalize_host(host).split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)
    suffix = ".".join(parts[-2:])
    if suffix in COMMON_SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix
