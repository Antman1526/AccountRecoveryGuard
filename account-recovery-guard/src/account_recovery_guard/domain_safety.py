from __future__ import annotations

from urllib.parse import parse_qsl, urlparse


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

REDIRECT_PARAMETER_NAMES = {
    "continue",
    "dest",
    "destination",
    "link",
    "next",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "return_to",
    "return_url",
    "target",
    "u",
    "url",
}


def https_url_matches_domain(url: str | None, expected_domain_or_url: str | None) -> bool:
    if not url or not expected_domain_or_url:
        return False
    parsed_url = urlparse(url)
    if parsed_url.scheme.lower() != "https":
        return False
    if parsed_url.username or parsed_url.password:
        return False
    url_host = normalize_host(parsed_url.hostname)
    expected_host = host_from_domain_or_url(expected_domain_or_url)
    if not url_host or not expected_host:
        return False
    if url_host == expected_host or url_host.endswith("." + expected_host):
        return True
    return registrable_domain_guess(url_host) == registrable_domain_guess(expected_host)


def safe_reset_link_matches_domain(url: str | None, expected_domain_or_url: str | None) -> bool:
    return https_url_matches_domain(url, expected_domain_or_url) and not has_unsafe_redirect_target(url, expected_domain_or_url)


def has_unsafe_redirect_target(url: str | None, expected_domain_or_url: str | None) -> bool:
    if not url:
        return False
    expected_host = host_from_domain_or_url(expected_domain_or_url)
    for value in redirect_target_values(url):
        target_host = _redirect_target_host(value)
        if not target_host:
            continue
        if not expected_host:
            return True
        if not https_url_matches_domain(value, expected_host):
            return True
    return False


def redirect_target_values(url: str | None) -> tuple[str, ...]:
    if not url:
        return ()
    parsed = urlparse(url)
    return tuple(
        value
        for key, value in _redirect_parameter_values(parsed.query, parsed.fragment)
        if key in REDIRECT_PARAMETER_NAMES
    )


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


def _redirect_parameter_values(*encoded_parts: str) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for encoded in encoded_parts:
        if not encoded or "=" not in encoded:
            continue
        pairs.extend((key.lower(), value.strip()) for key, value in parse_qsl(encoded, keep_blank_values=False))
    return tuple(pairs)


def _redirect_target_host(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        return normalize_host(parsed.hostname)
    if value.startswith("//"):
        return normalize_host(urlparse(f"https:{value}").hostname)
    return ""
