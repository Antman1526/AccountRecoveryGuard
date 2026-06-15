from account_recovery_guard.domain_safety import (
    has_unsafe_redirect_target,
    https_url_matches_domain,
    safe_reset_link_matches_domain,
)


def test_https_url_matches_domain_rejects_userinfo_urls():
    assert https_url_matches_domain("https://login.example.com@evil.test/reset", "example.com") is False


def test_safe_reset_link_allows_same_service_redirect_target():
    url = "https://example.com/reset?continue=https%3A%2F%2Faccounts.example.com%2Fsecurity"

    assert safe_reset_link_matches_domain(url, "example.com") is True
    assert has_unsafe_redirect_target(url, "example.com") is False


def test_safe_reset_link_blocks_external_redirect_target():
    url = "https://example.com/reset?continue=https%3A%2F%2Fevil.test%2Fsteal"

    assert safe_reset_link_matches_domain(url, "example.com") is False
    assert has_unsafe_redirect_target(url, "example.com") is True


def test_safe_reset_link_blocks_scheme_relative_redirect_target():
    url = "https://example.com/reset?next=%2F%2Fevil.test%2Fsteal"

    assert safe_reset_link_matches_domain(url, "example.com") is False
    assert has_unsafe_redirect_target(url, "example.com") is True


def test_safe_reset_link_blocks_insecure_redirect_target():
    url = "https://example.com/reset?return_url=http%3A%2F%2Fexample.com%2Fsecurity"

    assert safe_reset_link_matches_domain(url, "example.com") is False
    assert has_unsafe_redirect_target(url, "example.com") is True
