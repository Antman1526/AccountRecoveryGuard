import sys
import types

fake_secure_store = types.ModuleType("account_recovery_guard.secure_store")
fake_secure_store.get_secret = lambda secret_name: ""
fake_secure_store.set_secret = lambda secret_name, value: None
sys.modules.setdefault("account_recovery_guard.secure_store", fake_secure_store)

from account_recovery_guard.oauth_mail import GraphOAuthConfig, MicrosoftGraphMailProvider


class FakeTokenCache:
    has_state_changed = False

    def deserialize(self, cache_blob):
        self.cache_blob = cache_blob

    def serialize(self):
        return "{}"


class FakeGraphApp:
    def __init__(self, client_id, authority, token_cache):
        self.client_id = client_id
        self.authority = authority
        self.token_cache = token_cache

    def get_accounts(self):
        return []

    def acquire_token_silent(self, scopes, account=None):
        return None

    def initiate_device_flow(self, scopes):
        return {"user_code": "ABCD-EFGH", "message": "Use code ABCD-EFGH to sign in."}

    def acquire_token_by_device_flow(self, flow):
        return {
            "error": "invalid_grant",
            "error_description": "refresh_token=super-secret-value access_token=also-secret",
        }


def test_graph_auth_failure_does_not_echo_token_payload(monkeypatch, capsys):
    fake_msal = types.ModuleType("msal")
    fake_msal.SerializableTokenCache = FakeTokenCache
    fake_msal.PublicClientApplication = FakeGraphApp
    monkeypatch.setitem(sys.modules, "msal", fake_msal)
    monkeypatch.setattr("account_recovery_guard.oauth_mail.get_secret", lambda secret_name: "")
    monkeypatch.setattr("account_recovery_guard.oauth_mail.set_secret", lambda secret_name, value: None)

    provider = MicrosoftGraphMailProvider(GraphOAuthConfig("common", "client-id"))

    try:
        provider.fetch_messages()
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("Graph auth failure should raise a sanitized RuntimeError")

    assert "Microsoft Graph authentication failed (invalid_grant)" in message
    assert "Try signing in again" in message
    assert "super-secret-value" not in message
    assert "also-secret" not in message
    assert "refresh_token" not in message
    assert "access_token" not in message
    assert "ABCD-EFGH" in capsys.readouterr().out
