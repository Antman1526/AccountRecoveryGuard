from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email import message_from_bytes
from email.message import EmailMessage, Message
from typing import Protocol
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .secure_store import get_secret, set_secret


class MailProvider(Protocol):
    def fetch_messages(self, days_back: int = 30) -> list[Message]:
        ...


@dataclass(frozen=True)
class GmailOAuthConfig:
    client_secret_file: str
    token_secret_name: str = "gmail-oauth-token"


@dataclass(frozen=True)
class GraphOAuthConfig:
    tenant_id: str
    client_id: str
    token_secret_name: str = "graph-oauth-token"


class GmailApiMailProvider:
    """OAuth Gmail adapter scaffold using Google's official Python client libraries."""

    def __init__(self, config: GmailOAuthConfig):
        self.config = config

    def fetch_messages(self, days_back: int = 30) -> list[Message]:
        try:
            from googleapiclient.discovery import build  # type: ignore
            from google.oauth2.credentials import Credentials  # type: ignore
            from google_auth_oauthlib.flow import InstalledAppFlow  # type: ignore
        except ImportError as exc:
            raise RuntimeError("Install the oauth extra: python -m pip install '.[oauth]'") from exc
        scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
        token_json = get_secret(self.config.token_secret_name)
        creds = Credentials.from_authorized_user_info(json.loads(token_json), scopes) if token_json else None
        if not creds or not creds.valid:
            flow = InstalledAppFlow.from_client_secrets_file(self.config.client_secret_file, scopes)
            creds = flow.run_local_server(port=0)
            set_secret(self.config.token_secret_name, creds.to_json())
        service = build("gmail", "v1", credentials=creds)
        query = f"newer_than:{max(days_back, 1)}d"
        response = service.users().messages().list(userId="me", q=query, maxResults=250).execute()
        messages: list[Message] = []
        for item in response.get("messages", []):
            raw_response = service.users().messages().get(userId="me", id=item["id"], format="raw").execute()
            raw = base64.urlsafe_b64decode(raw_response["raw"].encode("ascii"))
            messages.append(message_from_bytes(raw))
        return messages


class MicrosoftGraphMailProvider:
    """Microsoft Graph adapter scaffold for desktop device-code authentication."""

    def __init__(self, config: GraphOAuthConfig):
        self.config = config

    def fetch_messages(self, days_back: int = 30) -> list[Message]:
        try:
            import msal  # type: ignore  # noqa: F401
        except ImportError as exc:
            raise RuntimeError("Install the oauth extra: python -m pip install '.[oauth]'") from exc
        import msal  # type: ignore

        scopes = ["Mail.Read"]
        cache = msal.SerializableTokenCache()
        cache_blob = get_secret(self.config.token_secret_name)
        if cache_blob:
            cache.deserialize(cache_blob)
        authority = f"https://login.microsoftonline.com/{self.config.tenant_id}"
        app = msal.PublicClientApplication(self.config.client_id, authority=authority, token_cache=cache)
        accounts = app.get_accounts()
        token = app.acquire_token_silent(scopes, account=accounts[0] if accounts else None)
        if not token:
            flow = app.initiate_device_flow(scopes=scopes)
            if "user_code" not in flow:
                raise RuntimeError("Microsoft device-code flow could not be created")
            print(flow["message"])
            token = app.acquire_token_by_device_flow(flow)
        if cache.has_state_changed:
            set_secret(self.config.token_secret_name, cache.serialize())
        if "access_token" not in token:
            raise RuntimeError(_graph_auth_failure_message(token))

        since = (datetime.now(UTC) - timedelta(days=days_back)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        params = urlencode(
            {
                "$top": "100",
                "$select": "subject,from,receivedDateTime,body",
                "$filter": f"receivedDateTime ge {since}",
            }
        )
        request = Request(
            f"https://graph.microsoft.com/v1.0/me/messages?{params}",
            headers={"Authorization": f"Bearer {token['access_token']}"},
        )
        with urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return [_graph_item_to_message(item) for item in payload.get("value", [])]


def _graph_item_to_message(item: dict) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = item.get("subject") or ""
    address = ((item.get("from") or {}).get("emailAddress") or {}).get("address") or ""
    name = ((item.get("from") or {}).get("emailAddress") or {}).get("name") or address
    message["From"] = f"{name} <{address}>" if address else name
    message["Date"] = item.get("receivedDateTime") or ""
    body = item.get("body") or {}
    content = body.get("content") or ""
    if body.get("contentType", "").lower() == "html":
        message.add_alternative(content, subtype="html")
    else:
        message.set_content(content)
    return message


def _graph_auth_failure_message(token: object) -> str:
    error_code = ""
    if isinstance(token, dict):
        raw_error = str(token.get("error") or "").strip()
        if raw_error and all(ch.isalnum() or ch in {"_", "-", "."} for ch in raw_error):
            error_code = raw_error[:80]
    suffix = f" ({error_code})" if error_code else ""
    return f"Microsoft Graph authentication failed{suffix}. Try signing in again and check the Outlook setup."
