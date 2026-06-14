from account_recovery_guard.email_scanner import ImapEmailScanner, ImapMailboxConfig


class FakeImapClient:
    def __init__(self):
        self.search_args = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def login(self, username, password):
        self.username = username
        self.password = password

    def select(self, folder, readonly=True):
        self.folder = folder
        self.readonly = readonly

    def search(self, *args):
        self.search_args = args
        return "OK", [b""]


def test_imap_scanner_uses_all_for_full_mailbox(monkeypatch):
    fake_client = FakeImapClient()

    monkeypatch.setattr(
        "account_recovery_guard.email_scanner.imaplib.IMAP4_SSL",
        lambda host, port, timeout: fake_client,
    )

    messages = ImapEmailScanner(
        ImapMailboxConfig(
            host="imap.gmail.com",
            username="you@gmail.com",
            password="app-password",
            folder="[Gmail]/All Mail",
            days_back=0,
        )
    ).fetch_messages()

    assert messages == []
    assert fake_client.search_args == (None, "ALL")
    assert fake_client.folder == "[Gmail]/All Mail"
