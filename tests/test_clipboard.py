from account_recovery_guard import clipboard


def test_clear_clipboard_if_unchanged_clears_matching_clipboard(monkeypatch):
    copied: list[str] = []
    monkeypatch.setattr(clipboard, "_paste_once", lambda: "Secret123!")
    monkeypatch.setattr(clipboard, "_copy_once", lambda text: copied.append(text) or True)

    assert clipboard.clear_clipboard_if_unchanged("Secret123!") is True
    assert copied == [""]


def test_clear_clipboard_if_unchanged_keeps_user_replacement(monkeypatch):
    copied: list[str] = []
    monkeypatch.setattr(clipboard, "_paste_once", lambda: "user copied something else")
    monkeypatch.setattr(clipboard, "_copy_once", lambda text: copied.append(text) or True)

    assert clipboard.clear_clipboard_if_unchanged("Secret123!") is False
    assert copied == []


def test_clear_clipboard_if_unchanged_clears_when_clipboard_cannot_be_read(monkeypatch):
    copied: list[str] = []
    monkeypatch.setattr(clipboard, "_paste_once", lambda: None)
    monkeypatch.setattr(clipboard, "_copy_once", lambda text: copied.append(text) or True)

    assert clipboard.clear_clipboard_if_unchanged("Secret123!") is True
    assert copied == [""]


def test_copy_text_schedules_conditional_clear(monkeypatch):
    scheduled = {}

    class FakeTimer:
        daemon = False

        def __init__(self, seconds, target, args):
            scheduled["seconds"] = seconds
            scheduled["target"] = target
            scheduled["args"] = args

        def start(self):
            scheduled["started"] = True

    monkeypatch.setattr(clipboard, "_copy_once", lambda text: True)
    monkeypatch.setattr(clipboard.threading, "Timer", FakeTimer)

    assert clipboard.copy_text("Secret123!", clear_after_seconds=60) is True
    assert scheduled == {
        "seconds": 60,
        "target": clipboard.clear_clipboard_if_unchanged,
        "args": ("Secret123!",),
        "started": True,
    }


def test_copy_command_reports_failure(monkeypatch):
    class Result:
        returncode = 1

    monkeypatch.setattr(clipboard, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(clipboard.subprocess, "run", lambda *args, **kwargs: Result())

    assert clipboard._run_copy_command(["pbcopy"], "Secret123!") is False
