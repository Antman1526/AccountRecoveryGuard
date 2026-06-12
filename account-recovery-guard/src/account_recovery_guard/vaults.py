from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from .models import PasswordCandidate, VaultEntry
from .passwords import fingerprint_password


class VaultError(RuntimeError):
    pass


@dataclass(frozen=True)
class BitwardenCliConfig:
    executable: str = "bw"
    timeout_seconds: int = 30


class BitwardenVault:
    def __init__(self, config: BitwardenCliConfig | None = None):
        self.config = config or BitwardenCliConfig()
        if shutil.which(self.config.executable) is None:
            raise VaultError("Bitwarden CLI 'bw' was not found on PATH")

    def upsert_login(self, candidate: PasswordCandidate) -> VaultEntry:
        existing = self._find_item(candidate.service_name, candidate.username, candidate.url)
        item = existing or self._get_template("item")
        item["type"] = 1
        item["name"] = candidate.service_name
        item["notes"] = candidate.note
        item["login"] = item.get("login") or {}
        item["login"]["username"] = candidate.username
        item["login"]["password"] = candidate.password
        item["login"]["uris"] = [{"uri": candidate.url}] if candidate.url else []

        encoded = self._encode(item)
        if existing:
            self._run(["edit", "item", existing["id"], encoded])
        else:
            self._run(["create", "item", encoded])
        return VaultEntry(
            service_name=candidate.service_name,
            username=candidate.username,
            url=candidate.url,
            password_fingerprint=fingerprint_password(candidate.password),
        )

    def read_entry(self, service_name: str, username: str, url: str | None = None) -> VaultEntry | None:
        item = self._find_item(service_name, username, url)
        if not item:
            return None
        login = item.get("login") or {}
        password = login.get("password") or ""
        uri = None
        uris = login.get("uris") or []
        if uris:
            uri = uris[0].get("uri")
        return VaultEntry(
            service_name=item.get("name") or service_name,
            username=login.get("username") or username,
            url=uri,
            password_fingerprint=fingerprint_password(password),
        )

    def _find_item(self, service_name: str, username: str, url: str | None) -> dict[str, Any] | None:
        output = self._run(["list", "items", "--search", service_name])
        try:
            items = json.loads(output)
        except json.JSONDecodeError as exc:
            raise VaultError("Bitwarden CLI returned invalid JSON") from exc
        for item in items:
            login = item.get("login") or {}
            uris = login.get("uris") or []
            urls = [entry.get("uri") for entry in uris]
            if login.get("username") == username and (not url or url in urls or not urls):
                return item
        return None

    def _get_template(self, name: str) -> dict[str, Any]:
        output = self._run(["get", "template", name])
        return json.loads(output)

    def _encode(self, payload: dict[str, Any]) -> str:
        return self._run(["encode"], input_text=json.dumps(payload))

    def _run(self, args: list[str], input_text: str | None = None) -> str:
        env = os.environ.copy()
        if "BW_SESSION" not in env:
            raise VaultError("BW_SESSION is not set. Run 'bw unlock --raw' and export the returned session token.")
        result = subprocess.run(
            [self.config.executable, *args],
            input=input_text,
            text=True,
            capture_output=True,
            timeout=self.config.timeout_seconds,
            env=env,
            check=False,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip() or "unknown Bitwarden CLI error"
            raise VaultError(stderr)
        return result.stdout.strip()


class NordPassImportVault:
    """Best available personal NordPass integration: stage official CSV imports and verify exports."""

    fieldnames = ["name", "url", "username", "password", "note", "folder"]

    def stage_import(self, candidates: list[PasswordCandidate], destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile("w", newline="", encoding="utf-8", delete=False, dir=destination.parent) as tmp:
            writer = csv.DictWriter(tmp, fieldnames=self.fieldnames)
            writer.writeheader()
            for candidate in candidates:
                writer.writerow(
                    {
                        "name": candidate.service_name,
                        "url": candidate.url or "",
                        "username": candidate.username,
                        "password": candidate.password,
                        "note": candidate.note,
                        "folder": "Account Recovery Guard",
                    }
                )
            tmp_path = Path(tmp.name)
        os.chmod(tmp_path, 0o600)
        tmp_path.replace(destination)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
        return destination

    def read_export(self, export_csv: Path) -> list[VaultEntry]:
        entries: list[VaultEntry] = []
        with export_csv.open("r", newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                password = row.get("password") or row.get("Password") or ""
                entries.append(
                    VaultEntry(
                        service_name=row.get("name") or row.get("Name") or "",
                        username=row.get("username") or row.get("Username") or "",
                        url=row.get("url") or row.get("URL") or None,
                        password_fingerprint=fingerprint_password(password),
                    )
                )
        return entries
