from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_sha256(checksum_file: Path, artifact_name: str) -> str:
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1].lstrip("*") == artifact_name:
            return parts[0].lower()
        if len(parts) == 1:
            return parts[0].lower()
    raise ValueError(f"No checksum entry for {artifact_name} in {checksum_file}")


def verify_checksum(artifact: Path, checksum_file: Path) -> None:
    actual = sha256_file(artifact)
    expected = expected_sha256(checksum_file, artifact.name)
    if actual != expected:
        raise ValueError(f"Checksum mismatch for {artifact.name}: expected {expected}, got {actual}")


def build_manifest(
    artifact: Path,
    checksum_file: Path,
    platform_name: str,
    signing_status: str,
) -> dict[str, object]:
    artifact = artifact.resolve()
    checksum_file = checksum_file.resolve()
    digest = sha256_file(artifact)
    expected = expected_sha256(checksum_file, artifact.name)
    if digest != expected:
        raise ValueError(f"Checksum mismatch for {artifact.name}: expected {expected}, got {digest}")
    return {
        "artifact_name": artifact.name,
        "size_bytes": artifact.stat().st_size,
        "sha256": digest,
        "checksum_file": checksum_file.name,
        "platform": platform_name,
        "signing_status": signing_status or "unsigned-development",
        "git_sha": os.environ.get("GITHUB_SHA") or os.environ.get("ARG_GIT_SHA") or "local",
        "github_run_id": os.environ.get("GITHUB_RUN_ID") or "local",
        "builder_os": platform.platform(),
        "created_utc": datetime.now(UTC).replace(microsecond=0).isoformat(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify release artifacts and write integrity manifests.")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="Verify an artifact against a .sha256 file")
    verify.add_argument("artifact")
    verify.add_argument("checksum_file")

    manifest = sub.add_parser("manifest", help="Write a JSON integrity manifest")
    manifest.add_argument("artifact")
    manifest.add_argument("checksum_file")
    manifest.add_argument("--platform", required=True)
    manifest.add_argument("--signing-status", default="unsigned-development")
    manifest.add_argument("--output", required=True)

    args = parser.parse_args(argv)
    artifact = Path(args.artifact)
    checksum_file = Path(args.checksum_file)
    if args.command == "verify":
        verify_checksum(artifact, checksum_file)
        print(f"{artifact.name}: OK")
        return 0

    data = build_manifest(artifact, checksum_file, args.platform, args.signing_status)
    output = Path(args.output)
    output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"artifact_integrity.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
