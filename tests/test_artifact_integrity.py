import json

from scripts.artifact_integrity import build_manifest, expected_sha256, sha256_file, verify_checksum


def test_artifact_integrity_verifies_checksum_and_writes_manifest_shape(tmp_path, monkeypatch):
    artifact = tmp_path / "AccountRecoveryGuard.exe"
    artifact.write_bytes(b"release-bytes")
    checksum = tmp_path / "AccountRecoveryGuard.exe.sha256"
    digest = sha256_file(artifact)
    checksum.write_text(f"{digest}  AccountRecoveryGuard.exe\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")

    verify_checksum(artifact, checksum)
    manifest = build_manifest(artifact, checksum, "windows", "unsigned-development")

    assert expected_sha256(checksum, artifact.name) == digest
    assert manifest["artifact_name"] == "AccountRecoveryGuard.exe"
    assert manifest["size_bytes"] == len(b"release-bytes")
    assert manifest["sha256"] == digest
    assert manifest["git_sha"] == "abc123"
    assert manifest["github_run_id"] == "42"
    assert json.dumps(manifest)
