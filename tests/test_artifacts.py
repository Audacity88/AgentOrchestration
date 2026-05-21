import hashlib
import json

import pytest

from src.common.artifacts import ArtifactManifestReader
from src.common.errors import ArtifactIntegrityError, ArtifactManifestError


def write_manifest(path, artifact_id, digest):
    payload = {
        "artifact_id": artifact_id,
        "algorithm": "sha256",
        "digest": digest,
    }
    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )


class TestArtifactManifestReader:
    def test_read_artifact_returns_blob_when_digest_matches(self, tmp_path):
        blob = tmp_path / "artifact.bin"
        payload = b"trusted artifact bytes"
        blob.write_bytes(payload)
        manifest = tmp_path / "manifest.json"
        expected_digest = hashlib.sha256(payload).hexdigest()
        write_manifest(manifest, "agent-plan", expected_digest)
        reader = ArtifactManifestReader()

        assert reader.read(manifest, blob) == payload
        assert blob.exists()

    def test_digest_mismatch_alerts_and_quarantines_blob(self, tmp_path):
        blob = tmp_path / "artifact.bin"
        blob.write_bytes(b"tampered bytes")
        manifest = tmp_path / "manifest.json"
        expected_digest = hashlib.sha256(b"expected bytes").hexdigest()
        write_manifest(manifest, "agent-plan", expected_digest)
        alerts = []
        reader = ArtifactManifestReader(
            quarantine_dir=tmp_path / "quarantine",
            alert_handler=alerts.append,
        )

        with pytest.raises(ArtifactIntegrityError) as exc_info:
            reader.read(manifest, blob)

        assert not blob.exists()
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.artifact_id == "agent-plan"
        assert alert.expected_digest != alert.actual_digest
        assert alert.quarantined_path.exists()
        assert alert.quarantined_path.read_bytes() == b"tampered bytes"
        assert exc_info.value.alert == alert

    def test_quarantine_preserves_existing_evidence(self, tmp_path):
        payload = b"tampered bytes"
        actual_digest = hashlib.sha256(payload).hexdigest()
        blob = tmp_path / "artifact.bin"
        blob.write_bytes(payload)
        manifest = tmp_path / "manifest.json"
        write_manifest(
            manifest,
            "agent-plan",
            hashlib.sha256(b"expected bytes").hexdigest(),
        )
        quarantine_dir = tmp_path / "quarantine"
        quarantine_dir.mkdir()
        existing = quarantine_dir / f"artifact.bin.{actual_digest}.corrupt"
        existing.write_bytes(b"prior evidence")
        alerts = []
        reader = ArtifactManifestReader(
            quarantine_dir=quarantine_dir,
            alert_handler=alerts.append,
        )

        with pytest.raises(ArtifactIntegrityError):
            reader.read(manifest, blob)

        assert existing.read_bytes() == b"prior evidence"
        assert alerts[0].quarantined_path.name.endswith(".1.corrupt")
        assert alerts[0].quarantined_path.read_bytes() == payload

    def test_quarantine_failure_still_emits_integrity_alert(self, tmp_path):
        blob = tmp_path / "artifact.bin"
        blob.write_bytes(b"tampered bytes")
        manifest = tmp_path / "manifest.json"
        write_manifest(
            manifest,
            "agent-plan",
            hashlib.sha256(b"expected bytes").hexdigest(),
        )
        quarantine_file = tmp_path / "not-a-directory"
        quarantine_file.write_text("occupied", encoding="utf-8")
        alerts = []
        reader = ArtifactManifestReader(
            quarantine_dir=quarantine_file,
            alert_handler=alerts.append,
        )

        with pytest.raises(ArtifactIntegrityError) as exc_info:
            reader.read(manifest, blob)

        assert blob.exists()
        assert len(alerts) == 1
        assert alerts[0].quarantine_error
        assert exc_info.value.alert == alerts[0]

    def test_missing_manifest_digest_raises_platform_error(self, tmp_path):
        blob = tmp_path / "artifact.bin"
        blob.write_bytes(b"trusted artifact bytes")
        manifest = tmp_path / "manifest.json"
        manifest.write_text(
            json.dumps({"artifact_id": "agent-plan"}),
            encoding="utf-8",
        )

        with pytest.raises(ArtifactManifestError):
            ArtifactManifestReader().read(manifest, blob)
