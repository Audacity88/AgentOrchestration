import hashlib
import json

import pytest

from src.common.errors import ArtifactIntegrityError, ArtifactManifestError
from src.storage import ArtifactManifestReader


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
            blocked_cache_dir=tmp_path / "blocked-cache",
            alert_handler=alerts.append,
        )

        with pytest.raises(ArtifactIntegrityError) as exc_info:
            reader.read(manifest, blob)

        assert not blob.exists()
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.artifact_id == "agent-plan"
        assert alert.expected_digest != alert.actual_digest
        assert alert.blocked_marker.exists()
        assert alert.quarantined_path.exists()
        assert alert.quarantined_path.read_bytes() == b"tampered bytes"
        assert exc_info.value.alert == alert
        marker = json.loads(alert.blocked_marker.read_text(encoding="utf-8"))
        assert marker["reason"] == "artifact_integrity_mismatch"
        assert marker["expected_digest"] == alert.expected_digest
        assert marker["actual_digest"] == alert.actual_digest

    def test_blocked_marker_prevents_cache_reuse(self, tmp_path):
        blob = tmp_path / "artifact.bin"
        blob.write_bytes(b"replacement bytes")
        manifest = tmp_path / "manifest.json"
        replacement_digest = hashlib.sha256(blob.read_bytes()).hexdigest()
        write_manifest(manifest, "agent-plan", replacement_digest)
        blocked_dir = tmp_path / "blocked-cache"
        blocked_dir.mkdir()
        marker = blocked_dir / "agent-plan.blocked.json"
        marker.write_text(
            json.dumps(
                {
                    "artifact_id": "agent-plan",
                    "reason": "artifact_integrity_mismatch",
                    "expected_digest": "expected-from-first-failure",
                    "actual_digest": "actual-from-first-failure",
                }
            ),
            encoding="utf-8",
        )
        alerts = []
        reader = ArtifactManifestReader(
            blocked_cache_dir=blocked_dir,
            alert_handler=alerts.append,
        )

        with pytest.raises(ArtifactIntegrityError) as exc_info:
            reader.read(manifest, blob)

        assert alerts == [exc_info.value.alert]
        assert blob.exists()
        assert alerts[0].blocked_marker == marker
        assert alerts[0].expected_digest == "expected-from-first-failure"
        assert alerts[0].actual_digest == "actual-from-first-failure"

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
            blocked_cache_dir=tmp_path / "blocked-cache",
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
            blocked_cache_dir=tmp_path / "blocked-cache",
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

    def test_manifest_can_identify_relative_blob_path(self, tmp_path):
        blob = tmp_path / "artifact.bin"
        payload = b"trusted artifact bytes"
        blob.write_bytes(payload)
        manifest = tmp_path / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "artifact_id": "agent-plan",
                    "digest": hashlib.sha256(payload).hexdigest(),
                    "path": blob.name,
                }
            ),
            encoding="utf-8",
        )

        assert ArtifactManifestReader().read(manifest) == payload

    def test_explicit_relative_blob_path_resolves_from_manifest_dir(
        self,
        tmp_path,
        monkeypatch,
    ):
        blob = tmp_path / "artifact.bin"
        payload = b"trusted artifact bytes"
        blob.write_bytes(payload)
        manifest = tmp_path / "manifest.json"
        write_manifest(
            manifest,
            "agent-plan",
            hashlib.sha256(payload).hexdigest(),
        )
        other_cwd = tmp_path / "other-cwd"
        other_cwd.mkdir()
        monkeypatch.chdir(other_cwd)

        assert ArtifactManifestReader().read(manifest, blob.name) == payload
