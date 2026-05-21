"""Artifact manifest reading and integrity checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional, Union
import hashlib
import json
import logging
import shutil

from src.common.errors import ArtifactIntegrityError, ArtifactManifestError
from src.common.metrics import metrics

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ArtifactManifest:
    """Digest metadata used to validate an artifact blob."""

    artifact_id: str
    digest: str
    blob_path: Optional[Path] = None
    algorithm: str = "sha256"


@dataclass(frozen=True)
class ArtifactBlob:
    """A verified artifact blob read through a manifest."""

    artifact_id: str
    path: Path
    digest: str
    content: bytes


@dataclass(frozen=True)
class IntegrityAlert:
    """Operator-facing alert emitted for artifact corruption."""

    artifact_id: str
    expected_digest: str
    actual_digest: str
    blob_path: Path
    blocked_marker: Path
    quarantined_path: Optional[Path] = None
    quarantine_error: Optional[str] = None
    alert_type: str = "artifact_integrity_mismatch"
    severity: str = "critical"


AlertHandler = Callable[[IntegrityAlert], None]
PathInput = Union[str, Path]
CHUNK_SIZE = 1024 * 1024


class ArtifactManifestReader:
    """Read artifact blobs through manifest digest validation."""

    def __init__(
        self,
        *,
        quarantine_dir: Optional[PathInput] = None,
        blocked_cache_dir: Optional[PathInput] = None,
        alert_handler: Optional[AlertHandler] = None,
    ):
        self.quarantine_dir = Path(quarantine_dir) if quarantine_dir else None
        self.blocked_cache_dir = (
            Path(blocked_cache_dir) if blocked_cache_dir else None
        )
        self.alert_handler = alert_handler

    def read(
        self,
        manifest_path: PathInput,
        blob_path: Optional[PathInput] = None,
    ) -> bytes:
        artifact = self.read_blob(manifest_path, blob_path)
        return artifact.content

    def read_blob(
        self,
        manifest_path: PathInput,
        blob_path: Optional[PathInput] = None,
    ) -> ArtifactBlob:
        manifest_file = Path(manifest_path)
        manifest = load_manifest(manifest_file)
        blob = resolve_blob_path(manifest_file, manifest, blob_path)
        blocked_marker = self.block_marker_path(manifest.artifact_id, blob)
        if blocked_marker.exists():
            alert = load_blocked_alert(
                blocked_marker,
                manifest=manifest,
                blob_path=blob,
            )
            emit_integrity_alert(alert, self.alert_handler)
            raise_integrity_error(alert)

        actual_digest = compute_file_digest(blob, manifest.algorithm)
        if actual_digest != manifest.digest:
            alert = self.handle_digest_mismatch(
                manifest=manifest,
                blob_path=blob,
                actual_digest=actual_digest,
                blocked_marker=blocked_marker,
            )
            raise_integrity_error(alert)

        return ArtifactBlob(
            artifact_id=manifest.artifact_id,
            path=blob,
            digest=actual_digest,
            content=blob.read_bytes(),
        )

    def handle_digest_mismatch(
        self,
        *,
        manifest: ArtifactManifest,
        blob_path: Path,
        actual_digest: str,
        blocked_marker: Path,
    ) -> IntegrityAlert:
        write_blocked_marker(
            blocked_marker,
            artifact_id=manifest.artifact_id,
            expected_digest=manifest.digest,
            actual_digest=actual_digest,
        )
        quarantined_path: Optional[Path] = None
        quarantine_error: Optional[str] = None
        try:
            quarantined_path = quarantine_blob(
                blob_path,
                actual_digest,
                self.quarantine_dir,
            )
        except OSError as exc:
            quarantine_error = str(exc)

        alert = IntegrityAlert(
            artifact_id=manifest.artifact_id,
            expected_digest=manifest.digest,
            actual_digest=actual_digest,
            blob_path=blob_path,
            blocked_marker=blocked_marker,
            quarantined_path=quarantined_path,
            quarantine_error=quarantine_error,
        )
        emit_integrity_alert(alert, self.alert_handler)
        return alert

    def block_marker_path(self, artifact_id: str, blob_path: Path) -> Path:
        blocked_cache_dir = self.blocked_cache_dir or (
            blob_path.parent / ".artifact-blocked-cache"
        )
        safe_artifact_id = artifact_id.replace("/", "_").replace("\\", "_")
        return blocked_cache_dir / f"{safe_artifact_id}.blocked.json"


def read_artifact(
    manifest_path: PathInput,
    blob_path: Optional[PathInput] = None,
    *,
    quarantine_dir: Optional[PathInput] = None,
    blocked_cache_dir: Optional[PathInput] = None,
    alert_handler: Optional[AlertHandler] = None,
) -> bytes:
    """Read an artifact blob only after its digest matches the manifest."""

    reader = ArtifactManifestReader(
        quarantine_dir=quarantine_dir,
        blocked_cache_dir=blocked_cache_dir,
        alert_handler=alert_handler,
    )
    return reader.read(manifest_path, blob_path)


def load_manifest(path: PathInput) -> ArtifactManifest:
    """Load digest metadata from a JSON artifact manifest."""

    manifest_path = Path(path)
    with manifest_path.open("r", encoding="utf-8") as manifest_file:
        payload = json.load(manifest_file)
    return manifest_from_mapping(payload, manifest_path=manifest_path)


def manifest_from_mapping(
    payload: Mapping[str, object],
    *,
    manifest_path: Optional[Path] = None,
) -> ArtifactManifest:
    artifact_id = require_manifest_string(
        payload,
        "artifact_id",
        fallback_key="id",
    )
    digest = require_manifest_string(payload, "digest").lower()
    algorithm = require_manifest_string(
        payload,
        "algorithm",
        default="sha256",
    ).lower()
    if not artifact_id:
        raise ArtifactManifestError("missing artifact_id")
    if not digest:
        raise ArtifactManifestError("missing digest")
    if algorithm not in hashlib.algorithms_available:
        raise ArtifactManifestError(
            f"unsupported digest algorithm: {algorithm}"
        )
    validate_digest(algorithm, digest)
    return ArtifactManifest(
        artifact_id=artifact_id,
        digest=digest,
        blob_path=manifest_blob_path(payload, manifest_path),
        algorithm=algorithm,
    )


def manifest_blob_path(
    payload: Mapping[str, object],
    manifest_path: Optional[Path],
) -> Optional[Path]:
    raw_path = (
        payload.get("blob_path")
        or payload.get("path")
        or payload.get("file")
    )
    if raw_path is None:
        return None
    if not isinstance(raw_path, str):
        raise ArtifactManifestError("blob_path must be a string")
    blob_path = Path(raw_path.strip())
    if blob_path.is_absolute() or manifest_path is None:
        return blob_path
    return manifest_path.parent / blob_path


def resolve_blob_path(
    manifest_path: Path,
    manifest: ArtifactManifest,
    explicit_blob_path: Optional[PathInput],
) -> Path:
    if explicit_blob_path is not None:
        return Path(explicit_blob_path)
    if manifest.blob_path is not None:
        return manifest.blob_path
    raise ArtifactManifestError(
        f"{manifest_path} does not identify an artifact blob"
    )


def quarantine_blob(
    blob_path: Path,
    actual_digest: str,
    quarantine_dir: Optional[PathInput] = None,
) -> Path:
    """Move a failed blob out of the cache path so it cannot be reused."""

    if quarantine_dir:
        destination_dir = Path(quarantine_dir)
    else:
        destination_dir = blob_path.parent / ".quarantine"
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = next_quarantine_path(
        destination_dir,
        blob_path.name,
        actual_digest,
    )
    shutil.move(str(blob_path), destination)
    return destination


def emit_integrity_alert(
    alert: IntegrityAlert,
    alert_handler: Optional[AlertHandler],
) -> None:
    metrics.increment("artifact.integrity_mismatch")
    if alert_handler:
        alert_handler(alert)
    logger.critical(
        alert.alert_type,
        extra={
            "severity": alert.severity,
            "artifact_id": alert.artifact_id,
            "expected_digest": alert.expected_digest,
            "actual_digest": alert.actual_digest,
            "blocked_marker": str(alert.blocked_marker),
            "quarantined_path": (
                str(alert.quarantined_path) if alert.quarantined_path else None
            ),
            "quarantine_error": alert.quarantine_error,
        },
    )


def compute_file_digest(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as blob_file:
        for chunk in iter(lambda: blob_file.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def next_quarantine_path(directory: Path, name: str, digest: str) -> Path:
    base_name = f"{name}.{digest}.corrupt"
    destination = directory / base_name
    if not destination.exists():
        return destination
    counter = 1
    while True:
        candidate = directory / f"{name}.{digest}.{counter}.corrupt"
        if not candidate.exists():
            return candidate
        counter += 1


def block_marker_payload(
    *,
    artifact_id: str,
    expected_digest: str,
    actual_digest: str,
) -> Mapping[str, str]:
    return {
        "artifact_id": artifact_id,
        "reason": "artifact_integrity_mismatch",
        "expected_digest": expected_digest,
        "actual_digest": actual_digest,
    }


def write_blocked_marker(
    marker_path: Path,
    *,
    artifact_id: str,
    expected_digest: str,
    actual_digest: str,
) -> None:
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.write_text(
        json.dumps(
            block_marker_payload(
                artifact_id=artifact_id,
                expected_digest=expected_digest,
                actual_digest=actual_digest,
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def load_blocked_alert(
    marker_path: Path,
    *,
    manifest: ArtifactManifest,
    blob_path: Path,
) -> IntegrityAlert:
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        marker = {}
    return IntegrityAlert(
        artifact_id=str(marker.get("artifact_id") or manifest.artifact_id),
        expected_digest=str(
            marker.get("expected_digest") or manifest.digest
        ),
        actual_digest=str(
            marker.get("actual_digest") or "blocked_cache_reuse"
        ),
        blob_path=blob_path,
        blocked_marker=marker_path,
    )


def require_manifest_string(
    payload: Mapping[str, object],
    key: str,
    *,
    fallback_key: Optional[str] = None,
    default: Optional[str] = None,
) -> str:
    value = payload.get(key)
    if value is None and fallback_key:
        value = payload.get(fallback_key)
    if value is None:
        if default is not None:
            return default
        return ""
    if not isinstance(value, str):
        raise ArtifactManifestError(f"{key} must be a string")
    return value.strip()


def validate_digest(algorithm: str, digest: str) -> None:
    expected_length = hashlib.new(algorithm).digest_size * 2
    if len(digest) != expected_length:
        raise ArtifactManifestError(
            f"digest length for {algorithm} must be {expected_length}"
        )
    if any(character not in "0123456789abcdef" for character in digest):
        raise ArtifactManifestError("digest must be lowercase hexadecimal")


def raise_integrity_error(alert: IntegrityAlert) -> None:
    message = (
        f"{alert.artifact_id} expected {alert.expected_digest} "
        f"but read {alert.actual_digest}"
    )
    if alert.quarantine_error:
        message = f"{message}; quarantine failed: {alert.quarantine_error}"
    error = ArtifactIntegrityError(message)
    error.alert = alert
    raise error
