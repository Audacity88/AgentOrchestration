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

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ArtifactManifest:
    """Digest metadata used to validate an artifact blob."""

    artifact_id: str
    digest: str
    algorithm: str = "sha256"


@dataclass(frozen=True)
class IntegrityAlert:
    """Operator-facing alert emitted for artifact corruption."""

    artifact_id: str
    expected_digest: str
    actual_digest: str
    blob_path: Path
    quarantined_path: Optional[Path] = None
    quarantine_error: Optional[str] = None


AlertHandler = Callable[[IntegrityAlert], None]
PathInput = Union[str, Path]
CHUNK_SIZE = 1024 * 1024


class ArtifactManifestReader:
    """Read artifact blobs through manifest digest validation."""

    def __init__(
        self,
        *,
        quarantine_dir: Optional[PathInput] = None,
        alert_handler: Optional[AlertHandler] = None,
    ):
        self.quarantine_dir = quarantine_dir
        self.alert_handler = alert_handler

    def read(self, manifest_path: PathInput, blob_path: PathInput) -> bytes:
        return read_artifact(
            manifest_path,
            blob_path,
            quarantine_dir=self.quarantine_dir,
            alert_handler=self.alert_handler,
        )


def load_manifest(path: PathInput) -> ArtifactManifest:
    """Load digest metadata from a JSON artifact manifest."""

    with Path(path).open("r", encoding="utf-8") as manifest_file:
        payload = json.load(manifest_file)
    return manifest_from_mapping(payload)


def manifest_from_mapping(payload: Mapping[str, object]) -> ArtifactManifest:
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
        algorithm=algorithm,
    )


def read_artifact(
    manifest_path: PathInput,
    blob_path: PathInput,
    *,
    quarantine_dir: Optional[PathInput] = None,
    alert_handler: Optional[AlertHandler] = None,
) -> bytes:
    """Read an artifact blob only after its digest matches the manifest."""

    manifest = load_manifest(manifest_path)
    blob = Path(blob_path)
    actual_digest = compute_file_digest(blob, manifest.algorithm)
    if actual_digest == manifest.digest:
        return blob.read_bytes()

    quarantined_path: Optional[Path] = None
    quarantine_error: Optional[str] = None
    try:
        quarantined_path = quarantine_blob(blob, actual_digest, quarantine_dir)
    except OSError as exc:
        quarantine_error = str(exc)
    alert = IntegrityAlert(
        artifact_id=manifest.artifact_id,
        expected_digest=manifest.digest,
        actual_digest=actual_digest,
        blob_path=blob,
        quarantined_path=quarantined_path,
        quarantine_error=quarantine_error,
    )
    emit_integrity_alert(alert, alert_handler)
    raise_integrity_error(alert)


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
    if alert_handler:
        alert_handler(alert)
    logger.error(
        "Artifact digest mismatch quarantined",
        extra={
            "artifact_id": alert.artifact_id,
            "expected_digest": alert.expected_digest,
            "actual_digest": alert.actual_digest,
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
