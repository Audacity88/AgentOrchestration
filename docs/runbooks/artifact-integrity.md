# Artifact Integrity Runbook

Artifact reads validate blob content against the artifact manifest digest before returning data to callers.

## Digest mismatch alert

An artifact digest mismatch is treated as a data integrity failure, not a transient download error. The reader emits an `IntegrityAlert` with the artifact id, expected digest, actual digest, original blob path, quarantine path when available, and any quarantine error.

## Quarantine behavior

When validation fails, the blob is moved out of the cache location into the configured quarantine directory, or into a sibling `.quarantine` directory by default. Quarantine filenames include the full observed digest and preserve existing evidence by choosing a fresh suffix on collision. Moving the blob prevents later reads from reusing corrupted content from the cache path.

## Recovery

1. Keep the quarantined blob for investigation until storage owners confirm whether the source object or cache layer is corrupt.
2. Re-fetch the artifact from a trusted source and compare its digest with the manifest.
3. Replace or invalidate the manifest only after confirming the manifest itself was wrong.
4. If quarantine failed, immediately block the affected cache path at the storage layer before retrying reads.
5. Clear the quarantine entry after the incident record includes the expected digest, actual digest, artifact id, and storage backend involved.
