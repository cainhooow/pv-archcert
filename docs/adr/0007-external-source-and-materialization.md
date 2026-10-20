# ADR-0007: Incomplete external source and credential-free runner handoff

## Status

Accepted for Milestone 1.

## Decision

Validated source can be sealed as either `COMPLETE` or
`INCOMPLETE_EXTERNAL_SOURCE`. Rejection produces typed failure evidence and no
snapshot. These states describe source availability, not certification verdicts.

Gitlinks record their path and referenced commit without fetching any remote.
Recognizable Git LFS v1 pointers record their path, claimed SHA-256 and claimed
size, while retaining the original pointer blob. All external entries are
unresolved; a claimed external hash is never used as verified file content.
Recognizable malformed/extended/unsupported pointer formats fail closed. This
version recognizes regular/executable blobs beginning with the LFS specification
version prefix. It does not consult `.gitattributes`, LFS servers, `.gitmodules`,
or network configuration. Those files remain ordinary untrusted source data.

The application emits `Received`, `Quarantined`, `ValidationStarted`, and then
either `Rejected` or `Accepted`/`SnapshotCreated` structural events. Evidence
includes request and resolution identities, manifest/object counts, sizes,
external dependencies, authority limits, schema/validator versions and timestamp.
Events are returned even on rejection; no durable audit-log claim is made.

The development `MemorySourceStore` owns immutable snapshots for the process
lifetime. Retention and retrieval by the returned read-only handle preserve
bytes independently of the repository. The CLI prints structured evidence but
does not persist a reusable source artifact. Durable storage and crash recovery
are deferred; serialized reports alone cannot reconstitute accepted source.

The future `SourceMaterializer` receives only an immutable snapshot and expected
source digest. It must require complete source, copy retained bytes into an
ephemeral filesystem without following symlinks, independently verify the
materialized canonical identity, remove any acquisition credentials and only
then return a runner-ready volume. It receives no repository locator/credentials.
No materializer, sandbox, Docker execution or credential injection is implemented
in this milestone. The interface contract is preparation, not proof of future
adapter behavior.

## Consequences

Ingestion does not contact attacker-selected remote URLs or execute repository
code. Unresolved external source cannot accidentally satisfy `require_complete`.
A later external-source resolver must bind fetched bytes to the recorded
identity, create a newly versioned resolved source representation and preserve
provenance. It must not mutate this immutable snapshot in place.
