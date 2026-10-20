# ADR 0037: Immutable artifacts and digest-bound signing recovery

Status: Accepted design for Ravenport. Date: October 20, 2026.

## Context

PostgreSQL and object storage cannot share a transaction. A crash around upload
or signing must neither fabricate an available object nor create a new issuance.

## Decision

An application ImmutableArtifactStore port exposes conditional immutable put and
verified bounded get. Implementations may use S3-compatible conditional writes or
a filesystem test/development adapter. Location never defines identity. Keys
include project authorization scope and SHA-256(bytes); deduplication never grants
cross-project reads. Every reference retains digest, size, producer, schema,
source, plan, execution/attempt and creation time as appropriate.

Register STAGING metadata, upload with create-only semantics, independently
rehash/read size, then transactionally mark AVAILABLE. Only AVAILABLE references
may advance a job. An upload error leaves STAGING, never a successful reference.
Unreferenced bytes after transaction rollback remain harmless orphans. Reconcile
staging by exact expected digest/size; missing/corrupt objects fail closed. No
automatic destructive orphan garbage collection is included. Objects referenced
by issued certificates must never be replaced. Missing objects invalidate retrieval
and continuation even if metadata says AVAILABLE.

Prepare private storage behind ArtifactCipher/KeyEnvelopeService boundaries.
Production hierarchy is root KEK -> organization/project KEK -> per-artifact DEK.
No custom cryptographic algorithm, plaintext signing-key storage, production
KMS/HSM or pretend encryption is introduced. The development unencrypted adapter
must be explicitly selected; sensitive production storage requires a real adapter.

After validated durable eligibility, prepare the canonical CertificateDraft with
a persisted issuance time, selected key ID and exact payload digest. Persist this
binding before sign(). A restart reconstructs and compares the same draft; any
changed field rejects under that issuance. Ed25519 signing is deterministic for
the same key/payload. Repeating this exact operation can recover a lost signature;
it never permits arbitrary data or new issued_at. Verify the returned envelope
under the separately trusted key, persist immutable envelope bytes, then commit
signature/key/digests/source/policy/job/attempt/verification metadata and COMPLETED.
No certificate flag exists without cryptographic objects. Export remains verifiable
with archcert verify without database or network.

## Security implications

Structural source/plan/attempt/execution bindings validate before evidence
publication and again before issuance. Neither worker reports nor object locations
can assert eligibility. Signing credentials exist only in trusted controller
composition after target cleanup; they never enter assignments, RunnerInput,
source, target environment, PostgreSQL or object storage.

## Alternatives considered

Upload followed by an unchecked row can lie about availability. Mutable keys allow
substitution. Blind signing retry with a new timestamp silently creates another
certificate instance. Signing Protobuf bytes would change canonical identities.

## Consequences

Orphans consume storage until reviewed reconciliation. Availability depends on
both metadata and verified bytes. Signing recovery needs retained original inputs
and the selected key, and rejects uncertainty instead of manufacturing completion.

Stoneward adds explicit development staging maintenance: private project-scoped
UUID stage files are inspected with no-follow descriptors and writer locks; only
old unlocked stages may be unlinked. Immutable digest objects are never garbage
collected by this command. Interrupted hard-link publication remains unavailable
until the abandoned staging link is removed and normal bytes verification passes.
Local storage headroom and current permissions are checked before new publication.
These controls do not provide encryption, arbitrary network-filesystem equivalence
or demonstrated host power-loss durability.
