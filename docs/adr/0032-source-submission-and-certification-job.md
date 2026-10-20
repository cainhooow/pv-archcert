# ADR-0032: A source submission is not a certification job

Status: Accepted for Northgate; extends ADR-0019.

Git push authenticates and authorizes source reception only. SourceSubmissionId
identifies the reception/audit instance; GitActorId/DeviceKeyId identify its actor
and public authentication key; ProjectId/RepositoryId identify authority scope;
SourceIdentity identifies immutable commit/tree/ArchCert SHA-256 bytes. These are
separate even when storage can later deduplicate identical sources.

The gateway publishes source evidence and immutable source, never creates a
CertificationId/job, chooses policy, runs checks or loads a key. A later operator
can inspect `archcert source show ID --store ROOT` and independently request
`archcert certify --source-submission ID --source-store ROOT ...` with the existing
authority/profile/policy/digest/key arguments. Store retrieval checks scope and
source identity, then gives only owned source bytes to the M2–M4B chain. Source
can be reused under another authority/execution/policy request without reception.
CertificationJobRequest prepares the future exact SnapshotReference-based port;
it creates no queued job or durable persistence. REST remains 501 UNAVAILABLE.

No acquisition credentials are needed after source resolution. No repository URL,
Git/LFS/submodule/SSH credential, session, public actor authenticator or store
capability enters RunnerInput, materialized files, target environment or signer.
Authority configuration/key/output paths remain outside source/store/workspaces.
