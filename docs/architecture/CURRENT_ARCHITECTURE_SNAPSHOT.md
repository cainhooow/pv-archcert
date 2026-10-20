# Current architecture snapshot — Stoneward with Ironcrest work in progress

Ironcrest architecture is defined in ADRs 0041–0042 and
threat-model/SEMANTIC_REVIEW.md. The design adds immutable knowledge, bounded
semantic veto and authority challenge selection above the existing trust core.
At this design checkpoint these components are not integrated or qualified;
no Ironcrest completion or semantic issuance guarantee is claimed. Historical
policy/certificate semantics and the exact Stoneward qualification remain intact.

ArchCert accepts authenticated SSH Git pushes with bounded SHA-1/SHA-256 packs
or explicit local loose objects, seals an independently hashed
source snapshot, resolves authority execution plans, executes under rootless OCI,
evaluates typed observations deterministically, and can issue a DEVELOPMENT ONLY
Ed25519 certificate after full integrity validation, signing and offline verification.
Eligibility remains unsigned and cannot itself report CERTIFIED.

```text
Authenticated HTTP -> protocol -> admission composition -> application ports -> PostgreSQL
Operator source export ---> protocol Protobuf adapter -> application ingress read model -> domain
CLI execution ------------> application + source/materialization/runner adapters
CLI evaluation -----------> policy -> application + domain
CLI certification --------> certificate -> policy + application + domain + evidence + crypto
Evidence -----------------> policy + application + domain
Crypto -------------------> mature Ed25519/SHA-256/key-encoding implementations
```

No signer/key dependency exists in runner, source, materialization, application,
policy, project configuration or daemon graphs. Crypto imports no workspace crate.
The CLI is trusted operator composition; target access to its flags/process would
be authority access. The architecture guard enforces both direct and transitive
signing exclusions and checks the execution interfaces for key/signing types.

```text
accepted exact SourceSnapshot
  + immutable authority ValidationPlan
  + separately pinned immutable PolicyBundle
  + independent execution identities
  + typed controller observations
    -> PolicyEvaluation (schema 1, five verdicts, structured findings)
    -> ELIGIBLE_FOR_CERTIFICATION gate
    -> compare identities, resolve references, re-evaluate original inputs
    -> canonical detailed EvidenceBundle + deterministic EvidenceManifest
    -> owned immutable CertificateDraft / canonical payload / SHA-256 identity
    -> CertificateSigner (key ID and exact canonical message only)
    -> detached Ed25519 signature
    -> offline verification under explicitly selected public key
    -> IssuedCertificate / VerifiedCertificate -> CERTIFIED
```

Execution and both sandbox/source cleanup finish before the CLI prepares a draft;
any execution/cleanup failure rejects issuance. Private-key loading happens only
after complete draft validation. The development signer uses explicit authority
paths outside source/workspaces, owned private files, OS cryptographic randomness,
PKCS#8 encoding and zeroizing buffers. No private bytes cross a runner/source/config
port or enter OCI transfer/environment. No production custody or hardware isolation
is claimed. The local signer shares the trusted controller OS identity.

Every authority-relevant certificate field is inside the signed payload: exact
project/repository/commit/tree/source digest, policy/version/digest, plan/evaluation/
manifest digests, finding IDs, versions, certifier/runner/isolation, issuance time,
scope, governance limitations, algorithm and stable public-key digest identity.
Certificate ID is SHA-256 of its canonical payload; it is not the signature.
The envelope adds only derived digest, detached signature and public material.

Schema-1 canonical JSON recursively sorts fixed ASCII keys, preserves Unicode
strings, rejects non-interoperable numbers, normalizes schema-defined sets and
emits compact UTF-8 without BOM/newline. Parsing rejects unknown/duplicate fields,
unknown schemas/algorithms, invalid/oversized fields and encodings within a 64 KiB
predecode envelope bound. Independent fixed Python/OpenSSL vectors supplement
Rust permutation, tampering, substitution and key-isolation tests.

The small certificate binds the manifest, which resolves typed observation/finding
references and binds the separate detailed canonical evidence bundle including
execution records and captured log prefixes. Detailed records must reproduce the
consumed observations against the exact plan. No logs are embedded in certificates.
Evaluation audit time does not change semantic evaluation identity; issued_at can
create a new certificate instance with unchanged source/evaluation identity.

| Vocabulary | Meaning |
| --- | --- |
| SOURCE ACCEPTED / COMPLETE | Validated immutable supported source; no unresolved required LFS/submodule content |
| MATERIALIZED | Verified/sealed under documented filesystem assumptions |
| OBSERVATION / COMPLETED | Controller fact; normal process exit includes nonzero |
| PROVEN | Authority evidence establishes the explicitly limited property |
| FAILED | Authority evidence establishes that the property is false |
| NOT_PROVEN | Required evidence absent/insufficient |
| NOT_APPLICABLE | Explicit authority applicability exclusion |
| INCONCLUSIVE | Contradictory, ambiguous, unsupported or infrastructure-impaired evidence |
| ELIGIBLE_FOR_CERTIFICATION | Every blocking requirement satisfied; no certificate yet |
| CERTIFIED | Canonical certificate successfully signed AND verified under the selected key |

Offline `archcert verify CERTIFICATE --public-key TRUSTED_PUBLIC_KEY` requires no
Git, Docker, workspace, network, database or private key. Embedded public material
is not trusted automatically. A valid signature authenticates recorded claims;
it does not establish universal software security or attest runtime binaries.
EXACT_SOURCE excludes branches/latest/future source/artifact/release/deployment.
NO EXPIRATION SEMANTICS YET. Revocation is NOT IMPLEMENTED; replay for the exact
same source is allowed. Trust-anchor distribution remains administrative.

M1–M4A source, materialization, isolation, fixed environment/network/resource,
structured observations and mandatory authority-policy guarantees remain active.
Project configuration cannot select signer/key/algorithm/authority or weaken policy.
No AI participates in issuance. Ravenport now implements authenticated durable
HTTP job admission/status and PostgreSQL metadata. No web UI, release permit, artifact certification,
waiver, policy inheritance, production KMS/HSM/PKCS#11, revocation or transparency
service is added. Only the exact Stoneward native profile is qualified; see qualification/NATIVE_LINUX_RUNNER.md.

See ADRs 0025–0027, MILESTONE_4B_REPORT.md, the certificate/signing threat model,
TCB_AND_DEPENDENCIES.md and CRYPTO_DEPENDENCY_REVIEW.md.

## Northgate ingress

```text
OpenSSH public-key auth -> explicit actor/device/repository grant
 -> fresh private quarantine -> bounded gitoxide pack decoding + M1 source validation
 -> isolated Git receive adapter -> immutable SourceSnapshot + ingress evidence
 -> separate later control-plane certification request -> existing M2–M4B chain
```

archcert-gateway and its standalone executable have no direct/transitive execution,
policy, Docker, evidence, certificate or signing dependencies. Git's bounded
advertisement/report handling runs with cleared configuration/environment and no
hooks. It is observed, not cryptographically attested. Each push is a new
submission; branch names are provenance and cannot mutate earlier snapshots.
One branch, create-only commands and self-contained packs are the initial contract.
A shallow declaration is supported only for the exact selected commit.

The finite local development store retains verified source separately from jobs.
`source show` and later `certify --source-submission` reuse immutable bytes without
Git acquisition. No acquisition credential reaches RunnerInput or certificate
signing. Ravenport REST now admits separate durable jobs. Source schema 1 is unchanged; old/new source identities
and Bottle policy behavior are reproduced by real SSH push/OCI regressions.

ExternalSourceAuthority verifies bounded LFS bytes and exact authority-mapped
submodule snapshots into a new immutable schema-2 SourceSnapshot. An operator-only
private LFS/accepted-child adapter enforces exact scoped grants. SourceBinding
carries only immutable identity metadata through artifact reload, materialization
and independent stopped-sandbox verification. Unresolved pointers/gitlinks remain
INCOMPLETE_EXTERNAL_SOURCE and cannot run; remote acquisition is not automatic.
See ADRs 0028–0033, NORTHGATE_DEPENDENCY_REVIEW.md, the Northgate threat model and
MILESTONE_5_REPORT.md for implementation evidence and limitations.

## Internal protocol contracts and Northgate completion

Protocol Buffers are the primary internal machine-to-machine schema/wire format.
The existing archcert-protocol crate generates common.v1/source.v1 DTOs using
pinned prost/prost-build and bundled protoc. Domain/application remain independent
of generated DTOs, prost, prost-types, and tonic; architecture guards enforce
direct and transitive exclusions. No tonic or actual RPC service is introduced.

IngressEvidence projects into a transport-independent application read model;
the operator `archcert-gateway export-proto` command emits validated binary source
observations after the existing immutable store load/rehash. It represents exact
source identity, Git/actor/device provenance, completeness, and resolved schema-2
binding summaries without credentials, origins, filesystem paths, or capabilities.
It cannot reconstruct accepted source or grant certification/execution authority.
SSH reception, current storage formats, and execution/signing paths are unchanged.

Protobuf bytes are not cryptographic canonicalization. Existing source, policy,
certificate/signing, and evidence canonical structures remain authoritative;
SHA-256 of Protobuf may identify only an exact serialized artifact. Unknown fields
cannot create trusted positive semantics. Future signer requests must be narrow,
certificate-specific contracts and cannot expose arbitrary-data signing.

The final protocol task and required gate results are recorded in
[MILESTONE_5_PROTOBUF_REPORT.md](../MILESTONE_5_PROTOBUF_REPORT.md), completing
M5 Northgate. Its [handoff plan](RAVENPORT_PLAN.md) records the original
Ravenport scope; the implementation below adds durable jobs and local worker
process contracts. See [ADR 0034](../adr/0034-protobuf-internal-protocol-contracts.md)
and [protocol architecture](PROTOBUF_PROTOCOL_CONTRACTS.md). Earlier reports retain
their historical results.

## Ravenport implementation in progress

The domain now defines pinned job inputs, explicit job/attempt states, bounded
attempt budgets and immutable job/attempt/fencing identities. Application owns
repository/read-model contracts. archcert-storage implements PostgreSQL admission,
scoped idempotency, row-locked claims, fenced leases, immutable artifact metadata,
issuance bindings and append-only audit through explicit SQLx migrations. Real
PostgreSQL tests cover concurrency and recovery. Authenticated loopback HTTP now
admits actual durable jobs and returns status. archcert-controller resumes durable
evaluation/issuance and dispatches a separate leased worker process. ADRs 0035–0037 govern the implementation.

ImmutableArtifactStore now has an explicitly unencrypted local development
adapter: project-scoped SHA-256 keys, atomic create-only publication, fsync and
bounded verified retrieval. ArtifactCipher defines the future encryption seam.
No production encryption provider or MinIO-specific semantics are implemented.

Ravenport worker process models and execution.v1 Protobuf assignment/result
contracts are implemented. Checked adapters retain existing operational evidence
serialization and canonical source identities. Pinned authority plans reconstruct
only from retained commands/image and must match their stored digest. Source
artifact acceptance and actual lease authority remain separate from wire decoding.

archcert-worker is now an actual separate execution executable. Its dependency
graph excludes metadata storage and signing. An authority-owned private stdin
assignment supplies verified source artifact bytes; stdout returns only the
versioned result envelope. Runtime configuration remains operator-only. The
worker rechecks source scope/identity and reports source/sandbox cleanup separately.
All eleven existing live rootless OCI regression groups passed for this boundary.

The trusted controller records EVALUATING with a durable phase time and preserves
structured policy/infrastructure/signing/verification failures. It reconstructs
observations only from a structurally bound persisted worker result. Eligibility
and exact issuance time/key/payload digest precede signing. Verified immutable
certificate metadata and audit commit with COMPLETED. Controller restarts after
execution/evaluation/signing do not repeat target commands. Lease expiry recovery
preserves prior attempts and requires confirmed runtime cleanup after target start.
See RAVENPORT_OPERATIONS.md for the explicit supervisor/run-once deployment and
its local development role/encryption/cleanup limitations.

## Stoneward native execution qualification

The pre-change capability matrix remains in the intentionally untracked M5.2
baseline working record. The exact Ubuntu 26.04.1/KVM/rootless profile is qualified; authoritative
status and support limits are in qualification/NATIVE_LINUX_RUNNER.md. Worker
`doctor` reports runtime prerequisites without accepting an execution assignment
or gaining control-plane credentials. Runtime evidence now retains the explicitly
selected Unix endpoint and reported daemon ID/security options/default runtime.
These observations do not attest runtime binaries or establish native deployment.

Stoneward now adds durable attempt/runtime bindings, irreversible DB fencing,
audited bounded cleanup states and a persistent local execution gate. Workers
receive no database credential. Each execution holds the gate through runtime
operations/cleanup; revoked gates reject stale later steps before the runtime API.
Controller startup and `reconcile` combine DB state/expiry, the exclusive gate,
bound daemon identity and exact ownership labels. Busy workers, unknown ownership,
late-create uncertainty and cleanup failures block retry. Accepted evidence closes
execution authority; continuation reconciles cleanup before policy/signing without
rerunning targets. The precise single-host protocol is in ADR 0039. Native OCI and
PostgreSQL, recovery/outage, offline verification and final residue-cleanup demonstrations passed on the exact documented profile.

Stoneward preserves certification semantics while adding single-host durable
execution fencing, ownership-scoped runtime reconciliation, separate cleanup
metadata/audit, dependency readiness and staging recovery. The worker holds a
private persistent attempt gate before all runtime resource creation. Recovery
revokes that gate before recording the PostgreSQL fence; runtime termination and
absence plus durable SUCCEEDED cleanup precede retry. Uncertain pending daemon
creation blocks indefinitely. Committed evidence is validated/adopted without a
target rerun. See ADRs 0038–0040 and the native qualification document for the
precise trusted-worker/filesystem profile and observed deployment limits.
