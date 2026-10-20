# Source ingress after Northgate

Northgate now connects authenticated real SSH Git push to the existing immutable
source boundary. LocalGitGateway remains the explicit loose-only development
adapter; PackedGitGateway validates normal received SHA-1/SHA-256 packs and
produces the same canonical schema-1 source. Manual pack-to-loose preparation is
no longer required. Real controlled/Bottle pushes and existing OCI/certificate
regressions are retained under docs/source-ingress/development.

| Boundary | Implemented | Further work |
| --- | --- | --- |
| Packfiles | Bounded mature headers/deltas, checksums, count/byte/depth/expansion/work limits, exact selected source | Fuzzing, broader interoperability, bounded shared thin-base storage if needed |
| Authentication | Restricted OpenSSH public keys, actor/device IDs, explicit repository grants, disabled key state | Production provisioning, rotation, separate OS identity/containment and deployment qualification |
| Ref mapping | One create-only branch, exact commit/tree, private candidate identity, limited exact shallow declaration | Additional workflows only with deterministic semantics |
| External source | Strict LFS pointers; exact operator private LFS/accepted-child resolver; new immutable schema-2 snapshots verified through execution | Allowed authenticated remote network adapters, DNS/redirect controls and Git LFS Batch API integration |
| Completeness | Unresolved LFS/gitlinks stay INCOMPLETE_EXTERNAL_SOURCE and cannot execute/qualify | No silent promotion or mutation of previous identities |
| Source storage | Finite private local development artifacts, rehash/scoping, reusable across later requests, replaceable SubmissionStore | Ravenport durable transactional retention/access/audit/crash recovery |
| Certification job | Explicit separation and exact immutable future job request; CLI later composes existing chain | REST remains 501; no durable scheduling yet |
| Internal protocol | Versioned common/source v1 Protobuf DTOs, checked application projection and operator export | Extend only for real Ravenport boundaries; no Protobuf cryptographic canonicalization |

Schema-2 accepted snapshots now carry immutable identity recipes through the
credential-free materializer and runner. Northgate does not fetch candidate
.gitmodules URLs or provision remote LFS credentials. The operator provisions a
private local LFS directory and exact accepted-child grants; acquisition authority
is dropped before execution. See ADRs 0028–0033 and MILESTONE_5_REPORT.md for exact
implemented scope and remaining risks.

The final Northgate contract task is recorded in
[MILESTONE_5_PROTOBUF_REPORT.md](../MILESTONE_5_PROTOBUF_REPORT.md).
[Protocol architecture](PROTOBUF_PROTOCOL_CONTRACTS.md) and ADR 0034 govern the
next milestone, [M5.1 Ravenport](RAVENPORT_PLAN.md). Future CertificationJob,
ValidationObservation, ExecutionEvidence, PolicyEvaluation transport, worker
assignment/result, signer request/result, and audit events have no speculative
schemas yet. Source reception and certification remain separate. The signer must
never become an arbitrary-data signing oracle, and evidence artifact wire hashes
must not replace existing canonical semantic bindings.
