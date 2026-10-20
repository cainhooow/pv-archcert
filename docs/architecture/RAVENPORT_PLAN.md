# M5.1 — Historical Ravenport handoff plan

This preserves the Northgate handoff before implementation. Ravenport is now
implemented; current behavior and limits are in [operations](RAVENPORT_OPERATIONS.md),
[the architecture snapshot](CURRENT_ARCHITECTURE_SNAPSHOT.md) and ADRs 0035–0037.
The future-tense sections below record the original plan.

M5 Northgate establishes authenticated Git ingress, immutable ordinary/resolved
source snapshots, controlled external acquisition, execution/policy/development
issuance/offline verification, and versioned internal Protobuf contracts.
The [focused Northgate report](../MILESTONE_5_PROTOBUF_REPORT.md) records the final
protocol work and gate results. Earlier milestone reports remain historical records.

Protocol Buffers are the primary internal machine-to-machine schema/wire format,
not cryptographic canonicalization. Follow [the protocol architecture](PROTOBUF_PROTOCOL_CONTRACTS.md)
and ADR 0034. Generated DTOs remain outside application/domain. Common/source v1
and the source-only export are implemented; no RPC service or persistence is implied.

When real boundaries exist, Ravenport may introduce these contract families:

| Future family | Boundary to justify and constraints to preserve |
| --- | --- |
| CertificationJob | Exact project/repository/immutable SnapshotReference, separate from source reception; durable admission and state transitions need their own design. |
| ValidationObservation | Typed controller observations with exact execution/source/plan binding; target claims confer no authority. |
| ExecutionEvidence | Bounded execution evidence transport; exact artifact SHA-256 is separate from explicitly canonical semantic policy/certificate bindings. |
| PolicyEvaluation transport | Preserve deterministic policy identity, verdicts, findings, and independently checked references. |
| Worker assignment/result | Authenticated peers, finite capabilities, exact immutable source/plan/policy references; no implicit network or signing authority. |
| Signer request/result | Certificate-specific narrow requests after validated eligibility/canonical draft preparation; arbitrary-data signing is forbidden. |
| Audit event | Explicit operational ordering and retention semantics, independent of source identity and certification authority. |

No speculative .proto files or empty placeholder packages are created for these
families. New positive authority semantics require an explicit versioned consumer
contract; an unknown additive field cannot grant old consumers a new capability.
Signer RPC must never expose `SignRequest { bytes arbitrary_data = 1; }` or an
equivalent general-purpose signing oracle. Existing certificate-specific canonical
signing remains the governing boundary.

Ravenport work may address durable source/job/evidence storage, transactional
scheduling, crash recovery, worker/control-plane messaging, and qualified service
deployment. None is implemented by this handoff. Current local development stores,
OpenSSH operator provisioning, incomplete-source gates, immutable schema-2 recipes,
and credential destruction constraints remain in force. Production/native Linux
qualification and remote external-source acquisition remain separately scoped.
