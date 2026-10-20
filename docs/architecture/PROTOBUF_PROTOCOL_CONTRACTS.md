# Protocol Buffers internal protocol contracts

ArchCert uses Protocol Buffers as its primary internal machine-to-machine schema
and wire format: internal RPC, service boundaries, worker/control-plane messages,
typed events, source-ingress transport, and future signer contracts. Northgate
introduces contracts and an inspection/export boundary, not services or persistence.
See [ADR 0034](../adr/0034-protobuf-internal-protocol-contracts.md).

## Cryptographic non-canonicality

Protocol Buffers are **not** ArchCert's cryptographic canonical serialization format.
The same logical message does not imply the same wire bytes forever. Field order,
unknown fields, and encoder changes can produce different valid encodings. Neither
ordinary encoding nor a deterministic encoder option establishes semantic identity.
No Protobuf canonicalization scheme is introduced here.

SHA-256 of Protobuf bytes may identify that exact stored artifact only. It must not
replace existing explicit canonical encodings for PolicyBundle identity, Certificate
identity, certificate signing, or canonical evidence manifests/bundles. Existing
canonical source schemas 1 and 2 also remain unchanged. A future ExecutionEvidence
transport artifact can have an exact-byte artifact SHA-256, while policy/certificate
semantic identities remain bound through their separately defined canonical structures.

The compatibility test deliberately decodes two differently ordered encodings into
the same semantic observation. The golden fixture establishes wire compatibility,
not canonical cryptographic identity. Operational timestamps, submitted refs, actors,
and submission IDs do not become source identity. Protobuf JSON is unnecessary for
operation; any future JSON view is diagnostic transport output and must not be signed.

## Initial packages and ownership

```text
proto/archcert/common/v1/identity.proto   archcert.common.v1
proto/archcert/source/v1/source.proto     archcert.source.v1
```

Only justified common/source contracts exist. No empty execution, policy, evidence,
certification, or signer schemas are created. The existing archcert-protocol crate
owns generated DTOs, binary serialization, schema constants/descriptors, and explicit
validated conversions. Its bootstrap HTTP DTOs retain their existing behavior.
There is no tonic dependency, RPC service, job creation, or production deployment.

```text
generated DTO <-> protocol conversion <-> application ingress read model -> domain
Git ingress evidence -> application ingress read model -> protocol export
```

Domain/application never import generated DTOs, prost, prost-types, or tonic. The
application owns transport-independent observations and consistency checks; protocol
owns wire validation. Gateway evidence projects into those application observations
without depending on protocol. Only the operator gateway CLI composes both adapters.
The architecture guard rejects inward protocol/runtime dependencies, including
renamed packages, and traverses normal/build dependency graphs for indirect leaks.
Protocol is also restricted to application/domain workspace dependencies and cannot
acquire policy, execution, evidence, certificate, or signer authority.

## Source submission semantics and conversion

`SourceSubmission` has a required semantic `contract_version = 1` because package
names are not encoded in bare messages. This version is independent of existing
source canonicalization `schema_version` (1 or 2). Unrecognized versions fail closed.

Common messages carry distinct project, repository, submission, actor, device,
SHA-256, Git OID, and source identities. Transport text/bytes becomes a domain value
only through a checked constructor. Project IDs use canonical UUID text supported
by the existing ProjectId; actor/submission IDs retain canonical RFC 4122 UUID v4
rules. Repository labels retain the domain's ASCII/length grammar and are never
interpreted as paths. Source/device SHA-256 requires exactly 32 bytes. Git OIDs carry
an explicit SHA-1 or SHA-256 algorithm and require exactly 20 or 32 bytes; mixed
commit/tree/requested object formats reject. Future algorithms require explicit support.

The version-1 adapter rejects missing required messages, unknown/UNSPECIFIED enums,
invalid IDs/digest lengths, unsupported schemas, invalid branch provenance,
inconsistent completeness/status/identity/acceptance fields, and invalid timestamps.
All enum zero values are UNSPECIFIED. Defaults never mean success. Full binary
messages are bounded to 64 KiB before decoding. Raw generated `Message::decode`
is only wire parsing: callers use `decode_submission` or the checked `TryFrom`
conversion before consuming application observations. `encode_submission` also
checks consistency. Error messages exclude hostile values and private diagnostics.

`received_at` and optional `accepted_at` use google.protobuf.Timestamp. Northgate
currently records nonnegative whole UTC Unix seconds through year 9999; fractional,
negative, or out-of-range input is rejected rather than silently rounded. Acceptance
cannot predate reception. Timestamps never participate in source hashing.

RECEIVED, QUARANTINED, VALIDATING, and REJECTED have no accepted source or acceptance
time. ACCEPTED requires COMPLETE source; INCOMPLETE_EXTERNAL_SOURCE requires at
least one unresolved LFS/gitlink requirement and cannot imply runner readiness.
Accepted states retain the exact requested commit, resolved commit/tree, source
SHA-256, one submitted branch ref as provenance, object algorithm, and actor/device.
Resolution transport preserves original submitter/device attribution and separately
records the resolver actor.

SourceState carries source schema, completeness, unresolved counts, and an optional
schema-2 resolution summary: original identity, parent submission, resolver actor,
verified top-level LFS replacements and child expansions. This summary describes an
existing resolved binding. It deliberately does not export the recursive verification
recipe or source bytes and cannot reconstruct/accept a SourceSnapshot. The actual
SourceBinding and verification remain in the existing immutable source boundary.
No credentials, candidate origins, URLs, private keys, local paths, or acquisition
capabilities are fields in these contracts.

Decoding observations is neither authentication nor authorization and cannot create
a trusted snapshot, verified evidence, policy permission, certificate, or signer
capability. Ravenport must independently authenticate peers and validate retained
source bindings at its actual acceptance boundary.

## Northgate integration

The read-only operator command exports an already accepted, reloaded/rehashed source:

```sh
cargo run -p archcert-gateway-cli -- export-proto \
  --store /absolute/private/authority-store SUBMISSION_UUID > submission.pb
```

`IngressEvidence::source_submission_state` performs the single evidence projection.
`archcert_protocol::protobuf::{encode_submission, decode_submission}` forms the binary
boundary. SSH receive, development storage artifacts, source hashing, resolution,
materialization, execution, policy, signing, and offline verification retain their
existing formats and behavior. The export contains observations, not the complete
IngressEvidence audit record or any storage capability. Existing `show` JSON remains
human-readable diagnostics, not Protobuf JSON or a signed artifact.

The real SSH regression exercises export/decode for ordinary SHA-1, SHA-256,
incomplete external source, and resolved schema-2 submissions. OCI need not restart
for this inspection-only boundary; execution/signing code and inputs are untouched.

## Reproducible Rust generation

The crate's build.rs uses exact prost/prost-build/prost-types 0.14.4 and exact
protoc-bin-vendored 3.3.0 (bundled libprotoc 36.2). Cargo.lock pins transitive crates
and registry checksums, including all platform-specific compiler packages. Building
requires a supported vendored host platform; there is no system protoc installation,
PATH fallback, plugin installation, or build-time network compiler download. Normal
Cargo dependency fetching/caching still applies. Binary compiler supply-chain trust
is explicit in the [dependency review](PROTOBUF_DEPENDENCY_REVIEW.md).

Generation command:

```sh
cargo check -p archcert-protocol --locked
cargo test -p archcert-protocol --test protobuf_compatibility --locked
```

Rust DTOs and a FileDescriptorSet are generated only into Cargo OUT_DIR, never
committed or edited manually. The owned .proto sources are the source of truth;
committed .pb/.textproto files are compatibility fixtures, not generated Rust code.
Schema changes trigger regeneration. New imports must join the explicit build list.
CI's normal locked workspace check/test/doc gates execute the same generation and
compatibility tests; no developer-specific protoc setup is needed.

Only the two explicitly enumerated authority-owned schemas and bundled Google
well-known includes are inputs. Build.rs explicitly selects bundled protoc, ignores
ambient PROTOC selection, rejects PROTOC_INCLUDE overrides, and configures no plugins.
It does not discover .proto files recursively or read candidate repositories,
project configuration, received refs, or acquisition roots. Candidate repositories
must never influence ArchCert schemas, protoc plugins, compiler choice, or generated
authority code. Build this authority workspace only from trusted ArchCert sources.

## Schema evolution and compatibility

- Never reuse field numbers, including after removal. Reserve removed numbers.
- Reserve removed field names where appropriate, including diagnostic JSON concerns.
- Prefer additive backward-compatible changes; preserve existing field types,
  cardinality, presence rules, and semantic meaning. A wire-compatible edit can
  still be semantically incompatible.
- Incompatible semantic changes require a new package version such as v2 and an
  explicit adapter/version policy; do not merely reinterpret v1 fields.
- Every enum has explicit zero UNSPECIFIED. Unknown/default required values reject.
  Never use defaulting enum getters to silently promote unknown input to success.
- Unknown additive fields may be decoded and ignored. Prost does not promise to
  preserve them through re-encoding. Old components cannot enforce new authority
  requirements hidden in such fields: use a new package/contract version for them.
- A future field cannot establish source verification, certification, network
  permission, or signing authority for an older consumer. Compatibility tests append
  such hypothetical claims to rejected/incomplete observations and verify unchanged
  semantics; they cannot fill missing required known fields.
- Keep golden wire artifacts readable under the supported version. Test semantic
  round trips, rejection paths, and additive compatibility, not canonical wire hashes.

## Ravenport handoff

[Ravenport planning](RAVENPORT_PLAN.md) reserves future families without implementing
schemas now: CertificationJob, ValidationObservation, ExecutionEvidence, PolicyEvaluation
transport, worker assignment/result, signer request/result, and audit events.
Each needs a real process/storage/service boundary and an authority review first.

Future signer RPC must be certificate-specific and narrow. An arbitrary-data
`SignRequest { bytes arbitrary_data = 1; }` is forbidden: callers must never turn
the authority signer into a general-purpose signing oracle. The existing canonical
certificate preparation/eligibility boundary must precede signing. Actual signer
RPC, durable jobs, persistence, recovery, distributed workers, and production RPC
remain M5.1 or later scope.
