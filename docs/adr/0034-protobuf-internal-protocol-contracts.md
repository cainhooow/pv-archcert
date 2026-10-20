# ADR 0034: Protocol Buffers for Internal Protocol Contracts

Status: Accepted. Date: October 20, 2026. Milestone: M5 Northgate finalization.

## Context

Northgate has authenticated Git ingress, immutable ordinary/resolved source,
controlled external acquisition, execution, policy, development issuance, and
offline verification. Ravenport will introduce actual durable process boundaries.
Those boundaries need explicit versioned machine contracts without coupling
application/domain ownership to wire types or altering cryptographic identities.

## Decision

ArchCert uses Protocol Buffers as its primary internal machine-to-machine schema
and wire format. Generated Protobuf DTOs remain protocol-layer types.
Domain/application models remain transport-independent. Protocol Buffers are not
ArchCert's cryptographic canonical serialization format.

The existing archcert-protocol crate owns generated common.v1/source.v1 DTOs,
checked conversions, binary helpers, and package/version/descriptor exposure.
Application ingress observations use existing validated domain identities. The
operator gateway export composes the source evidence projection and protocol
adapter. No tonic or RPC service is introduced.

Use pinned prost/prost-build with a pinned bundled protoc and authority-owned
explicit schema inputs. Generate Rust in OUT_DIR; commit only schema sources and
wire compatibility fixtures. Apply the fail-closed validation, evolution, and
build rules in [Protobuf protocol contracts](../architecture/PROTOBUF_PROTOCOL_CONTRACTS.md).
The architecture guard prevents direct/transitive inward Protobuf ownership.

## Consequences

Shared contracts can expand when real boundaries exist, with explicit package
versions and conservative enum handling. Protobuf bytes can identify an exact
artifact through SHA-256 but do not establish canonical semantic identity.
Policy, certificate/signature, source, and evidence canonical encodings remain
unchanged; no new canonicalization scheme is defined.

The wire codec and generated compiler chain add scoped protocol/build TCB, reviewed
in [the dependency inventory](../architecture/PROTOBUF_DEPENDENCY_REVIEW.md). Unknown
fields support additive compatibility but cannot introduce trusted positive semantics
in an older consumer. Transport observations alone grant no capability.

Future signer requests must be certificate-specific and cannot accept arbitrary
data for signing. Evidence transport hashes remain exact-artifact identifiers;
policy/certificate bindings continue through explicit canonical structures.
Ravenport owns future jobs, durable storage, recovery, worker messaging, and narrow
signer services; Northgate creates no speculative schemas or deployment here.
