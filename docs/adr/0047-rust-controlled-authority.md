# ADR 0047: Separate controlled Rust authority and trust challenge

Status: Accepted. Date: October 21, 2026. Extends ADRs 0020, 0042–0046.

## Context

The Python settlement profile is a deliberately narrow fixture contract. Applying
it to ArchCert or an ordinary Rust workspace would invent a challenge obligation
unrelated to the source. Pre-Genesis engineering validation needs a supported Rust
path while preserving historical profile/policy and certificate semantics.

## Decision

Add `rust-workspace-review-v1` version 1.0.0, separately constructed by authority
composition. It pins `archcert-rust-controlled-v1` version 1.0.0, local exact replay,
mandatory semantic review, denied external disclosure/network, the Rust extractor
registry, scoped Rust trust invariant, ADR 0046 packaging policy/digest, challenge
registry, gate algorithm and explicit partial engineering context acceptance.
Repository content never provisions this capability. The existing private grant's
execution family selects this new supported composition before target inspection.
The Python settlement profile, registry, policy and historical bytes are unchanged.

`rust-workspace-v1` is a separate execution family, with cargo/rustc/Python 3 supplied
by its explicitly approved image. Its authority ceilings are 900 seconds per step,
2 CPUs, 8 GiB memory, 256 tasks, 6 GiB scratch per mount and existing bounded output
prefixes. This does not change the historical `rust` family or Stoneward mechanism.
An authority recipe supports fmt, locked all-target/all-feature check and Clippy,
locked workspace tests, warnings-denied rustdoc and cargo-deny. The image must
provide the exact required tools, offline dependency cache and authority launcher;
no dependency installation or network allowance is granted during target execution.
Tools are an image provisioning requirement, not an assumption about Rust projects.

The Rust challenge registry pins `rust-inward-architecture-v1` version 1.0.0.
Authority Python source is embedded as literal argv (`python3 -I -c ... 1`) through
the unchanged runner. It invokes offline locked Cargo metadata inside OCI, checks
bounded package/edge counts and iteratively inspects named layer closures. Named
`*-domain` and `*-application` layers exclude transport/provider/signing dependency
families; `*-semantic` layers exclude signing. It also checks that the sandbox user
cannot create files on /source. No repository script or test implements the guard.
The scope is structural named-layer dependency evidence, not analysis of arbitrary
source behavior, renamed roles or universal architecture compliance. Projects
without matching layer names receive no named-layer guarantee.

Semantic proposals may name only this registry template and repetition 1. They
cannot supply command, image, mount, runtime socket, network or limits. The fixed
required step is `rust-trust-architecture`. Plan construction, pending gate identity
and accepted execution-result checks resolve the exact authority registry digest.
CLEAR remains a semantic non-veto, with zero deterministic property contribution.

## Evidence, recovery and compatibility

The package persists inside the schema-2 request role. Existing create-only
publication and non-expiring provider claims remain in force. Schema-2 manifests
retain all eight roles; only the new Rust policy expects a schema-2 REQUEST
reference. Historical policies still require schema 1 for that reference, and all
historical manifest/certificate bytes retain their meaning. No certificate schema,
signing algorithm, database migration, worker lease or runtime-fencing change is
introduced. Issuer, controller and storage all require the reviewed chain for both
explicit semantic policies; historical admission cannot bypass the Rust prerequisite.

## Security implications and alternatives

The image/toolchain/cache and authority script are trusted supply-chain inputs.
Cargo metadata is hostile structured input; byte/package/edge/runtime/resource
bounds and iterative traversal limit expansion. Cargo may inspect repository config
inside the existing isolated execution boundary. The challenge does not establish
that package names convey honest intent or that a compiler, OS or dependency is
uncompromised. Same-sandbox tests and source remain mutually observable. Semantic
CLEAR cannot make a nonzero deterministic challenge eligible; policy independently
requires the fixed challenge and ordinary workspace checks.

Reusing settlement, running target-selected scripts as authority evidence, arbitrary
model shell generation and broadening historical Rust limits were rejected. A new
profile is explicit and auditable but requires operator image provisioning. This
is engineering self-validation under shared implementation/authority, not independent
certification, Genesis / Firstwarden or native Stoneward requalification. Canonical
M6 remains planned; M7/M8 remain substantially implemented ahead of sequence.

The private Rust authority grant may lower `semantic_request_bytes` within the
fixed 1 MiB maximum. The resulting packaging policy, semantic limits and authority
profile digest bind that exact bound before source packaging. Raising it or using
it with another execution family rejects. Recovery under changed bounds fails pin
comparison. This allows a real mandatory-overflow self-test session without adding
a target field or weakening a limit. Profile algorithm/version remain fixed;
parameterized immutable authority artifact identities distinguish the selections.
