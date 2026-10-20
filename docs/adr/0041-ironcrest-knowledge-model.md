# ADR 0041: Immutable, scoped knowledge above the trust core

Status: Accepted design for Ironcrest; implementation status is recorded in the
current architecture snapshot. Date: October 20, 2026.

## Context

Source acceptance establishes immutable bytes, not their behavior. Structural
knowledge and change impact can help select additional scrutiny without becoming
deterministic proof. Repository instructions, claims and apparent approval files
are hostile data. Historical policy identities and certificate schema 1 must keep
their exact meanings.

## Decision

Application owns extractor ports and knowledge orchestration. Domain owns the
transport-independent vocabulary, provenance, coverage and authority knowledge
types. Extractor adapters receive only a borrowed, verified, complete accepted
SourceSnapshot. They receive no filesystem path, write handle, runtime, network,
policy editor or signer. A registry has explicit versioned extractor identities;
no repository plugin discovery occurs.

The generic inventory records every accepted entry's exact path, digest, Git mode,
size and bounded classification. Structural extraction produces observed syntax,
never an asserted resolved call graph. Unsupported languages, macros, dynamic
dispatch, SQL and unresolved names become retained blind spots. A bounded typed
graph supports source files, symbols, modules, dependencies, tests, migrations,
entry points, policies, invariants, findings, claims, evidence and blind spots.
Typed edges describe their actual derivation and carry provenance. No graph
database or additional service is required.

Authority bundles are constructed through a separate trusted composition API,
never from target files. Each entry has stable ID/version/scope/severity/authority,
description, approval state and explicit supersession. Bundles are immutable and
digest-bound. Global scope must be explicit; project bundles reject foreign scope.
Knowledge may reference a pinned policy but cannot edit it. Claim text remains
untrusted even when it resembles a policy, finding or certificate.

An authority selects the baseline from an accepted source or trusted prior
certification. Both baseline and target must match project and repository. The
target has no baseline selection API. Missing baseline means FULL_REVIEW; uncertain
impact expands review. Manifest comparison includes content and mode changes,
additions and deletions. Structural change identity and bounded relation traversal
add tests, policies, invariants and findings; unresolved relationships remain
explicit. Impact never removes mandatory deterministic steps.

Artifacts bind schema/kind, project/repository, exact source identities, extractor
versions, authority bundle identities, limits and all retained observations.
Cryptographic identity uses a documented restricted canonical JSON representation:
fixed ASCII keys, recursively sorted keys, compact UTF-8, unchanged strings,
schema-defined ordered arrays and safe integers only. Protobuf is transport, not
canonical identity. No generated DTO enters domain/application.

Coverage is dimensional (complete, partial, unavailable), with reasons and blind
spots. Evidence provenance separately distinguishes direct observation,
deterministic derivation, authority assertion, semantic inference and unresolved
knowledge. Neither an aggregate intelligence score nor a correctness percentage
exists. Limit exhaustion is an explicit error or incomplete artifact, never
silent truncation with complete coverage.

## Security implications and consequences

Extraction interprets hostile bytes in the authority process. Parser dependencies
need review; finite file, byte, node, edge and traversal budgets constrain work but
do not prove parser memory safety or global availability. No target code, build
script, macro expansion or database executes during extraction. SQL identity is
always retainable; a schema model requires a separately supported parser.

Knowledge is evidence of what ArchCert observed or inferred, not proof of arbitrary
behavior. Bundle trust depends on operator provisioning and the trusted authority
process. Cross-project isolation must be checked before composition and replay.
Historical source/policy/certificate identities are unchanged.

## Alternatives

Mutable checkout analysis breaks source binding. Repository-owned approval files
confuse data and authority. Compiler-quality resolution claims without a compiler
are misleading. An extra graph service adds no required capability. All are rejected.
