# ADR 0050: Versioned Greywatch claims and immutable citations

Status: Accepted. Date: October 31, 2026. Extends ADRs 0042–0047.
Milestone status is separately reconciled in ADR 0045.

## Context

The controlled review lifecycle already freezes bounded requests, retains exact
accepted bytes, conservatively handles uncertain invocations, mediates challenges
and independently evaluates deterministic policy. Its historical response has no
structured assertion polarity, discovery or source citation. Opposite prose cannot
be compared mechanically. Its package includes the reserved job UUID. Changing the
meaning of those bytes would break recovery and assurance identities.

## Decision

Add `archcert-greywatch-v1/1.0.1`: request schema 3, package schema 2, provider
response schema 2 and accepted review schema 2. The request pins the full protocol
descriptor, template version, response/normalization schema, fixed authority
instruction digest and citation/discovery/contradiction policies. Changes to these
interpretation inputs require an explicitly new version and semantic identity.

Stable semantic identity binds the package, protocol, reviewer and limits. Package
identity excludes operational job UUIDs; the invocation request still binds the
actual job and every immutable source/authority input. Responses must reproduce its
exact digest. Identical semantic inputs never authorize cross-session response
replay. Existing bounded authority selection is reused. Final serialization after
adding protocol context must fit the original ceilings or fail before invocation.
Both mandatory descriptor copies and their envelope fields are reserved before
optional context selection. This reservation changes no authority ceiling or
historical package; selected/excluded counts describe the resulting new package.
The new controller path retains `SemanticContextLimit` as an explicit incomplete
coverage error before invocation; historical preparation error mapping is unchanged.

Claims have local IDs, subject/proposition keys, assertion/denial polarity,
untrusted explanation and separate supporting/contradicting citations. Provenance
is the containing immutable review, raw response, exact request/session, provider
and frozen invocation audit time. Normalization records UNVERIFIED or
REQUIRES_AUTHORITY_RESOLUTION; neither is a deterministic verdict. Opposite
polarities for the same exact keys produce a canonical contradiction record and
require more evidence. Reported contradictory citations also require resolution.
No general natural-language consistency detection or provider honesty is claimed.

Discoveries have a separate typed supplemental model. They create no deterministic
FAILED/PROVEN result or automatic certificate blocker. Existing explicit
authority-related BLOCKING_CONCERN items preserve conservative veto semantics.
UNREVIEWED_AREA requires more evidence. Provider text cannot impersonate human
disposition or authorize challenges.

Citations have a closed grammar: exact admitted snapshot/path/file digest/inclusive
line range, knowledge digest/node ID, included observation digest, or selected
authority reference. Unknown paths/lines/nodes/evidence/policies, substituted
digests and unsupported fields reject the response. A valid citation establishes
object identity only. Filenames in free prose remain unverified text.

COMPLETED, REFUSED and CONTEXT_EXHAUSTED are provider outcomes. Refusal/exhaustion
must be incomplete and contain no analysis/proposal. They require more evidence.
Transport failures retain classified uncertainty. Non-expiring invocation claims
still mean remote receipt may be unknown: timeout/process death never permits an
automatic retry. There is no session expiration, wall-clock trust or TTL reclaim.

## Retention, recovery and disclosure

Valid bounded raw response bytes remain verbatim with digest/size/provenance.
Accepted reviews additionally retain normalized claims/discoveries/conflicts.
Recovery reparses raw bytes under the pinned protocol and compares normalization;
recomputed tampering digests cannot create acceptance. Invalid bounded output
retains digest/size/classification without raw bytes. Oversized output retains
size/classification without unbounded hashing. Provider diagnostics/credentials
are never evidence. There is no separate mutable claim table.

Only local exact replay and an unavailable default exist. No external provider,
network transport, SDK or credential provisioning is added. Replay model metadata
is fixture provenance, not a remote version guarantee. A local deadline fixture
qualifies adapter containment only. Remote delivery/partial response distinctions
and multiple-provider aggregation remain unimplemented. Consensus would not prove
truth. Deterministic request reproducibility is separate from model repeatability.

Source may already contain committed secrets. Private package retention is part
of admitted review, not permission for external disclosure. Target network stays
denied. No provider credential reaches execution, certificates or Release Permits.
Development controller/store/OS authority and same-UID risks remain unchanged.

## Compatibility and integration

Historical requests 1/2, response/review 1, policy/profile bytes, migrations,
certificate schema and release semantics retain their exact meanings. The new
protocol requires explicit authority opt-in and versioned profile identity;
absence preserves historical selection. Recovery never silently selects latest.
Changing a retained session's authority selection fails exact pin comparison.

The private authority grant selects `greywatch: true` only alongside required
controlled review. The controlled profile becomes 1.2.1 and the Rust profile 1.1.1,
with gate `archcert-greywatch-gate-v1/1.0.0`. Both explicitly select bounded partial
engineering context while retaining mandatory policy/invariant material and all
deterministic execution obligations. Historical controlled 1.1.0/Rust 1.0.0 profiles
retain their original context/gate semantics. Old sessions require the original
authority configuration; switching the grant cannot reinterpret them.

Protocol 1.0.1 explicitly reserves mandatory protocol-envelope bytes before optional
selection. The initial 1.0.0 foundation and development profile 1.2.0/1.1.0 runs
retain their original source/request identities; they are not reconstructed with
this changed selection budget. Their recovery requires the original authority
implementation, while already issued development certificates retain unchanged
offline verification. No stored artifact or previous certificate is rewritten.

The eight-role journal/manifest binds new REQUEST/REVIEW versions and therefore
every normalized item. No new signing/execution API or retry is introduced.
Manifest schema 2 recognizes REQUEST 3 only paired with REVIEW 2; historical
REQUEST 1/2 still requires REVIEW 1. PostgreSQL permits schema 3 only for REQUEST.
Existing migration checksums and role identities are unchanged.
Offline verification needs retained digests and the selected public key, never a
future provider call. There is no new human waiver workflow: unresolved sessions
block and require a separately authorized new workflow/additional evidence.

KEEP historical `ironcrest` modules, public identities, SQL/checksums, CLI and
immutable history. MIGRATE new explanatory prose to Greywatch. No ALIAS is needed.
M6/M7 scopes remain unchanged; Genesis and M9 are not started.

## Alternatives and validation

Heuristic NLP truth/contradiction judgments, trusting filenames, silently extending
old responses, mutable accepted artifacts, provider consensus as proof and retry
until CLEAR are rejected. Explicit keys bound mechanical contradiction coverage;
a provider can still omit or misdescribe a claim. Deterministic checks remain
necessary under CONTINUE.

Regressions cover exact bytes/restoration, typed contradictions, citation tampering,
framing/versions/limits, refusal/exhaustion, actual local adapter deadline,
injection separation, duplicate identity and cross-session replay. Architecture
guards prohibit transitive runtime/acquisition/persistence/signing capability in
provider adapters and provider HTTP clients in inward layers. Executed evidence
belongs under ignored `target/m8-closure/`; this ADR alone declares no closure.

> This is engineering self-validation under a shared implementation/authority context. It is not independent certification and does not replace Genesis / Firstwarden.
