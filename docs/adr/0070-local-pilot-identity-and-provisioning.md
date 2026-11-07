# ADR 0070: Bounded local pilot identity and project provisioning

Status: Accepted for development implementation; acceptance is recorded separately.
Date: November 6, 2026. Extends ADRs 0028, 0035–0040 and 0051–0059.

## Context

External bearer provisioning and a historical evidence preview do not provide a
fresh local installation. A local operator needs durable account bootstrap and
project registration without gaining browser-selected policy, runtime or signing.

## Decision

Add an opt-in local identity/provisioning service separate from Glassmere. Its
application port contains a closed set of operations. The panel calls a fixed
loopback endpoint with a separate private random credential. The panel retains
SELECT-only authority observation, existing server sessions, Origin/CSRF checks,
limits and original evidence verification. Legacy bearer deployments retain their
contracts. Local password mode rejects browser bearer exchange.

The explicit host installer applies migration 0011 and creates an instance UUID
and a 30-minute single-use random setup secret outside source. PostgreSQL's
singleton row and conditional update serialize the first administrator transition
with account insertion and audit. INITIALIZED cannot transition back to setup.
Missing/mismatched database state, dependency failure or incomplete publication is
RECOVERY_REQUIRED, never a reason to initialize again. The host may renew only an
unconsumed bootstrap secret. No startup path performs migrations.

Passwords use RustCrypto Argon2id v19, 64 MiB, three iterations, one lane, random
128-bit salt and 256-bit output. Normalized ASCII email is unique. Local account
records retain an independent random panel credential; only its SHA-256 is
published to the panel. No human password uses a bearer hash. All secret exchange
is private loopback HTTP in this pilot; this is not a public or production IAM.

Local account state and grant generations are authoritative in PostgreSQL. Each
authenticated local panel request independently rechecks enablement/generation.
The panel's existing session revision also binds exact role/project assignments.
Host role changes and password recovery rotate credentials/generations and audit
atomically. Restart expires sessions while preserving accounts. A database-backed
shared login budget survives process restart. No browser storage holds tokens.

The host delegates only creation of new owned projects under one selected Python
command recipe and digest-pinned image. The browser supplies names, an exact
repository identifier and an Ed25519 public key; it supplies no project UUID,
actor, authority recipe, image, runtime or signing key. The service generates UUIDs
and atomically commits project, repository grant and audit. Each repository needs
a separate SSH public key. Existing Northgate handles forced commands, quarantine,
pack validation and immutable source. There is no web clone/import or external
LFS/submodule acquisition. Local onboarding selects SHA-1 Git; existing other
formats remain available through their original explicit provisioning.

Private panel/gateway/controller configuration files are rebuildable projections.
Mutations retain publication-pending state in the database before file publication.
A host `publish` reconstructs exact durable assignments after interruption; it
never reopens setup. Publication uses private temporary files, fsync and atomic
replacement; an advisory lock coordinates host and service publishers. A partial
projection grants no valid local session because current DB revision is mandatory.

Certification resolves accepted complete source through the existing control-plane
admission operation, pinning project/repository/commit/tree/snapshot/policy/plan and
scoped idempotency. The independent trusted controller polls existing `run-once`;
its worker remains a credential-free child. Existing startup reconciliation, leases,
gates, accepted evidence, failure classification and signing are unchanged. The
launcher never prunes unknown resources. A panel process being healthy establishes
neither runtime readiness nor certification success.

Local status checks the required migration and opens the existing artifact/source
stores through their original private no-follow adapters. Artifact headroom is
checked without publication. Missing or unsafe stores are reported as ERROR,
without creating replacement directories or reopening initialized accounts.

Development signing requires the host's explicit configure-authority operation.
Only controller invocations receive signing-key paths. Workers receive an explicit
runtime endpoint for execution or diagnostics; panel and ingress receive neither.
M6 remains a separate
operator lifecycle and is unavailable in the local onboarding UI. No arbitrary
build recipe, semantic provider, production signing or native qualification is added.

## Security implications and limitations

The local service is trusted identity and bounded provisioning authority, not a
signer or runner. Dependency guards exclude signing/runtime/provider capabilities.
Migration, control and SELECT-only observation DB roles are separate; no DB
credential reaches a worker. Local control is not an adversarial multi-tenant IAM
or row-level-security system. Same-UID/root, migration administrator, runtime and
filesystem compromise remain outside this development boundary. Private credentials,
source/evidence and backups are unencrypted at rest. Production requires distinct
OS identities, stronger custody, TLS and an independently reviewed IAM deployment.

The initial administrator has no cross-project wildcard. Only projects it creates
are assigned. Additional account creation, account transfer, browser policy edits,
release execution and imported remote Git are unsupported in this slice. Host
password recovery is explicit and audited; there is no browser reset backdoor.

## Alternatives and consequences

A privileged all-in-one container, Docker socket in the panel, target-selected
clone commands, file-only bootstrap, default passwords and framework replacement
were rejected. The extra local service makes the existing observation boundary
visible and preserves independently provisioned execution/signing. Operational
projections and complete backups require deliberate recovery. This local delivery
does not close M9, start M10/M11, Pre-Genesis or Genesis, or independently certify
ArchCert. Acceptance must use new storage, real SSH ingress and actual execution;
missing prerequisites remain explicit blockers.
