# ADR 0071: Product accounts in the existing ArchCert API

Status: Accepted for development deployment; acceptance is recorded separately.
Date: November 7, 2026. Supersedes ADR 0070's separate service decision.

## Context

Running ArchCert locally requires deployment of its existing application, not a
second local product. ADR 0070 added useful secure bootstrap, accounts and project
provisioning but unnecessarily composed them in another API executable. The
existing `archcertd` already owns trusted durable admission and bounded commands.

## Decision

Move the account/provisioning adapter into `archcertd`. Remove the separate API
package, listener and certification RPC implementation. Glassmere's product port
uses the same API: account operations use its private `/api/v1/platform` endpoint,
and certification uses the original `/api/v1/certifications` HTTP contract and
unchanged `ControlPlane::submit`. The panel adapter translates account identity
into private authenticated headers. A broker credential alone grants no project
access: current database account generation, role and ownership are required.
Account authorization narrows the existing control plane's grants while reusing
its repository pool, artifact adapter, admission, evidence and verification logic.
The original external bearer/command credentials remain independently scoped.

The product's existing Glassmere session/authentication engine is retained.
Password login exchanges an Argon2id-verified password for an independent random
panel credential internally; only its digest is projected into panel provisioning.
The session is server-side, opaque, HttpOnly and SameSite=Strict, with existing
expiration, CSRF, Origin and current-assignment validation. Account setup remains
single-use, host-authorized and database-serialized. Outages never reopen setup.
Recovery, role changes and password changes rotate generations and are audited.

Migration 0012 renames the five physical account/provisioning tables in place.
Migration 0011 and its checksum remain unchanged. Historical account identifiers,
triggers, sequence names, grant identifiers and `local-certify-` idempotency keys
remain byte-compatible. These historical strings are not a parallel product.
There are no compatibility views or second copies of the account tables. Existing
initialization, passwords, grants, accepted sources, jobs and certificates retain
their identities. Explicit update renames private configuration files and database
roles, preserving their authority and retaining previous configuration privately.
It never reruns first registration or changes historical certificate bytes.

Rename the deployment helper to `scripts/archcert-services`. It only builds,
configures and supervises the real binaries. It is not an API, alternate domain,
database engine or certification implementation. Existing services remain native;
PostgreSQL may use the selected infrastructure Docker context. Controller/worker
and the independent rootless execution daemon keep their original boundaries.

## Security implications

Neither API nor panel gains signing or runtime control. Architecture dependency
guards apply to the integrated API. The panel keeps SELECT-only observation and
cannot read account hashes; the API performs bounded transactional writes. The
worker receives neither database access, source acquisition credentials nor keys.
An administrator receives only delegated new-project provisioning; it gains no
wildcard project, policy, runtime or signing authority. All source admission and
execution retain Northgate, Ravenport and Stoneward checks.

Readiness timestamps written by the native supervisor are evaluated against that
same host clock. Future or older-than-45-second observations are unavailable.
Database/VM clock skew cannot make fresh native observations falsely stale; the
database clock still governs bootstrap expiry and login budgets.

## Alternatives and consequences

Blindly reverting ADR 0070 would discard tested account and onboarding features.
Keeping two APIs would duplicate composition and obscure the application boundary.
The selected integration preserves valid functionality and durable evidence.
Forward migration requires a complete backup and explicit update. Downgrading
executables over a migrated database is unsupported; restore into a separate
installation instead. Development same-UID/root custody is unchanged and is not
production IAM or independent authority assurance. M9 remains INCOMPLETE; M10,
M11, Pre-Genesis and Genesis remain NOT STARTED.
