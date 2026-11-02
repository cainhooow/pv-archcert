# ADR 0052: Audited external Glassmere credential provisioning

Status: Accepted design; qualification is recorded separately.
Date: November 2, 2026. Extends ADR 0051.

## Context

Glassmere reloads externally provisioned schema-1 principals on every request.
An existing session binds the complete principal grant revision. Changing its
credential hash, role or project scope invalidates that session. The initial
operations guide required an external auditable provisioning procedure but
provided no implementation for bootstrap or subsequent grant changes.

## Decision

Provide `scripts/glassmere-provision` as a trusted operator tool outside the
browser. Bootstrap creates one explicitly named panel Administrator with explicit
project UUIDs and a fresh OS-generated 256-bit credential. Other operations add
principals, set their exact role/project grants, rotate credentials or revoke a
principal. The tool refuses to remove the last principal. There is no default
account or credential and no browser provisioning endpoint.

Require a canonical private owned directory and private owned regular files,
rejecting symlinks and hardlinks. Deliver each new credential in a new private
file in that directory, never stdout, arguments or audit. Configuration retains
only its SHA-256. Credential output cannot overwrite configuration, either audit
sink or the provisioning lock. HTTPS is mandatory unless the operator explicitly
selects development HTTP on a fixed `127.0.0.1` origin. Preview credentials have
the same rotation and revocation behavior as other credentials.

A dedicated OS file lock serializes provisioning writers. Before replacement,
append and fsync an INTENT with an operation UUID, external operator identity,
action, affected principal, old/new public role/project grants and old/new
configuration digests. Never record credential bytes or their individual hashes.
Publish the complete new configuration by same-directory atomic replacement,
fsync the directory, then append/fsync COMMITTED. The configuration remains
schema 1; no historical authority artifact or grant semantics change.

If the previous process left an INTENT, compare the actual private configuration
digest with its exact old/new digests. Append RECOVERED_ABORT or RECOVERED_COMMIT
as appropriate before another operation. Unknown state, malformed/partial audit,
an unexpected configuration change or exhausted audit capacity blocks further
provisioning. Secret delivery can precede an interrupted configuration update;
the retained delivery file is not evidence that the credential became active.
The operator must inspect/reconcile rather than overwrite it on retry.

## Security implications

Panel Administrator remains a presentation role. This tool grants no project
repository authority, provider/runtime access, policy capability or signing
capability. Workflow grants still require their separate control-plane authority.
It changes no accepted review, certificate, Release Permit or deterministic truth.
The provisioning journal is operational audit, not Crownvale transparency or a
cryptographically authenticated history. It cannot defend against its owning
operator, same-UID process or root rewriting all private files. OS/service identity
isolation and independent audit retention remain deployment responsibilities.

The panel continues to recheck grants; provisioning never directly edits session
memory. Existing sessions are rejected after role/project changes, rotation or
revocation. Independent configuration writers are unsupported once this tool's
journal exists. A missing or invalid configuration fails closed in the panel.

## Alternatives and consequences

Browser user administration, plaintext/default credentials, unaudited manual
configuration replacement and storing credentials in the panel audit were
rejected. An external identity provider remains possible but is not introduced.
Two files cannot share a filesystem transaction, so explicit intent/reconciliation
preserves the distinction between publication and its audit acknowledgement.
This is M9 provisioning work; M10, M11 and Genesis remain NOT STARTED.

The Python regression exercises actual files, concurrent writers, denial cases
and injected failures on either side of replacement. Session interoperability
requires the Rust authentication regression. Injected failures do not establish
host power-loss durability or replace actual workflow SIGKILL qualification.
