# ADR 0062: Private readiness entrypoint and historical receipt grammar

Status: Accepted development entrypoint; HTTP and browser readiness remain absent.
Date: November 5, 2026. Extends ADRs 0058, 0060 and 0061.

## Context

The fenced readiness evaluator needs an authenticated entrypoint and qualification
through the actual controller and shared M6 verifier. A receipt containing a past
RELEASE_ALLOWED observation must not appear to authorize a later deployment.

## Decision

Add the trusted controller's fixed `request-readiness` command. Accept only exact
project, repository, invocation, expected current authority-context identity and
idempotency key. Load a separately provisioned command-credential mapping and an
owned private token file. Token contents must be the exact graphic credential,
without a trailing newline. No token argument, actor, recipe, execution command,
key, posted evidence or readiness boolean is accepted. Current backend grants and
original object ownership remain enforced by the existing control-plane port.

Public readiness receipts use explicit schema 2 and
`observation_freshness: HISTORICAL_OBSERVATION`. This applies to pending and
terminal readiness receipts; their result is always a historical observation.
Existing job receipts retain schema 1 with no new serialized field. Existing
schema-1 consumers fail closed on schema 2. Internal request/outcome bytes, hashes,
aliases, M6 evidence and signing contracts do not change. No readiness HTTP request
is added by this private CLI. Future transport/presentation must require schema 2
and preserve its historical meaning rather than accept a missing freshness field.

Same-key request replay retains the original receipt even during dependency loss.
A different explicit key asks another question. APPLIED records evaluation and
may carry RELEASE_DENIED. Absent observation capability is INCONCLUSIVE. An older
allowed receipt is never used as a cached current readiness response.

## Qualification boundary

The development fixture can explicitly copy one selected historical invocation
from the selected database's public schema into its own new isolated schema. It
retains original admission, non-expiring claims and exact evidence references.
Available bytes are independently read/hashed and create-only copied into a new
private artifact store. No original authority row or byte is modified. The new
audit event explicitly identifies a development historical import, not issuance
or authority database recovery. Query configuration retains explicitly selected
public trust and recipes. The permission grant only authorizes observation; it
cannot substitute its job profile for the frozen M6 execution recipe.

The harness uses actual controller processes, scoped credentials, SELECT-only
observation and retained signatures. Test same-key/different-key observations,
scope/context/private-file denials, artifact loss, missing observation capability
and actual SIGKILL after claim/publication. Require exact journal counts and
unchanged imported release/claim/evidence state. These tests do not execute targets,
load private signing keys, create certificates/permits or extend native qualification.

## Security implications and alternatives

The private CLI has no browser role. Backend credentials remain independently
provisioned and cannot authenticate legacy submission. Its OS identity and database
capabilities retain the existing development trust limits. The fixture import is
test tooling, never an HTTP recovery/import endpoint. Output and secrets stay in
ignored private target directories.

Returning cached readiness as current, exposing frozen release JSON to a browser,
or generating new signatures to conceal historical evidence identity was rejected.
M9 remains INCOMPLETE; M10, M11 and Genesis remain NOT STARTED.
