# ADR 0057: Command-only credentials and authority resolution

Status: Accepted design; HTTP, dispatcher and browser qualification remain separate.
Date: November 5, 2026. Extends ADRs 0032, 0035, 0043 and 0053–0056.

## Context

The historical development submission API accepts an authority bearer and deduplicates
one identical client key. Glassmere commands additionally coalesce workflow intent
across different keys. Giving the panel that historical bearer would permit a
compromised broker to bypass the command journal through the older API.

## Decision

Provision command credentials in a separate strict private file. Each principal
binds a high-entropy bearer hash to an existing authority actor, exact project and
repository, and a nonempty subset of five fixed operations. Reject duplicate scope
mappings, unknown operations, repeated permissions, ambiguous token identities and
every token hash present in historical authority grants. Command credentials cannot
authenticate the legacy submission API. Neither file gains an implicit default.
The command file must meet the existing owned private regular-file, parent, size,
hard-link and symlink checks. Transport composition must reload it for each request;
removing a permission invalidates subsequent requests, without erasing history.

The application owns the fixed operation vocabulary. ReviewDisposition, arbitrary
commands, direct signing and governance operations remain absent. A command
permission grants no execution capability and does not establish target truth.
Browser roles remain a separate server-side check; a posted role cannot create a
backend principal or operation permission.

Derive an explicit schema-1 authority-context identity from scope, actor, selected
policy, resolved plan, profile, pinned image, original attempt limit and applicable
review/profile/registry/baseline selection. Exclude credential hashes, paths and
operational timing. Rotation alone does not change workflow intent. A changed
authority selection produces a different context; it cannot silently reinterpret
a retained command. The hash identifies trusted selection, not authority in itself.
Current repository and exact command-operation/context grants remain independently
required in PostgreSQL. Explicit operator provisioning adds command grants but
does not grant repository access, run migrations, revoke older grants or happen
automatically at startup or during an HTTP request.

Authentication returns a non-serializable, privately constructed, short-lived
authorization for one exact scope, context and operation. Control-plane request
methods recheck that operation, current authority context and repository grant.
Certification resolution shares the historical passive source validation and
registration phase, but creates no job before journal acceptance. Reviewed
certification requires an existing owned exact session and its matching submission;
authorize its scope before private source/knowledge preparation. Missing review
selection cannot downgrade a reviewed profile. Cancellation and recovery submit
fixed object IDs only; the journal scopes them in SQL, and the atomic executor
retains all existing eligibility, cleanup and budget checks.

Private journal records still have no blanket public serializer. A scoped status
read also checks the authenticated operation and exact context before returning
the internal record to trusted composition. Later transport code must explicitly
project safe receipts and must not publish frozen recipes or leases.

## Security and qualification

This boundary adds no HTTP routes, signer, runtime, semantic provider or acquisition
credential to the panel. No new permission becomes usable just because its enum
value exists. Release-build and readiness dispatch still require their separately
bounded M6/verifier composition. Credential-file tests cannot establish browser
RBAC, HTTP retry behavior, process-kill recovery or production identity isolation.
Those remain M9 closure requirements. M10, M11 and Genesis remain NOT STARTED.

## Alternatives and consequences

Reusing the legacy bearer would make the new idempotency boundary optional.
Accepting browser-supplied actors, recipes, permissions or signed-result facts would
move authority into presentation. A separate command credential file adds explicit
operator provisioning and revocation work, but preserves the old API contract and
keeps its credentials out of the new panel broker.
