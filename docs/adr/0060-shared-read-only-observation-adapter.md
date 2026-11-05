# ADR 0060: Shared read-only observation adapter

Status: Accepted design; release/readiness commands require separate implementation
and qualification. Date: November 5, 2026. Extends ADRs 0048, 0051 and 0059.

## Context

Glassmere's PostgreSQL/public-verifier composition lived in the panel executable.
A trusted readiness-command dispatcher needs the same exact source/artifact checks.
Copying those rules into another executable would risk divergent release decisions.
Moving PostgreSQL or certificate adapters into application/presentation would cross
the existing inward dependency boundary.

## Decision

Extract the existing composition into `archcert-observation`, an outer adapter
implementing the unchanged application query port. Preserve its configuration
schema, SQL-facing calls, independent public trust selection, artifact rehashing,
M6 verifier calls, categorical aggregation, revision preimage and errors. The panel
continues to compose that adapter with presentation and its independent command
broker. No HTTP transport or command mutation enters observation.

The adapter opens only the existing SELECT-only observation repository and read-only
artifact store. It accepts selected public keys and fixed recipes, never private
signing keys, runtime endpoints, source/provider credentials or database mutation
ports. Its dependency guard admits the exact application/domain/storage/public
verifier and parsing/IO dependencies it needs. Transitive runtime, provider and
source-acquisition dependencies remain forbidden. Presentation and application
cannot depend on this outer adapter.

Future command composition must still authenticate, authorize, bind original
scope/context, mediate a durable transition and audit through its own application
ports. A retained readiness receipt remains historical. Current readiness must
recheck actual dependencies and identities through fresh observation. This
extraction enables reuse; it grants no new command, execution or signing authority.

## Compatibility, security and validation

This is a composition refactor. It changes no source/certificate/permit identity,
authority policy, readiness rule, query schema, SQL or response content. Compare
the moved code byte-for-byte apart from public API documentation. Keep the
existing bounded M6 development qualification and same-UID/root limitations.
The Rust module path and linked executable identity naturally change; they do
not reinterpret historical signed bytes or qualify a new native mechanism.

Run the affected Rust checks, architecture guards, real PostgreSQL observation
tests and integrated browser journeys against the composed service. Adding a
crate alone establishes no release/readiness command qualification. M9 remains
INCOMPLETE; M10, M11 and Genesis remain NOT STARTED.

## Alternatives and consequences

Duplicating the verifier composition, granting presentation infrastructure ports
or making application depend on an executable was rejected. The shared adapter
adds one workspace package and an explicit dependency allowlist while retaining
the existing authority and public-verification contracts.
