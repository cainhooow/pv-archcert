# ADR 0049: Exact knowledge restoration and deterministic scenario selection

Status: Accepted. Date: October 31, 2026.
Extends ADR 0041; roadmap attribution follows ADR 0045.

## Context

Historical knowledge already binds schema, project/repository, exact commit/tree/
snapshot, extractor identities, authority bundle digests, selected baseline and
all configurable knowledge limits. The inventory extractor identity versions the
application's inventory semantics; structural extractor versions identify their
own interpretation. The controlled authority profile separately pins this registry,
limits and bundles. Operational creation times and workspace IDs are excluded.
There is no mutable or incremental authoritative knowledge update API.

Existing impact evidence retains related tests, policies and invariants, but
provides no separate deterministic validation-scenario mapping or selection
witness. Semantic challenges are a different M8 capability. M7 selection must be
usable without any reviewer, provider, semantic response or challenge proposal.

## Decision

Add `KnowledgeEngine::restore_exact`. It first bounds and hashes supplied bytes,
then fully regenerates knowledge from the authority-selected accepted source,
registry, limits, bundles and baseline. Only exact canonical equality returns a
private accepted `KnowledgeArtifact`. Even attacker-recomputed digests, alternate
valid JSON, unsupported schemas and newer timestamps cannot establish freshness.
Missing object bytes remain storage failure. There is no untrusted decoder that
constructs accepted knowledge. Existing controller reconstruction and immutable
role-reference comparisons retain their behavior.

Add a separate authority-only `ScenarioCatalog` with explicit global/project
scope, ID/version, mandatory/impact-selected requirements and exact path or
approved authority-entry triggers. There is no target deserializer, score,
command, runtime, signer or policy-verdict field. Fixed ceilings are 128 scenarios,
32 triggers per scenario and 1 MiB canonical catalog bytes. Invalid/oversized
catalogs fail before selection. Scenario and trigger sets sort canonically.

`select_validation_scenarios` recomputes impact from private accepted target and
baseline knowledge. It never accepts an untrusted affected-node list. It always
selects mandatory catalog entries, even for an empty delta. Full review selects
every entry and retains the impact artifact with its omissions. Otherwise a
canonical breadth-first traversal of the union of old/new relations records a
changed node, affected component/authority node and actual ordered edge witness.
Traversal is conservatively bidirectional, matching historical impact semantics;
it is not a resolved directed call graph. Cycles visit each node once. The existing
node/edge/depth ceilings bound traversal; witness overflow fails closed. Selection
serialization has an 8 MiB ceiling and cannot silently truncate obligations.

New canonical schema-1 kinds are `ARCHCERT_ASTERWYN_SCENARIO_CATALOG` and
`ARCHCERT_ASTERWYN_SCENARIO_SELECTION`, with algorithm
`asterwyn-scenario-selection-v1/1.0.0`. Selection binds catalog, project/repository,
exact target/baseline source, both knowledge digests and impact digest. Mandatory,
conservative-full-review and relation-closure reasons are explicit tagged enums.
The full bound impact artifact supplies source changes, retained old nodes and
uncertainty for auditing each reason. Equal catalog IDs/versions with changed
mapping bytes still have different content identities.

The selection API produces evidence and obligations, not an execution plan. Its
caller must retain preexisting authority-mandatory checks in addition to catalog
obligations. Existing plan resolution and reviewed admission already preserve
those requirements and are unchanged. No current controller automatically skips
work based on this new artifact. Future executor/catalog integration must verify
these bindings and preserve mandatory requirements before using selection.

## Compatibility and migration

Existing knowledge/impact schema 1, inventory/extractor IDs, controlled profiles,
policies, protocols, database migrations, eight-role manifests and historical
serialized bytes remain unchanged. Exact restoration uses the original supplied
controls; it never selects a newer registry/profile during recovery. New producer
semantics require a new explicit version instead of reinterpreting old artifacts.
There is no persistence migration: the new selection is an in-memory immutable
artifact with exportable canonical bytes and no accepted database record.

KEEP all historical `ironcrest` modules, SQL, protocol/profile/policy/CLI names and
ADRs under ADR 0045. MIGRATE current roadmap prose to canonical Asterwyn attribution.
No compatibility alias is needed: the new API uses scenario/knowledge vocabulary
and the new artifact kinds explicitly identify Asterwyn.

## Security implications

Repository source, configuration, comments and filenames remain data. Only trusted
composition provisions catalogs, extractors, bundles, baselines and limits. A
catalog digest establishes identity, not honest provisioning. Semantic CONTINUE
contributes no deterministic property and is not an input to this API. M8 may
consume M7 artifacts later; no M8 behavior is added here.

Blind spots retain machine code, exact optional path and bounded reason; their
canonical bytes give a stable local omission identity within the bound artifact.
The artifact identifies the responsible registry. Every retained omission and
unresolved edge may under-approximate relationships, so impact expands to all
old/new nodes and all target files. Unknown never means unaffected. Known absence
is limited to the complete admitted file inventory, never absence of runtime
calls, dependencies, routes or behavior. There is no confidence percentage.

Rust extraction remains syntax only. Manifest dependency resolution, schema to
migration resolution, route to handler resolution, macro/include/build-generated
expansion, cfg activation, dynamic loading and behavioral test coverage are
unsupported. They retain inventory/uncertainty and trigger conservative selection.
An authority-selected exact baseline is supported; Git ancestry, authorship and
branch history are unavailable dimensions, not inferred clean history. Missing
history does not strengthen coverage. Hardlinks, special files and hostile host
metadata are handled at source/materialization admission; knowledge has no host
filesystem handle and cannot follow source symlinks.

The authority process, parser dependencies, OS and resource provisioning remain
trusted. Finite artifact and graph limits do not establish parser memory safety,
global availability, compiler resolution or independent certification. M6 runtime,
release and signing mechanisms are unchanged. Genesis / Firstwarden is NOT STARTED.

## Alternatives and validation

AI-ranked scenario authority, target-authored catalogs, unbounded traversal,
mutable incremental caches and deserializing arbitrary JSON as accepted knowledge
were rejected. Full regeneration trades performance for exact freshness and
compatibility. Conservative full review may select much more work than necessary.

Regression specifications live in `archcert-knowledge/tests/{asterwyn,selection}.rs`,
application `knowledge/impact_tests.rs`, materialization `tests/asterwyn.rs`, and
storage's real PostgreSQL knowledge-publication test. They separate graph mechanics
from the Rust adapter's deliberately unresolved syntax. Process/materialization,
Git-layout, corruption, replay, monotonicity, mandatory-scenario and authority
ceiling cases require no semantic provider. Current exact-source executed results
belong under ignored `target/m7-*`; this decision alone declares no milestone pass.
