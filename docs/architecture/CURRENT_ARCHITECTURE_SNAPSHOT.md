# Current architecture snapshot — Stoneward with knowledge and semantic review

Greywatch protocol extension: [ADR 0050](../adr/0050-greywatch-supplemental-claims.md)
adds explicit private-grant `greywatch: true` selection, controlled profile 1.2.1 /
Rust profile 1.1.1, request 3/package 2/provider response 2/review 2 and a separately
versioned gate. Typed claims, discoveries, exact admitted citations, contradiction
records and provider refusal/exhaustion remain supplemental. Stable semantic/package
identity excludes operational UUIDs; exact invocation responses remain session-bound.
Historical constructors, grants without opt-in, migrations, canonical artifacts,
certificate and Release Permit semantics retain their meanings. The existing
immutable journal/admission/manifest chain carries the new versions. No external
provider, source disclosure, execution authority or signing capability is added.

The canonical roadmap and historical naming inventory are defined in
[ADR 0045](../adr/0045-roadmap-reconciliation.md). M5.2 Stoneward is COMPLETE within
its documented qualification scope. M6 Ironcrest (Artifact Binding, Reproducible
Builds & Release Permit) is COMPLETE within the exact single-file native profile
recorded in [the M6 qualification](../qualification/NATIVE_LINUX_M6_RELEASE.md)
under ADR 0048. Development signing and the documented assurance limits remain.
M7 Asterwyn (Project Knowledge Engine & Change Impact Graph) is COMPLETE within
its bounded deterministic scope under ADR 0049 and the closure reconciliation in
ADR 0045. Dimensional knowledge coverage retains every Partial/NotAvailable state;
milestone closure does not make unsupported relationships complete. M8 Greywatch
(Semantic Review, Agent Claims, Discoveries & Blind Spots) is COMPLETE within the
bounded supplemental-review scope in ADR 0050 and its closure reconciliation in
ADR 0045. Local replay establishes no semantic correctness or complete source
coverage. M9 Glassmere is IN PROGRESS under ADR 0051. M10, M11 and
Genesis / Firstwarden are NOT STARTED.

ADR 0065 adds private application/storage mediation of verified release-build
admission. The existing public verifier checks the original registered certificate
against frozen M6 recipe/policy/key identities; a sealed command-generation
capability and current independent grants gate atomic M6 admission/audits/receipt.
No build claim, runtime, evidence publication or signing is added. ADR 0068 extends
this boundary with separately authenticated identifier-only HTTP requests.

ADR 0066 adds private fixed build-authority selection and native identifier-only
request resolution. A distinct build context binds the supported recipe version,
environment and policy/key identities; existing operation contexts keep their
original bytes. Current independent grants and owned certificate/source bindings
precede passive exact-source loading and journal acceptance. This requests work
only; ADR 0067 connects private dispatch and ADR 0068 connects scoped HTTP transport.

ADR 0067 adds the identifier-only native request-build entrypoint and independently
verified command dispatch through the sealed atomic M6 admission port. Explicit
schema-3 build receipts mean workflow admission; they establish no execution,
reproducibility, permit or current readiness. Known no-effect verification failures
retain exact rejection receipts and may receive a new explicit key. Commit
uncertainty remains recoverable under the original immutable request. Existing
job/readiness receipts and every M6 execution/signature contract retain their meaning.

ADR 0068 adds the closed schema-3 HTTP build action containing only an owned
certification job ID. Independent credentials, exact operation-specific context,
current grants and passive complete-source binding still gate request acceptance.
Verification and atomic admission remain in the separate controller. Existing
request bounds are unchanged. ADR 0069 adds the opt-in browser form through current
role/project/object, Origin, CSRF and independent backend-grant checks. Its schema-3
receipt displays admission only; refresh creates no workflow and grants no current
release status. The five-operation presentation vocabulary adds no execution or
signing port. M9 remains in progress and later milestones remain not started.

ADRs 0041–0044 describe the implemented knowledge, semantic review and durable
lifecycle controls. They were historically mislabeled M6/Ironcrest. The retained
`ironcrest` code, persistence, profile, policy and manifest names refer to that
implementation, not canonical M6. Controlled authority-profile review, immutable
challenge selection, durable admission and issuance remain integrated. Historical
validation and support limits are recorded in the intentionally untracked
`docs/MILESTONE_6_REPORT.md` and the validation boundary below. The naming correction
neither broadens Stoneward's exact native execution qualification nor establishes
a production certifier.

The initial knowledge core now owns generic graph/provenance/coverage vocabulary,
explicit scoped authority bundles and an application extractor registry over
verified complete SourceSnapshot bytes. archcert-knowledge supplies passive pinned
syn Rust syntax extraction; imports and impl trait names remain unresolved syntax,
not resolved calls. A function named main remains a symbol; executable entry-point
resolution is unavailable. Every accepted path/digest/size/mode is inventoried. SQL identity
is retained without an invented schema. Canonical knowledge/impact artifacts carry
extractor versions, authority identities, exact source/baseline pins, bounds and
blind spots. Missing or uncertain baseline/relationships expand to full review.
No runtime/provider/signing boundary is changed. Parser limits and residual risks
are documented in IRONCREST_DEPENDENCY_REVIEW.md.

The application SemanticReviewer port now prepares bounded canonical context with
a separate fixed authority contract, labeled untrusted repository bytes, approved
authority identities, exact source/baseline/knowledge/impact/policy/job bindings and
optional untrusted claim/evidence links. Strict semantic responses have no policy
verdict or signing representation. Immutable review artifacts retain exact accepted
response bytes/digests, adapter/model metadata, request identity, time and classified
failure/truncation state; restore validates exact expected inputs without a provider
call. The deterministic gate supports BLOCK, REQUIRE_MORE_EVIDENCE and CONTINUE;
CONTINUE adds no deterministic property. archcert-semantic provides local exact
replay and an unavailable default only. No external source disclosure or AI service
is configured. Timeout/crash tests simulate classified transport failures; there is
no live provider process or remote transport to qualify.

The controlled authority challenge registry supports bounded idempotency replay
against a documented settlement.py fixture API, with an authority-owned SQLite
final-state assertion. Proposals cannot specify commands, image, mounts, network,
privilege, endpoints, budgets or credentials. The registry constructs a new additive
authority plan; it never mutates an admitted pinned plan. Other challenge categories
are vocabulary only. The opt-in CLI integration test executes good and defective
fixtures through the unchanged rootless runner. Test-source confidentiality during
target execution is not established. These are engineering tests, not certification.

The application now provides a separately versioned `ironcrest-controlled-v1`
authority profile capability. It pins mandatory local replay, denied external
disclosure, policy/extractor/knowledge/challenge identities, limits, required
idempotency replay and gate semantics. Session/request validation rejects weaker
or foreign authority pins. This capability now validates reviewed admission;
historical policy and certificate behavior remain unchanged.

Migration 0005 now links a validated pre-admission session to its reserved
certification job in one transaction. The application freezes registry-approved
additive challenges and a reconstructible final authority execution plan first;
all exact source, actor, policy, profile, baseline and evidence identities are
rechecked before admission. Concurrent retries cannot create another job or
replace an admitted plan. Versioned gate evidence includes its algorithm, accepted
review and required challenge identities. Real PostgreSQL/private object tests
cover six interrupted publication boundaries, exact admission/restart and replay
rejection. Authenticated controller orchestration now consumes these APIs; the
application capability alone grants no signing authority.

The issuance foundation now has a private accepted-challenge prerequisite, a new
controlled deterministic policy and explicit schema-2 manifest construction. The
manifest preserves the complete schema-1 manifest and binds all eight typed
Ironcrest roles with exact digest/size/schema/producer metadata. Profile version
1.1.0 records pending required challenges as REQUIRE_MORE_EVIDENCE while retaining
the review decision. The certificate constructor independently re-evaluates policy;
CONTINUE creates no PROVEN result. Historical bundle identities, certificate schema
1, signing and offline verification remain compatible. Controller composition
restores the reviewed chain and accepted challenge evidence before evaluation and
preparation. Historical controlled lifecycle gates passed; exact commands and
evidence are recorded in the working report under its original M6 filename. This is not a
canonical milestone completion claim.

Migration 0004 and the application IroncrestRepository port now add a separate
project-scoped pre-admission journal. It checks repository grants and accepted
target/baseline identities, freezes authority/source pins and eight create-only
artifact roles, and grants at most one non-expiring provider invocation claim.
IroncrestWorkflow publishes through the existing immutable artifact store, verifies
readback, restores accepted/staged responses without another provider call and
persists the gate only for the exact accepted review. A claimed invocation with
no recoverable response blocks. Real PostgreSQL and private filesystem regressions
cover concurrent claims, immutable roles, scope rejection, interrupted response
publication, reconnect, repeated preparation/gate and no duplicate accepted review.
Historical job/attempt tables, leases and readiness requirements are unchanged;
optional journal readiness requires migration 4 explicitly.

Controller execution admission, the versioned Ironcrest issuance profile, schema-2
manifest binding and actual process-crash checkpoints are implemented. Controlled
source-to-certificate and veto-before-signing regressions passed. The controller
supports separately pinned historical and Ironcrest policies. ADR 0043 requires
the final challenge plan to be frozen before the new immutable job is admitted;
an admitted Ravenport plan may never be patched to add semantic challenges.

ArchCert accepts authenticated SSH Git pushes with bounded SHA-1/SHA-256 packs
or explicit local loose objects, seals an independently hashed
source snapshot, resolves authority execution plans, executes under rootless OCI,
evaluates typed observations deterministically, and can issue a DEVELOPMENT ONLY
Ed25519 certificate after full integrity validation, signing and offline verification.
Eligibility remains unsigned and cannot itself report CERTIFIED.

```text
Authenticated HTTP -> protocol -> admission composition -> application ports -> PostgreSQL
Operator source export ---> protocol Protobuf adapter -> application ingress read model -> domain
CLI execution ------------> application + source/materialization/runner adapters
CLI evaluation -----------> policy -> application + domain
CLI certification --------> certificate -> policy + application + domain + evidence + crypto
Evidence -----------------> policy + application + domain
Crypto -------------------> mature Ed25519/SHA-256/key-encoding implementations
```

No signer/key dependency exists in runner, source, materialization, application,
policy, project configuration or daemon graphs. Crypto imports no workspace crate.
The CLI is trusted operator composition; target access to its flags/process would
be authority access. The architecture guard enforces both direct and transitive
signing exclusions and checks the execution interfaces for key/signing types.

```text
accepted exact SourceSnapshot
  + immutable authority ValidationPlan
  + separately pinned immutable PolicyBundle
  + independent execution identities
  + typed controller observations
    -> PolicyEvaluation (schema 1, five verdicts, structured findings)
    -> ELIGIBLE_FOR_CERTIFICATION gate
    -> compare identities, resolve references, re-evaluate original inputs
    -> canonical detailed EvidenceBundle + deterministic EvidenceManifest
    -> owned immutable CertificateDraft / canonical payload / SHA-256 identity
    -> CertificateSigner (key ID and exact canonical message only)
    -> detached Ed25519 signature
    -> offline verification under explicitly selected public key
    -> IssuedCertificate / VerifiedCertificate -> CERTIFIED
```

Execution and both sandbox/source cleanup finish before the CLI prepares a draft;
any execution/cleanup failure rejects issuance. Private-key loading happens only
after complete draft validation. The development signer uses explicit authority
paths outside source/workspaces, owned private files, OS cryptographic randomness,
PKCS#8 encoding and zeroizing buffers. No private bytes cross a runner/source/config
port or enter OCI transfer/environment. No production custody or hardware isolation
is claimed. The local signer shares the trusted controller OS identity.

Every authority-relevant certificate field is inside the signed payload: exact
project/repository/commit/tree/source digest, policy/version/digest, plan/evaluation/
manifest digests, finding IDs, versions, certifier/runner/isolation, issuance time,
scope, governance limitations, algorithm and stable public-key digest identity.
Certificate ID is SHA-256 of its canonical payload; it is not the signature.
The envelope adds only derived digest, detached signature and public material.

Schema-1 canonical JSON recursively sorts fixed ASCII keys, preserves Unicode
strings, rejects non-interoperable numbers, normalizes schema-defined sets and
emits compact UTF-8 without BOM/newline. Parsing rejects unknown/duplicate fields,
unknown schemas/algorithms, invalid/oversized fields and encodings within a 64 KiB
predecode envelope bound. Independent fixed Python/OpenSSL vectors supplement
Rust permutation, tampering, substitution and key-isolation tests.

The small certificate binds the manifest, which resolves typed observation/finding
references and binds the separate detailed canonical evidence bundle including
execution records and captured log prefixes. Detailed records must reproduce the
consumed observations against the exact plan. No logs are embedded in certificates.
Evaluation audit time does not change semantic evaluation identity; issued_at can
create a new certificate instance with unchanged source/evaluation identity.

| Vocabulary | Meaning |
| --- | --- |
| SOURCE ACCEPTED / COMPLETE | Validated immutable supported source; no unresolved required LFS/submodule content |
| MATERIALIZED | Verified/sealed under documented filesystem assumptions |
| OBSERVATION / COMPLETED | Controller fact; normal process exit includes nonzero |
| PROVEN | Authority evidence establishes the explicitly limited property |
| FAILED | Authority evidence establishes that the property is false |
| NOT_PROVEN | Required evidence absent/insufficient |
| NOT_APPLICABLE | Explicit authority applicability exclusion |
| INCONCLUSIVE | Contradictory, ambiguous, unsupported or infrastructure-impaired evidence |
| ELIGIBLE_FOR_CERTIFICATION | Every blocking requirement satisfied; no certificate yet |
| CERTIFIED | Canonical certificate successfully signed AND verified under the selected key |

Offline `archcert verify CERTIFICATE --public-key TRUSTED_PUBLIC_KEY` requires no
Git, Docker, workspace, network, database or private key. Embedded public material
is not trusted automatically. A valid signature authenticates recorded claims;
it does not establish universal software security or attest runtime binaries.
EXACT_SOURCE excludes branches/latest/future source/artifact/release/deployment.
NO EXPIRATION SEMANTICS YET. Revocation is NOT IMPLEMENTED; replay for the exact
same source is allowed. Trust-anchor distribution remains administrative.

M1–M4A source, materialization, isolation, fixed environment/network/resource,
structured observations and mandatory authority-policy guarantees remain active.
Project configuration cannot select signer/key/algorithm/authority or weaken policy.
No AI participates in issuance. Ravenport now implements authenticated durable
HTTP job admission/status and PostgreSQL metadata. No web UI, production artifact certification,
waiver, policy inheritance, production KMS/HSM/PKCS#11, revocation or transparency
service is added. Native qualification is limited to the documented Stoneward
profile and the separate M6 single-file profile; see qualification/NATIVE_LINUX_RUNNER.md
and qualification/NATIVE_LINUX_M6_RELEASE.md.

See ADRs 0025–0027, MILESTONE_4B_REPORT.md, the certificate/signing threat model,
TCB_AND_DEPENDENCIES.md and CRYPTO_DEPENDENCY_REVIEW.md.

## Northgate ingress

```text
OpenSSH public-key auth -> explicit actor/device/repository grant
 -> fresh private quarantine -> bounded gitoxide pack decoding + M1 source validation
 -> isolated Git receive adapter -> immutable SourceSnapshot + ingress evidence
 -> separate later control-plane certification request -> existing M2–M4B chain
```

archcert-gateway and its standalone executable have no direct/transitive execution,
policy, Docker, evidence, certificate or signing dependencies. Git's bounded
advertisement/report handling runs with cleared configuration/environment and no
hooks. It is observed, not cryptographically attested. Each push is a new
submission; branch names are provenance and cannot mutate earlier snapshots.
One branch, create-only commands and self-contained packs are the initial contract.
A shallow declaration is supported only for the exact selected commit.

The finite local development store retains verified source separately from jobs.
`source show` and later `certify --source-submission` reuse immutable bytes without
Git acquisition. No acquisition credential reaches RunnerInput or certificate
signing. Ravenport REST now admits separate durable jobs. Source schema 1 is unchanged; old/new source identities
and Bottle policy behavior are reproduced by real SSH push/OCI regressions.

ExternalSourceAuthority verifies bounded LFS bytes and exact authority-mapped
submodule snapshots into a new immutable schema-2 SourceSnapshot. An operator-only
private LFS/accepted-child adapter enforces exact scoped grants. SourceBinding
carries only immutable identity metadata through artifact reload, materialization
and independent stopped-sandbox verification. Unresolved pointers/gitlinks remain
INCOMPLETE_EXTERNAL_SOURCE and cannot run; remote acquisition is not automatic.
See ADRs 0028–0033, NORTHGATE_DEPENDENCY_REVIEW.md, the Northgate threat model and
MILESTONE_5_REPORT.md for implementation evidence and limitations.

## Internal protocol contracts and Northgate completion

Protocol Buffers are the primary internal machine-to-machine schema/wire format.
The existing archcert-protocol crate generates common.v1/source.v1 DTOs using
pinned prost/prost-build and bundled protoc. Domain/application remain independent
of generated DTOs, prost, prost-types, and tonic; architecture guards enforce
direct and transitive exclusions. No tonic or actual RPC service is introduced.

IngressEvidence projects into a transport-independent application read model;
the operator `archcert-gateway export-proto` command emits validated binary source
observations after the existing immutable store load/rehash. It represents exact
source identity, Git/actor/device provenance, completeness, and resolved schema-2
binding summaries without credentials, origins, filesystem paths, or capabilities.
It cannot reconstruct accepted source or grant certification/execution authority.
SSH reception, current storage formats, and execution/signing paths are unchanged.

Protobuf bytes are not cryptographic canonicalization. Existing source, policy,
certificate/signing, and evidence canonical structures remain authoritative;
SHA-256 of Protobuf may identify only an exact serialized artifact. Unknown fields
cannot create trusted positive semantics. Future signer requests must be narrow,
certificate-specific contracts and cannot expose arbitrary-data signing.

The final protocol task and required gate results are recorded in
[MILESTONE_5_PROTOBUF_REPORT.md](../MILESTONE_5_PROTOBUF_REPORT.md), completing
M5 Northgate. Its [handoff plan](RAVENPORT_PLAN.md) records the original
Ravenport scope; the implementation below adds durable jobs and local worker
process contracts. See [ADR 0034](../adr/0034-protobuf-internal-protocol-contracts.md)
and [protocol architecture](PROTOBUF_PROTOCOL_CONTRACTS.md). Earlier reports retain
their historical results.

## Ravenport implementation in progress

The domain now defines pinned job inputs, explicit job/attempt states, bounded
attempt budgets and immutable job/attempt/fencing identities. Application owns
repository/read-model contracts. archcert-storage implements PostgreSQL admission,
scoped idempotency, row-locked claims, fenced leases, immutable artifact metadata,
issuance bindings and append-only audit through explicit SQLx migrations. Real
PostgreSQL tests cover concurrency and recovery. Authenticated loopback HTTP now
admits actual durable jobs and returns status. archcert-controller resumes durable
evaluation/issuance and dispatches a separate leased worker process. ADRs 0035–0037 govern the implementation.

ImmutableArtifactStore now has an explicitly unencrypted local development
adapter: project-scoped SHA-256 keys, atomic create-only publication, fsync and
bounded verified retrieval. ArtifactCipher defines the future encryption seam.
No production encryption provider or MinIO-specific semantics are implemented.

Ravenport worker process models and execution.v1 Protobuf assignment/result
contracts are implemented. Checked adapters retain existing operational evidence
serialization and canonical source identities. Pinned authority plans reconstruct
only from retained commands/image and must match their stored digest. Source
artifact acceptance and actual lease authority remain separate from wire decoding.

archcert-worker is now an actual separate execution executable. Its dependency
graph excludes metadata storage and signing. An authority-owned private stdin
assignment supplies verified source artifact bytes; stdout returns only the
versioned result envelope. Runtime configuration remains operator-only. The
worker rechecks source scope/identity and reports source/sandbox cleanup separately.
All eleven existing live rootless OCI regression groups passed for this boundary.

The trusted controller records EVALUATING with a durable phase time and preserves
structured policy/infrastructure/signing/verification failures. It reconstructs
observations only from a structurally bound persisted worker result. Eligibility
and exact issuance time/key/payload digest precede signing. Verified immutable
certificate metadata and audit commit with COMPLETED. Controller restarts after
execution/evaluation/signing do not repeat target commands. Lease expiry recovery
preserves prior attempts and requires confirmed runtime cleanup after target start.
See RAVENPORT_OPERATIONS.md for the explicit supervisor/run-once deployment and
its local development role/encryption/cleanup limitations.

## Stoneward native execution qualification

The pre-change capability matrix remains in the intentionally untracked M5.2
baseline working record. The exact Ubuntu 26.04.1/KVM/rootless profile is qualified; authoritative
status and support limits are in qualification/NATIVE_LINUX_RUNNER.md. Worker
`doctor` reports runtime prerequisites without accepting an execution assignment
or gaining control-plane credentials. Runtime evidence now retains the explicitly
selected Unix endpoint and reported daemon ID/security options/default runtime.
These observations do not attest runtime binaries or establish native deployment.

Stoneward now adds durable attempt/runtime bindings, irreversible DB fencing,
audited bounded cleanup states and a persistent local execution gate. Workers
receive no database credential. Each execution holds the gate through runtime
operations/cleanup; revoked gates reject stale later steps before the runtime API.
Controller startup and `reconcile` combine DB state/expiry, the exclusive gate,
bound daemon identity and exact ownership labels. Busy workers, unknown ownership,
late-create uncertainty and cleanup failures block retry. Accepted evidence closes
execution authority; continuation reconciles cleanup before policy/signing without
rerunning targets. The precise single-host protocol is in ADR 0039. Native OCI and
PostgreSQL, recovery/outage, offline verification and final residue-cleanup demonstrations passed on the exact documented profile.

Stoneward preserves certification semantics while adding single-host durable
execution fencing, ownership-scoped runtime reconciliation, separate cleanup
metadata/audit, dependency readiness and staging recovery. The worker holds a
private persistent attempt gate before all runtime resource creation. Recovery
revokes that gate before recording the PostgreSQL fence; runtime termination and
absence plus durable SUCCEEDED cleanup precede retry. Uncertain pending daemon
creation blocks indefinitely. Committed evidence is validated/adopted without a
target rerun. See ADRs 0038–0040 and the native qualification document for the
precise trusted-worker/filesystem profile and observed deployment limits.

## Controlled review controller and historical validation boundary

Explicit private grants select Ironcrest, mandatory knowledge and an accepted
baseline before source/knowledge access. Historical grants retain their prior
behavior; the old submission API refuses grants requiring review. The controller's
separate Ironcrest module composes application workflow and authority ports. Its
normal continuation reuses accepted worker evidence, persists exact challenge
results and independently evaluates the separately pinned Ironcrest policy. The
issuer additionally requires the private accepted-challenge prerequisite and binds
schema-2 evidence without changing certificate v1 or offline verification.

The controlled live regression passed authenticated SSH source-to-certificate,
semantic blocker, unavailable reviewer, persisted replay rejection, a real failing
challenge under semantic CLEAR, and historical Bottle NOT_ELIGIBLE. Sixteen actual
SIGKILL checkpoints retain one execution attempt and immutable issuance identity.
Unknown provider outcome remains OPERATOR_RECOVERY_REQUIRED, never a retry permit.
All standard gates passed, with 244 workspace tests passing and 32 opt-in tests
ignored in that command. Explicit runs also passed all thirteen real PostgreSQL
groups, Protobuf, artifact-store, real Northgate SSH, focused Ironcrest and live OCI
challenge regressions. The exported certificate verified with a cleared environment
after the controller, worker, ingress, PostgreSQL and OCI test services stopped.
The reproduced PostgreSQL lease anomaly was caused by competing development VM
clock synchronizers; after aligning clocks, 100 isolated runs and twenty parallel
suites passed. The original occurrence lacked clock observations, so attribution
of that historical failure retains explicit uncertainty in the working report.

Semantic review uses local exact replay; no live external model is configured or
qualified. Syntax extraction is not compiler resolution; model nondeterminism,
provider drift, false positives/negatives and injection susceptibility remain.
There is no universal bug detection or external disclosure authorization by default.

Runner, worker, runtime reconciliation, execution fencing/cleanup, deterministic
rule evaluation and certificate cryptography/offline verification mechanisms were
not changed. New policy data, issuance prerequisites and manifest construction sit
above that qualified execution boundary. Relevant real OCI challenges were rerun;
no changed Stoneward mechanism required native Linux requalification. The existing
exact qualified platform and its limitations remain as previously documented.

## Bounded semantic context

[ADR 0046](../adr/0046-bounded-semantic-packaging.md) separates complete immutable
knowledge/impact artifacts from the semantic reviewer projection. Application owns
a versioned authority-only packager and explicit FULL_CONTEXT, PARTIAL_ACCEPTABLE,
INSUFFICIENT_CONTEXT classifications. Schema-2 requests contain a canonical package,
its digest, omission counts/reasons and exact serialized byte accounting under the
unchanged 1 MiB ceiling. Historical direct-embedding preparation is preserved.
The immutable request role is also the package persistence/recovery checkpoint;
provider responses bind that exact request. Partial acceptance requires a new
explicit authority profile and grants no deterministic proof or complete coverage.

## Controlled Rust authority

[ADR 0047](../adr/0047-rust-controlled-authority.md) introduces the distinct
`rust-workspace-review-v1` authority profile, `rust-workspace-v1` execution family
and `archcert-rust-controlled-v1` deterministic policy. They require local replay,
explicitly bounded partial context, ordinary authority-selected Rust checks and a
fixed Rust dependency/source-immutability challenge. The authority-owned guard
runs offline Cargo metadata within OCI and checks named layer dependency closures;
it does not execute repository scripts as its implementation. Exact registry pins
select pending requirements and accepted challenge steps throughout the durable
lifecycle. Controller, issuer and storage all enforce the reviewed prerequisite.
Schema-2 manifests bind the package through a schema-2 REQUEST only for the new
Rust policy. Existing Python profile/policy/manifest identities are unchanged.

## Canonical M6 artifact binding and release permits

[ADR 0048](../adr/0048-artifact-build-and-release-permit.md) and the
[operator guide](../release/README.md) define a separate release namespace. Historical
`ironcrest` identifiers and source certificate schemas keep their meanings. M6 does
not start Genesis / Firstwarden or reconcile M7/M8 completion.

Domain/application distinguish certified source, recipe, environment, invocation,
result, file artifact, reproducibility and permit identities. Authority composition
verifies the exact source certificate against explicit scope/key/policy, then
freezes one canonical input manifest. A versioned fixed Rust recipe binds the
read-only source snapshot, digest-pinned image, public dependency bundle/toolchain
inventory assertions, literal offline locked Cargo invocation, fixed environment,
finite limits and one bounded output selector. Target configuration selects none
of these authorities. Preparation of public dependencies remains outside execution.

Migration 0006 adds project-scoped create-only invocation/evidence metadata,
non-expiring independent A/B execution claims, immutable publication intent and
append-only audit. Short row-locked transactions precede runtime or object-store
operations. The controller builds in two fresh rootless instances and source/scratch
workspaces. An unknown claim or failed cleanup blocks; no lease expiry or automatic
retry authorizes repeating an unknown build. Accepted results resume from rehashed
immutable bytes. This conservative initial path does not add remote build workers
or automatic cleanup of unknown standalone runtime resources.

The release runner uses a separate `archcert-docker-release-v1` evidence producer
and explicit `large-offline-image-v1/60s` control profile. Historical default control
operations retain 15 seconds. Since daemon archives omit live tmpfs bytes, a fixed
runtime-invoked authority reader collects only /output/artifact with no-follow,
nonblocking regular-file/size/directory/mutation checks and a separate bounded byte
channel. It grants no status or filename authority to target text. All runtime and
source cleanup finishes before signing. SHA-256 and size identify imported bytes;
create-only storage publication and independent readback precede acceptance.

Canonical comparison evidence binds both independent execution results and artifact
identities. Equal complete bytes mean REPRODUCIBLE; actual differences mean
NON_REPRODUCIBLE; missing/infrastructure-impaired completion means INCONCLUSIVE.
Only REPRODUCIBLE can prepare a permit. The issuer independently rechecks the source
certificate, selected recipe, actual execution/cleanup/equality evidence and artifact
readback. A private exact-message durable capability is required before signing.
The small separate ARCHCERT_RELEASE_PERMIT payload binds source/certificate,
invocation/recipe/environment, artifact, comparison, fixed policy and release key.
Existing Ed25519 primitives sign canonical bytes; selected-key verification and
immutable envelope readback precede RELEASE_PERMITTED. Completed permits can be
restored without reloading a private key.

The offline `archcert release-gate` verifies a permit under an explicitly trusted
release key and checks actual artifact bytes plus project/repository. A source
certificate alone, another scope, wrong key or substituted binary cannot pass.
It is a local gate: external deployment integration, OCI/package formats, expiry,
revocation and production signer custody are not implemented. Inventory assertions
are not toolchain/runtime attestation. The new mechanism has its own exact native
qualification in qualification/NATIVE_LINUX_M6_RELEASE.md; the historical Stoneward
report keeps its original mechanism and source scope. Native collector, independent
equal/unequal build, real PostgreSQL and seven-SIGKILL release regressions passed.
The separately identified ArchCert source passed engineering self-validation,
independent native A/B builds and selected-key offline artifact authorization with
the dedicated database/runtime stopped. Development fixture validation and each
exact-source engineering run retain separate identities. M6 is COMPLETE within
that bounded scope; Genesis / Firstwarden is NOT STARTED and M7/M8 are unchanged.

## Asterwyn deterministic closure expansion

[ADR 0049](../adr/0049-asterwyn-deterministic-selection.md) adds exact restoration
by bounded full regeneration and a separate authority-only scenario catalog.
Scenario selection binds exact source/baseline/knowledge/impact/catalog identities,
always preserves mandatory catalog obligations, retains full-review uncertainty
and records actual relation witnesses for targeted selections. It requires no
semantic provider. It does not modify existing execution plans or M8 behavior.

Canonical knowledge/impact schema 1, historical controlled authority profiles,
extractor IDs and durable role identities retain their bytes and meanings. There
is no incremental knowledge update or Git-history inference. Unsupported compiler,
manifest, route, schema and behavioral relations remain explicit omissions and
expand review; full review does not claim complete semantic knowledge. The new
selection artifact has no database lifecycle or automatic executor integration.
Exact-source closure evidence is retained under ignored `target/m7-*`. The
reconciliation covers all 34 criteria with explicit applicability and limitations.
Deterministic qualification includes canonical/replay/corruption/ceiling tests,
actual materialization/process/history perturbations, real PostgreSQL publication
races and three actual controller SIGKILL recovery checkpoints. M7 is COMPLETE
within this scope; no semantic CLEAR/PASS contributes to that decision.

## Glassmere observation boundary (M9 in progress)

[ADR 0051](../adr/0051-glassmere-observation-boundary.md) defines private
presentation and query over M0–M8 authority. Application owns categorical readiness;
the existing verifier checks exact certificate/build/permit bindings. Presentation
receives explicit bounded read models, never signing/runtime/acquisition/provider
capabilities. Read-only repeatable snapshots and immutable-byte verification avoid
merging independent latest records. No persistent Glassmere projection is needed.
Browser sessions are separate from project/role authorization. See the
[threat model](../threat-model/GLASSMERE.md). Implementation and qualification
remain in progress; M10, M11 and Genesis are NOT STARTED.

Glassmere now composes `archcert-glassmere` presentation and sessions with a narrow
application query port in `archcert-panel`. Under
[ADR 0060](../adr/0060-shared-read-only-observation-adapter.md), the shared
`archcert-observation` outer query adapter uses SELECT-only
`ObservationRepository`, the observation-only filesystem reader and existing
public-key certificate/M6 verification. It never configures a signer, runtime or
acquisition/provider adapter. The browser receives explicit versioned fields,
project-bound downloads, exact readiness blockers and original-stream timeline
sequences. Query collections are bounded and attempt metadata is batched.

The server embeds buildless HTML/CSS/JavaScript. Private provisioned random bearer
credentials exchange for expiring HttpOnly same-origin sessions; role/project
revocation invalidates the session's grant revision. Viewer and Reviewer retain
read-only scope; Administrator additionally inspects panel audit. Under
[ADR 0059](../adr/0059-glassmere-browser-command-broker.md), Operator and
Administrator can request three fixed job operations through an opt-in,
separately authenticated loopback broker. Explicit backend grants, exact context,
object scope, origin/CSRF and current versioned panel grants remain mandatory.
The panel retains SELECT-only database access and receives no runtime or signer.
No user or policy administration is exposed through the browser. See
[operations and known limits](../glassmere/README.md). This is an INCOMPLETE M9
visibility implementation, not milestone closure or independent certification.

[ADR 0053](../adr/0053-glassmere-operational-command-journal.md) adds a private
application command journal with explicit operation/context grants, immutable retry
aliases, intent deduplication and fenced dispatch. Under
[ADR 0056](../adr/0056-glassmere-known-rejection-idempotency.md), a known no-effect
rejection permits a fresh action with another key; the original key always retains
its original receipt. Pending, applied and uncertain work remains coalesced.
These are operational records,
not cached query projections. [ADR 0054](../adr/0054-glassmere-atomic-job-commands.md)
mediates existing non-reviewed admission, narrowly eligible queued cancellation and
infrastructure-only retry with domain mutation, audit and receipt in one transaction.
Reviewed certification additionally consumes the existing sealed application
admission under [ADR 0055](../adr/0055-glassmere-reviewed-command-mediation.md),
preserving its source/review/challenge chain and atomic linkage/receipt. Retained
reviews can be restored without any provider invocation capability. Release-build
mediation remains open. These private ports enable no HTTP command by themselves;
transport and browser qualification are separate boundaries.

[ADR 0057](../adr/0057-glassmere-command-credential-boundary.md) separates private
command credentials from legacy submission tokens. Existing authority configuration
selects policy/profile/plan/image/budget; credentials select only an existing actor,
exact scope and fixed operation. Context identity excludes credentials, and current
repository and command grants remain separate. Passive certification resolution
creates no job before journal acceptance. Reviewed requests require their owned
existing session before private preparation. No HTTP command route or browser
mutation is enabled by this composition alone.

[ADR 0058](../adr/0058-glassmere-job-command-transport.md) adds separately opt-in
loopback daemon routes with strict identifier-only requests and public receipt
projection for certification, eligible cancellation and exact-attempt recovery.
Command credentials reload per request and cannot authenticate legacy submission.
The trusted controller can provision permissions and poll these requests through
the existing atomic application executors, without target execution or key loading.
Historical receipt inspection binds original context under current scope/operation
authorization; mutations require current selection. Release/readiness transport,
complete browser qualification and M9 closure remain open.

ADR 0059 adds the optional browser broker for those three operations. Forms carry
identifier-only intent and a retained action key, then redirect to a GET receipt.
The backend owns durable intent coalescing and domain eligibility. Audited panel
assignments now include a fresh random grant generation, preventing restored roles
from reviving older sessions. Legacy unversioned grants remain read-only compatible
but cannot enable Operator/Administrator commands. This adds no release/readiness,
review disposition, user administration, runtime or signing operation.

[ADR 0061](../adr/0061-private-readiness-request-evaluation.md) adds private
readiness-request mediation. A narrow application observer reuses the shared live
query/verifier; the journal rechecks current grants, original scope/context and
coordination ownership before publishing a historical receipt and audit. Same-key
replay retains that receipt; a new explicit key can request another observation.
This acquires no build claim and changes no source certificate or Release Permit.
The controller requires an explicit observation configuration and separate
SELECT-only database capability. No readiness HTTP or browser operation is enabled;
current readiness still requires a fresh live dependency check.

[ADR 0062](../adr/0062-readiness-request-entrypoint.md) adds the trusted controller's
identifier-only `request-readiness` entrypoint with a separate private scoped token
file. Readiness receipts use public schema 2 and an explicit historical-observation
marker; existing job receipts retain their exact schema-1 grammar. The development
qualification harness copies explicitly selected historical evidence into an
isolated schema/store and uses actual controller/public-verifier composition.
It creates no new source certification, build claim or permit, and enables no
daemon or browser readiness operation.

[ADR 0063](../adr/0063-readiness-command-transport.md) adds opt-in daemon readiness
requests with schema 2 and only an exact invocation identifier. The existing
credential/scope/context/object/idempotency checks mediate durable acceptance;
the HTTP handler performs no verification or execution. Same-key receipts remain
historical, and a new explicit key asks a fresh question. Job schemas and all
resource/authority limits remain unchanged. The browser still exposes only the
three previously qualified job operations; readiness browser integration is open.

[ADR 0064](../adr/0064-glassmere-readiness-browser-request.md) adds the fourth
opt-in browser operation: an exact historical readiness question. Operator and
Administrator still require separate backend grants, current project/object scope,
Origin/CSRF and reauthorization after passive lookup. The broker requires schema 2
and the explicit historical marker. Retained observations have structured identity
and blocker summaries without live-confirmation attributes; their exact live query
is a separate link. No new build, review waiver, signature or release authority is
introduced. Full browser integration qualification and M9 closure remain separate.

## Local self-hosted pilot (M9 remains incomplete)

ADR 0070 adds an opt-in separate local identity/provisioning service. PostgreSQL
owns one-way instance initialization, Argon2id accounts, non-revivable assignment
generations, bounded owned project registration and operational audit. Glassmere
uses a private fixed loopback port for onboarding and rechecks the durable account
generation on each authenticated local request. Its authority observation remains
SELECT-only and excludes account tables; the service receives no runtime or signer.
Legacy external bearer and command-broker contracts remain available separately.

`scripts/archcert-local` explicitly installs/migrates private storage outside target
source, supervises the existing native services, and invokes the existing trusted
controller's run-once loop only with explicit rootless runtime/development custody.
Northgate still validates authenticated Git pushes into immutable source; local
certification reuses existing exact-source durable admission. The worker remains a
credential-free child. No new target execution, policy, certificate, canonical
artifact, M6 recipe or runtime cleanup mechanism is introduced. Private projections
are reconstructible from retained database state; initialized setup never reopens.

The local UI supports one host-selected bounded Python profile, with unsupported
M6/remote-import/provider paths explicit. Classification is LOCAL SELF-HOSTED PILOT
— DEVELOPMENT CERTIFICATION AUTHORITY. Operational acceptance and limits are in
operations/LOCAL_PILOT.md; compilation or web availability alone establishes no
end-to-end acceptance, M9 completion, native qualification or independent certification.
M10, M11, Pre-Genesis and Genesis remain NOT STARTED.
