# Milestone 4A — Deterministic policy evaluation

Engineering self-validation in the supplied macOS workspace, October 19, 2026
(America/Sao_Paulo; UTC timestamps are October 20). This is not independent
certification. **UNSIGNED POLICY EVALUATION — NOT A CERTIFICATE.**

## IMPLEMENTED

Bounded strict authority policy bundles, independent canonical SHA-256 identity,
typed deterministic evaluation, five property verdicts, exact evidence binding,
structured stable findings, fail-closed pre-signing eligibility, an `evaluate`
development CLI, retained real/controlled demonstrations, architecture guards,
threat model and ADRs 0022–0024. No certificate is constructed/issued, no key is
loaded, no signer called and no semantic AI participates in authoritative evaluation.

The pre-edit review/gates are retained in [MILESTONE_4A_BASELINE.md](MILESTONE_4A_BASELINE.md).
ADRs 0001–0021, the M3.5 report/current snapshot, plans, observations, source and
execution models, CLI semantics and evidence/policy scaffolds were reviewed before
implementation. The unsuitable unused verdict-input/certification-status policy
interface was replaced rather than activated. Inactive generic evidence now holds
payload references instead of pre-interpreted verdicts; crypto remains unchanged.

## POLICY MODEL

`PolicyBundle::read` parses strict bounded TOML into immutable normalized policy.
Schema 1 has seven fixed generic property IDs and non-recursive typed rules:
source completeness, source match, sandbox environment, denied network and exact
named authority command completion with TYPECHECK/TEST/BUILD category. Rules do
not contain scripts/expressions/plugins. Every field is explicit and unknown fields
reject, including inside applicability and rules. Tagged empty struct variants
close a reproduced Serde unit-variant unknown-field acceptance gap.

The real example [archcert-development-v1.toml](../policies/archcert-development-v1.toml)
is embedded and independently pinned by the CLI. It requires all seven properties.
It is a development baseline, not a production-grade policy. Applicability is
ALWAYS or an explicit authority policy-profile set matched against the separately
selected bundle/profile ID. It never depends on a project's requested execution
profile, presence/absence of requested commands, labels or claimed applicability.

Limits: 64 KiB input before decoding, 32 properties (seven fixed IDs available),
16 producer IDs, 128 bytes per identifier/version/producer, 2,048 bytes per
property description, 32 required command step IDs, 16 applicability profile IDs.
No recursive expression language exists. Existing TOML recursion protection and
byte bounds constrain malformed nesting. Evaluation caps 160 expected executions,
4,096 observations and 128-byte mutable observation strings. Work is approximately
O(P × S × (O + S + E) × B), plus bounded sorting, for properties P,
required steps S, observations O, expected executions E and bounded encoding size B. Existing snapshot completeness is consumed in O(1), without Git parsing.

## VERDICT SEMANTICS

| Verdict | Meaning |
| --- | --- |
| PROVEN | Required authoritative evidence positively establishes the policy's stated property |
| FAILED | Authoritative evidence establishes that the property is false |
| NOT_PROVEN | Required evidence absent/insufficient; first-class and distinct from failure/success |
| NOT_APPLICABLE | Explicit authority applicability exclusion; never inferred from missing evidence |
| INCONCLUSIVE | Evidence exists but infrastructure failure, contradiction, ambiguity or unknown versions prevent a reliable conclusion |

Completed normal exit 1–255 produces FAILED command completion. Missing/invalid
completion exits, setup/start/runtime failures and ambiguous termination are
INCONCLUSIVE. Timeouts/resource limits fail the explicitly bounded completion
property. An absent required command/fact is NOT_PROVEN. Contradictory authoritative
facts are INCONCLUSIVE; identical redundant observations are idempotent. Supported
producer/schema versions are explicit; unknowns cannot silently pass. Controller
unavailable-execution observations cannot assert positive source/isolation facts.

`TEST_SUITE_COMPLETES` means the authority-designated command completed with exit
zero in the bound execution context. It does not establish test coverage or absence
of defects. `BUILD_COMPLETES` does not establish artifact security. Typecheck does
not establish checker soundness. Sandbox/network facts establish configured controls,
not runtime binary attestation or escape resistance. Toolchain remains NotObserved.

## CANONICAL POLICY IDENTITY

Policy schema 1 uses the applicable restricted subset of RFC 8785 canonical JSON:
fixed ASCII object keys, Unicode scalar strings, booleans, arrays and schema=1.
Properties sort by stable ID spelling; producers/step/applicability sets sort by
ASCII bytes and reject duplicates. All object keys sort recursively. Emit compact
UTF-8 JSON, standard deterministic string escaping, no BOM or terminal newline;
SHA-256 exactly those bytes. Input comments/field order/authoring whitespace,
filesystem enumeration, host OS and time do not enter the digest. String contents
are preserved, including description whitespace and Unicode. This does not define
a general cryptographic serializer or certificate format.

Explicit recursive sorting also preserves identity under serde_json/preserve_order
feature unification. Exact canonical vectors and SHA-256 were independently produced
with Python 3.14 and rechecked using Node JSON.stringify/crypto:

- Development bundle 1.0.0: `e128e7a0cfeaf0f11917a35cc655b0e9fe6ea96dcf550bea5d25898ea8f7b9ae`.
- Unicode/control/quote/backslash vector: `d16b30957bbec71442b24289730df4e209e20e6b4b01885c081d5afe4b564357`.

Authoring representation and canonical bytes are separate. Policy version/schema
are part of identity. The supplied authority selection must exactly match bundle
ID/version/digest; mismatches return no evaluation or eligibility. See
[ADR-0023](adr/0023-canonical-policy-identity.md) for the full algorithm and bounds.

## AUTHORITY BOUNDARIES

Policy consumes only application/domain types. It cannot depend on Docker JSON/CLI,
materializer/source adapter internals, filesystem syscalls, HTTP/Axum or signing.
Application/domain do not depend on policy. The extended dependency guard enforces
these workspace edges and keeps evidence/crypto out of active CLI/daemon links.

`--authority-config` is explicit trusted operator command provisioning, separate
from target `--config`. Authority steps compose first; projects cannot overwrite
or remove them. Command properties require exact policy step IDs, authority-required
provenance and matching category. Project labels/stdout alone cannot satisfy them.
The CLI embeds one pinned policy and provides no weaker-policy/waiver/signing flag.
Strict project configuration rejects policy/severity/applicability/version/digest/
waiver/disable fields. Target source-only OCI layers cannot overwrite policy files.

Development bundles live under the ArchCert authority checkout's policies directory;
production storage must be separate/access-controlled. An operator with CLI/build
access is trusted authority. SHA-256 is identity, not policy/evidence authenticity.
No remote authentication or durable authority provisioning is claimed.

## EVALUATION FLOW

Exact accepted immutable SourceSnapshot + authority-resolved ValidationPlan +
separate expected execution IDs + typed observations + pinned immutable PolicyBundle
→ property interpretations → findings → unsigned certification eligibility.

Observations now carry explicit schema, whole-plan digest and profile in addition
to existing source/step/execution/kind/producer/version. Conversion rejects a step
from a different plan and mismatched command/profile/image/limits. The plan digest
covers schema/kind and full immutable plan, including order, commands, profiles,
image/programs/limits, category and provenance. Expected execution identities come
from controller results independently of candidate observations. Unknown or foreign
bindings cannot establish properties. Historical unbound M3.5 reports are not
silently upgraded into authoritative M4A evidence.

The CLI's `evaluate` runs the same exact source→plan→materialization→sandbox flow
as `run`, then emits JSON. Runtime failures without execution payload yield only
an unavailable-execution observation. Missing setup facts remain missing. Source
and sandbox cleanup remain separately reported. Exit 0 describes the completed
execution/evaluation operation, not eligibility; nonzero execution/runtime errors
can emit the complete evaluation before returning exit 1. No API expansion:
HTTP certification submission remains 501 UNAVAILABLE, without a job or persistence.

## FINDING MODEL

Each property result includes fixed ID/description, applicability, verdict, severity,
blocking flag, required evidence selectors, actual stable payload references and
reason code. Actual references contain typed observation identity plus canonical
payload SHA-256, or the immutable snapshot reference. Detailed execution payloads
are not duplicated in property results. Retained report tests resolve every
observation reference and verify plan/source/policy bindings.

A Finding contains deterministic SHA-256 ID, property, severity, verdict status,
reason, blocking flag and observation references. Its correlation preimage contains
schema, exact source, exact plan digest, policy reference, property, verdict and
reason; timestamp, per-run UUIDs and explanatory prose are excluded. Detailed
references preserve exact execution identities. Findings arise only from authority
evaluation. Multi-slot conclusion precedence and canonical ordering are defined
in [ADR-0022](adr/0022-deterministic-policy-authority-and-verdicts.md).

## ELIGIBILITY MODEL

P0 (critical source/isolation/authority) and P1 (essential engineering) always block
when unsatisfied; every mandatory property blocks at every severity. Optional P2
(additional engineering) and P3 (informational) findings can be advisory. PROVEN
satisfies a requirement; NOT_APPLICABLE does so only with explicit policy permission.
FAILED, NOT_PROVEN and INCONCLUSIVE never satisfy mandatory requirements.

ELIGIBLE_FOR_CERTIFICATION requires every blocking requirement satisfied.
NOT_ELIGIBLE means a definite blocker exists, including missing evidence or
unpermitted non-applicability. INCONCLUSIVE means blockers exist and all are
INCONCLUSIVE. Individual property uncertainty is retained even when another
property causes NOT_ELIGIBLE. No waiver/accepted-risk/human override exists.
No CERTIFIED result exists in the evaluator's eligibility enum.

## FILES CHANGED

- Cargo.lock: workspace dependency edges only, no third-party version additions.
- CLI Cargo.toml/src/main.rs and new tests/policy_cli.rs: evaluation composition,
  operator mandatory commands, unavailable-execution facts and truthful JSON.
- Domain src/lib.rs: precise five-state semantics documentation.
- Application Cargo.toml/src/validation.rs and tests/observations.rs: exact plan
  digest, explicit observation schema/profile/plan binding, mandatory builder and
  cross-plan conversion regression. tests/architecture.rs: policy dependency guard.
- Policy Cargo.toml/src/lib.rs, new src/model.rs/src/evaluation.rs and tests/policy.rs:
  replacement evaluator/model, bounds, identity, findings/eligibility and regressions.
- Policy tests/fixtures/canonical-unicode.toml/.json and policies development TOML/
  canonical JSON: fixed independently reproduced vectors and real authority bundle.
- Evidence src/lib.rs: inactive payload references replacing verdict-bearing inputs.
- scripts/demo-policy-evaluation and tests/fixtures/policy-target/checks.py:
  reproducible controlled exact Git commits and real OCI demonstrations.
- docs/policy/README.md, CONTROLLED_AUTHORITY.toml and four retained JSON reports.
- docs/MILESTONE_4A_BASELINE.md, this report, ADRs 0022–0024 and
  docs/threat-model/POLICY_EVALUATION.md.
- README.md and architecture ARCHITECTURE.md/CURRENT_ARCHITECTURE_SNAPSHOT.md/
  TCB_AND_DEPENDENCIES.md: current executable behavior, boundaries and TCB review.

The supplied workspace has no Git metadata; no commit/PR is claimed. Existing
historical ADRs/reports and source/materializer/runner enforcement code are retained.

## TESTS ADDED

26 new unique default tests: 23 policy, two CLI and one application plan-binding
regression. Default suite total: 132 passing, zero failed, eleven ignored live groups.
No heavy property-test dependency was added. Finite exhaustive tests cover all
5,040 property orderings, all 24 four-fact permutations plus whole-observation
rotations, explicit audit-time changes and stable finding IDs. Cross-source/commit/
tree/plan/profile/step/execution/category/discriminator/producer substitutions,
missing facts, empty plans, duplicates/contradictions, unknown versions, all five
verdicts, severities, authority provenance, project escalation, parser/complexity
bounds, stdout spoofing, policy pin mismatches and retained evidence references
are covered. Applicability remains applicable even if project commands disappear.

## REAL/CONTROLLED DRY RUNS

[Retained reports and reproduction guide](policy/README.md) contain complete inputs,
observations, property results, findings and eligibility. All say UNSIGNED POLICY
EVALUATION, NOT A CERTIFICATE and certificate=NOT ISSUED.

| Scenario | Test property | Eligibility |
| --- | --- | --- |
| Actual controlled passing typecheck/test/build | PROVEN | ELIGIBLE_FOR_CERTIFICATION; seven properties PROVEN |
| Actual controlled unittest exit 1, despite TESTS PASSED stdout | FAILED | NOT_ELIGIBLE |
| Actual runner invoked with unavailable /usr/bin/false client | INCONCLUSIVE | NOT_ELIGIBLE; required isolation/source-view facts also absent |
| Actual Bottle version command only | NOT_PROVEN | NOT_ELIGIBLE; typecheck/test/build all NOT_PROVEN |

Controlled passing commit `67085b42fe02ff0832641629a31634338214be00`, tree
`c6365ec31116a8e66e83f91b058c472fe0064df7`, snapshot
`5241a6ce473582f26aa1c6ffab22f9082ecedc26cf11d09a6e641ad79cc5d8af`.
Failing commit `44d8bba2c0d305b4aa2870c6caafa74dbbe77fd1`, tree
`feb95c6e8174316a51197c83cb8d739940c2831f`, snapshot
`81597c168e33b10fd28ca51aedac8612e9b65ab20f608d87049de9061abf8bf5`.
Controlled plan SHA-256
`8ef37e471318bae8dae6778a4e023254e20a298c006f569c3dc229720d7cfb27`.
The tiny fixture's typecheck checks its own annotations/result type, not general
Python type correctness; its build compiles its source under bounded /work.

Bottle exact commit `8ec5fe29420d14998c0d86885083983eaea8b839`, tree
`e0851c0b9e8f8c96e3d3bf2a1eb6bc07d9ed1667`, snapshot
`e3f098f88ca986831b531f2f055c76513ad55360785d81f5f43c34a4d98c92b0`;
plan SHA-256 `394062de021f07b186ff0308d846707184197f1e836b055a0e5a983c177113e9`.
Only python3 /source/bottle.py --version ran. Four source/isolation properties
are PROVEN; mandatory validation evidence remains absent. No policy was weakened.
The existing manually acquired/pack-converted M3 Bottle loose objects were reused;
no new production Git ingress/acquisition capability was introduced.

## COMMANDS ACTUALLY EXECUTED

Baseline and full implementation gates:

```bash
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo deny check
./scripts/check-architecture
```

Additional development checks included cargo fmt, focused application/policy/CLI
tests, unlocked workspace-only manifest-edge resolution, cargo build -p archcert-cli,
source/dependency searches and independently computing policy vectors using
/opt/local/bin/python3.14 and /opt/local/bin/node. The serializer feature check was:

```bash
cargo test -p archcert-policy --test policy \
  --features serde_json/preserve_order --locked
```

Live provisioning and reproduction actually used:

```bash
/opt/local/bin/colima list
/opt/local/bin/colima start archcert-m3 --activate=false
/opt/local/bin/colima --profile archcert-m3 ssh -- systemctl --user is-active docker
/opt/local/bin/colima --profile archcert-m3 ssh -- id -u
ssh -F /Users/cainho/.colima/_lima/colima-archcert-m3/ssh.config \
  -o ControlMaster=no -o ExitOnForwardFailure=yes -N \
  -L /Users/cainho/Projetos/archcert/target/m4a/rootless.sock:/run/user/501/docker.sock \
  lima-colima-archcert-m3
ARCHCERT_TEST_DOCKER=/opt/local/bin/docker \
ARCHCERT_TEST_ENDPOINT=unix:///Users/cainho/Projetos/archcert/target/m4a/rootless.sock \
ARCHCERT_TEST_IMAGE=python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f \
./scripts/demo-policy-evaluation
ARCHCERT_TEST_DOCKER=/opt/local/bin/docker \
ARCHCERT_TEST_ENDPOINT=unix:///Users/cainho/Projetos/archcert/target/m4a/rootless.sock \
ARCHCERT_TEST_IMAGE=python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f \
./scripts/test-live-oci
/opt/local/bin/colima stop archcert-m3
```

The demonstration script invokes the built CLI source inspect/evaluate commands
with exact source commit/snapshot, authority project/repository, pinned image,
explicit workspace/client/endpoint and either the operator authority commands or
Bottle's separate project request. It records reports directly; no observation
JSON is manually invented to make the real passing/failing cases succeed. The
unavailable-runtime case deliberately substitutes only the trusted client path.
Independent labeled container/image queries after the tests found no leftovers;
temporary source roots were empty. The dedicated VM was stopped again.

## RESULTS

Baseline and initial complete implementation gates all passed. The additional
serde_json/preserve_order run passed all 23 policy tests, including both exact
canonical vectors and retained report reference checks. Final post-hardening workspace results: all seven required gates passed, exit 0.
Default suite: **132 passed, zero failed, eleven explicitly ignored live groups**.
The architecture dependency guard passed separately and within default tests.
Rustdoc denied warnings; cargo-deny advisories/bans/licenses/sources passed with
only the existing justified upstream syn/winnow duplicate warnings.

Logs are retained under ignored target/m4a: baseline-{0..6}.log, verified-{0..6}.log,
verified-results.json, preserve-order-final.log, demo.log and live-oci.log.
Final gates were repeated after explicit recursive canonical-key sorting was added;
policy/plan/observation/finding digests and retained results remained identical.

Development failures were corrected and are not counted as passing gates: a test
fixture initially used the wrong existing SourcePath/SourceMode APIs; strict parser
regressions reproduced the Serde unit-variant unknown-field gap; automatically
created redundant Rust module stubs duplicated integration tests and triggered
missing-doc warnings, so those stubs were removed. The first serializer-feature
run exposed an unsorted JSON wrapper in the retained-report test's own digest
calculation; it was corrected to use the documented canonical ordering, and the
complete feature run passed. The system Python lacked tomllib; independently
provisioned Python 3.14 was used for vector generation. No test, assertion or
security deadline was weakened.

## LIVE OCI RESULT

**11 passed, zero failed, zero ignored**, serial opt-in live gate in 106.19 seconds.
No deadline/assertion was weakened or test disabled. Actual source/environment,
network, host isolation, resource, output, timeout/descendant and cleanup groups
passed. Passing/failing policy target commands also ran on the real rootless OCI
path; the deliberately unavailable runtime scenario started no target.

Observed Docker client 29.8.1, rootless Docker server 29.5.2, runc 1.3.5,
containerd v2.2.4/rootlesskit 3.3.0, Ubuntu 24.04.4/Linux 6.8.0-117-generic inside
the dedicated Colima VM; details remain in retained observations/evidence.
Native Linux is still **NOT YET QUALIFIED**. Existing pinned Python image reused
without a pull. Baseline and final Colima profiles both report Stopped.

## KNOWN LIMITATIONS

This is unsigned process-local development evaluation. It trusts controller
observations and independent execution/policy selections supplied by trusted
callers, not arbitrary deserialized target claims. Reports have no cryptographic
authentication; a digest does not authenticate policy/evidence origin. Authority
storage, command review, runtime/image approval and operator access are administrative.

Only seven supported properties, one CLI policy profile, explicit authority command
selection, one execution per step, simple authority-profile applicability and no
inheritance/retries/toolchain-version proofs. Tests/builds mean command completion,
not meaningful coverage, defect freedom or artifact assurance. Cleanup failures
are separately operationally reported; no cleanup-success policy property exists.
Failures before an accepted source/bound execution context can still return a CLI
error before a complete evaluation report. The evaluator itself accepts empty/
incomplete evidence and incomplete snapshots and returns conservative results.

All M1–M3.5 ingress/filesystem/runtime limits remain: selected loose objects,
Unix controller, unresolved LFS/submodules, manual external Bottle preparation,
process-local store, shared-kernel/container trust, no production scheduler,
authenticated push/pack gateway or native Linux qualification. No production-grade
assurance or independent review is claimed from this engineering self-validation.

## UNRESOLVED RISKS

Compromised trusted controller/runtime/image/dependencies/operator can forge or
misinterpret inputs. Policy authoring mistakes can omit requirements or approve
meaningless commands; deterministic evaluation cannot prove command quality.
Canonical/evaluator schema and authority version governance require review on
future changes. Cross-OS execution is structurally deterministic but has not been
independently qualified on multiple native operating systems in this workspace.
Parser fuzzing, global admission/RSS/I/O/storage quotas, authenticated evidence
retention, persistent orphan recovery and stronger source/runtime attestation
remain absent. See the complete [policy threat model](threat-model/POLICY_EVALUATION.md).

## DEFERRED WORK

Certificate construction/serialization, signing/Ed25519/keys/detached signatures,
durable authority/evidence/job/source stores, PostgreSQL, authenticated transport,
source acquisition extensions, policy inheritance, retries, waiver/risk acceptance/
human overrides, production execution qualification and semantic review. No inactive
signing scaffold was invoked or expanded. No certificate.json schema is finalized.

## READINESS FOR MILESTONE 4B

M4A supplies exact source/plan/policy identities, deterministic property verdicts,
structured stable findings, references to consumed typed observations and explicit
pre-signing eligibility. Missing/foreign/hostile output evidence cannot silently
pass, target failure stays distinct from runtime uncertainty, and ordering/time
do not decide eligibility. This is the input immediately before future certificate
construction and signing. M4B must separately design authenticated retention and
canonical certificate construction, then sign successfully before any CERTIFIED
result. Eligibility remains **NOT A CERTIFICATE**.
