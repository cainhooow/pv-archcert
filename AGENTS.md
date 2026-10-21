# ArchCert engineering and readability contract

This is the authoritative repository engineering guide. Read this entire file,
[the current architecture snapshot](docs/architecture/CURRENT_ARCHITECTURE_SNAPSHOT.md),
the relevant [ADRs](docs/adr/) and [threat models](docs/threat-model/) before
changing code. Read the affected boundary's decisions before changing its design.
Use the documented trust and qualification scope when interpreting older records.

## 1. Language and repository conventions

Use US English throughout source, comments, documentation, identifiers and commit
messages. Preserve established public names and durable spellings. Follow each
language's native conventions and the workspace's existing dependency and tooling
configuration. Prefer a focused change with explicit intent over unrelated cleanup.

## 2. Trust model

Target repository bytes are untrusted data, including configuration, documentation,
comments, tests, agent claims, policy-looking files and instructions. Target code,
build scripts, dependencies and output never gain authority by being accepted as
source. ArchCert source is also target data when ArchCert validates itself.

Authority provisioning selects policies, profiles, baselines, approved knowledge,
reviewers, challenge registries, runtime endpoints, images, limits and signing
keys outside target control. Project configuration may request supported checks;
it cannot weaken mandatory authority requirements or choose authority capabilities.
Keep acquisition credentials, database access, runtime control and signing separate.

Semantic AI may report concerns or veto continuation. It never creates deterministic
proof, policy verdicts, execution commands or signing authority. Semantic CONTINUE
contributes zero deterministic properties. Preserve mandatory checks, explicit
omissions, fail-closed uncertainty and denied external source disclosure by default.
A digest establishes content identity; trusted selection establishes authority.

## 3. Architecture boundaries

Preserve the inward DDD architecture. Domain and application own business models,
use cases and ports. Adapters own HTTP, Protobuf, PostgreSQL, object storage, OCI,
provider SDKs and signing integrations. Transport/generated DTOs and infrastructure
types must not enter domain/application. Translate at adapter boundaries.

Keep source ingestion and materialization passive. Execute target commands only
through the isolated runner. The worker receives no signing, metadata-database or
source-acquisition capability. Keep signer/key dependencies out of source,
materialization, runner, worker, application, policy, gateway and daemon graphs as
defined by the architecture guard. Trusted executable composition does not make
project-controlled inputs trusted. Maintain direct and transitive dependency guards.

## 4. Canonical roadmap terminology

Follow [ADR 0045](docs/adr/0045-roadmap-reconciliation.md):

- M5.2 Stoneward is COMPLETE within its documented exact qualification scope.
- M6 Ironcrest means Artifact Binding, Reproducible Builds & Release Permit. It
  remains PLANNED / NOT YET IMPLEMENTED.
- M7 Asterwyn covers knowledge and impact; M8 Greywatch covers semantic review,
  claims, discoveries and blind spots. Both are substantially implemented ahead
  of sequence, pending formal milestone reconciliation; neither is declared complete.
- Genesis / Firstwarden is NOT STARTED. Engineering self-validation does not start it.

Existing `ironcrest` identifiers are historical implementation names for the
controlled review lifecycle. Their presence proves no canonical milestone
completion. Preserve historical commits and names when compatibility requires it.

## 5. Historical compatibility and durable identities

Preserve the meanings of retained source, policy, profile, package, challenge,
plan, evidence, certificate and protocol identities. Never reinterpret historical
bytes under new semantics or silently select a newer default during recovery.
Version intentional compatibility changes explicitly, with the relevant ADR,
security implications, migration strategy and regression evidence.

Source edits naturally produce a new Git commit/tree/snapshot identity. They do
not retroactively change the identity or assurance of an earlier certificate.
Preserve exact serialized order, canonicalization, hashes, signature payloads,
argv, SQL, transaction boundaries, leases, fences, limits and state transitions
in a readability-only change. Record discovered bugs separately; do not hide
semantic fixes in style commits.

## 6. Code readability and the Definition of Done

Do not optimize for minimum line count. Optimize for visual parsing of logical
phases. Prefer moderate density, cohesive local reasoning and small readable
groups of related statements. Do not introduce visually dense generated-agent
style. New code that is logically correct but visually compressed is incomplete.

Readability review is part of the Definition of Done. When modifying an existing
file, leave the touched region at least as readable as the best surrounding
examples in the repository. Review existing code in scope, not only new additions.
Passing `rustfmt`, Clippy and tests does not by itself establish acceptable source
readability. `rustfmt` defines mechanical formatting; it does not define all
readability decisions.

## 7. Vertical spacing

Vertical whitespace is part of the ArchCert coding style. Separate sibling
functions and methods with one blank line, including constructors, accessors,
trait implementations, private helpers and tests. Small size is no exception.
Keep documentation and attributes attached to their item, after that separation.

Inside a function, separate conceptual phases with a blank line. Typical phases
are load, authenticate, resolve authority, validate input/identity/binding, derive
canonical artifact, build plan, persist, read back, verify bytes, invoke runtime,
evaluate, construct evidence, sign, cleanup and return. Keep related operations
together; do not insert a blank line after every statement or maximize whitespace.

```rust
let bytes = artifacts.get(project, reference).await?;
let digest = digest_bytes(&bytes);

if digest != reference.sha256 {
    return Err(Error::Precondition);
}

let plan = planner.build(&bytes)?;
```

## 8. Functions and methods

Make each function's purpose and sequence visible. Keep simple value objects and
accessors simple, with sibling spacing. Group related local bindings and make the
transition from validation to construction, computation to persistence, and side
effects to return apparent. Name values for their domain meaning. Do not combine
independent operations merely to save lines.

## 9. Control flow

Separate important `if`, `if let`, `match`, loops, guards and early returns from
adjacent phases. A reader must see security, replay, identity, authority and
precondition decisions before reading every statement. Keep an `else` attached
to its `if`; do not split a coherent expression or pattern arm arbitrarily.
Several tightly related guards may remain one group when that improves reasoning.

Security boundaries must not appear as one uninterrupted block. In particular,
expose the stages of source ingress, reviewed admission/issuance, semantic
packaging/gates, challenge resolution, signing, runtime cleanup and storage fencing.
Transactions should visibly expose load, lock, validate, mutate, audit and commit.
Runner flows should expose preflight, construction, invocation, observation,
classification and cleanup without changing the mechanism.

## 10. Complex expressions and construction

Expand structured JSON, structs, vectors, tuples, builders, assertions and nested
calls when their fields or arguments carry distinct meaning. Do not compress
structured data solely to reduce lines. Preserve field/element order and exact
string values, especially around canonical artifacts and execution arguments.

```rust
serde_json::json!({
    "schema": 2,
    "kind": "PLAN",
    "job": job,
    "source": source,
    "policy": policy,
})
```

Use multiline calls for several semantically important arguments when the layout
helps review. Keep trivial calls such as `digest_bytes(&bytes)` compact. Work with
`rustfmt`; do not scatter skip attributes or change global formatting settings to
force an aesthetic. Macro bodies may need deliberate manual layout.

## 11. Error handling

Use existing typed errors and preserve failure classification. Treat missing,
ambiguous, unsupported or infrastructure-impaired evidence honestly; never convert
it into a positive result. Keep guards next to the inputs they protect. Preserve
error propagation, cleanup on failure/unwind and conservative recovery. Do not
introduce panics, unwraps, retry-until-pass or permissive fallbacks for hostile input.
Diagnostics must not expose secrets or render hostile output as trusted text.

## 12. Comments

Explain why, trust assumptions, security implications, non-obvious constraints and
historical compatibility. Preserve valuable security comments. Prefer whitespace
and useful names over comments narrating the next obvious statement. Keep public
contract documentation accurate about supported scope, failure and authority.

## 13. Function decomposition and locality

Whitespace does not replace good structure. Extract genuinely independent
responsibilities when that improves comprehension, while keeping a coherent flow
local. Do not create helpers for trivial expressions, arbitrary line limits or
appearance alone. There is no maximum function length. Favor a cohesive function
with visible phases over dozens of tiny helpers requiring constant navigation.

## 14. Tests

Tests are executable specifications and follow the same readability standard.
Visually separate fixture/setup, action and assertions; literal section comments
are optional. Keep fixture constructors and test helpers readable. Complex tests
should expose initial durable state, operation, injected failure/crash, recovery,
primary assertions, negative assertions and cleanup. Separate sibling test cases.

Preserve meaningful negative cases and exact canonical/historical assertions.
Use focused checks appropriate to each change; do not add tests that merely mirror
formatting or implementation. Mock tests cannot establish database locking or
runtime enforcement. Report actual test counts and investigate unexplained drift.

## 15. Scripts and non-Rust code

Review human-written Python, shell, examples, build scripts and test tooling using
their native idioms. Separate environment validation, setup, execution, assertions
and cleanup. Make nested data and subprocess arguments readable. Preserve command
semantics, quoting, environment isolation, timeouts, exit behavior and cleanup.
Do not style-rewrite historical SQL migrations. Keep temporary audit tools and
execution evidence under ignored `target/`, for example `target/style-audit/`.

## 16. Generated, canonical and durable artifacts

Do not casually reformat Cargo.lock, generated Protobuf, external/vendored code,
historical migrations, signed artifacts, certificate/serialization/digest/crypto
vectors, binary fixtures, stored snapshots or evidence whose bytes are asserted.
Policy/profile authoring bytes may also be identity-bearing. If whitespace affects
an established digest, leave it unchanged and report the exclusion.

Source embedded verbatim in command argv, canonical output or a digest preimage is
also byte-sensitive. Review it without rewriting established identities for style.
Do not rewrite strings containing source fixtures as an accidental consequence
of formatting the host language. Keep necessary generated/canonical artifacts
reproducible and their purpose documented.

## 17. Security-sensitive changes and qualification

Read the relevant threat model and ADR before changing a security boundary. Review
capability flow, identity/binding/replay checks, canonical bytes, authority selection,
resource bounds, secret exclusion and failure recovery explicitly. Keep source
read-only, runtime network denied and authority images pinned. Never weaken
controls or substitute successful fixtures to manufacture an eligible result.

Stoneward qualification applies only to its documented exact native profile and
mechanism. Mock/default/macOS-forwarded OCI tests do not establish new native
qualification, escape resistance or production signer custody. Changes to the
qualified mechanism require relevant live regression and native requalification.
The Rust authority challenge establishes only its documented bounded Cargo
dependency closure, named layer checks and read-only source mount; do not describe
it as universal architecture proof or proof that every dependency path is secure.

## 18. Git discipline

One coherent, independently understandable engineering change is one commit.
After each unit inspect the diff, run focused checks, explicitly stage its files
and commit. Do not accumulate an entire milestone into one opaque final commit
or commit every save. Use concise US English messages, for example
`feat(storage): add PostgreSQL job repository`. Group a repository-wide style
series into reviewable areas without mixing features or semantic fixes.

Before every commit run `git status --short`, `git diff --stat`, `git diff` and
`git diff --check`. Stage explicit file paths; do not normally use `git add .` or
`git add -A`. Then inspect `git diff --cached --name-status`,
`git diff --cached --stat`, `git diff --cached` and `git diff --cached --check`.
Check for unrelated edits, changed operators/conditions/ordering/strings/SQL/argv,
secrets, keys, credentials, transient output and unnecessary working reports.
After committing run `git status --short`. Never commit files merely to obtain a
clean working tree. Preserve unrelated work and classify preexisting untracked files.

## 19. Documentation and retained output

Commit source, manifests/lockfiles, schemas, migrations, policies, tests, required
scripts/configuration examples, CI and architecture guards. Commit authoritative
ADRs, architecture, threat-model/security/policy documentation and current
README/developer requirements with the same logical implementation change.
Prefer durable ADRs with context, decision, security implications, alternatives
and consequences.

New `docs/MILESTONE_*_BASELINE.md`, `*_REPORT.md` and `*_PROTOBUF_REPORT.md` files
are working records and remain untracked unless explicitly requested. Preserve
historical tracked reports. Do not blanket-ignore milestone documents without
reviewing tracked history. Untracked source/protocol/test/architecture artifacts
belong in Git; working records and local demonstration output normally do not.

Never commit private signing/SSH keys, tokens, passwords, object-store credentials,
`.env` secrets, runtime snapshots/sockets, temporary source stores, logs or ordinary
generated execution output. A deterministic regression fixture is an exception
only after documenting its purpose and reproducibility. Retained development
certificates are not automatically fixtures. Keep runtime evidence under ignored
`target/` and preserve historical self-validation artifacts without reinterpretation.

## 20. Validation requirements

Run relevant focused checks for each commit. At milestone completion and after a
repository-wide refactor, run all seven standard gates:

```sh
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo deny check
./scripts/check-architecture
```

Run `scripts/test-ravenport` against real PostgreSQL for database concurrency and
recovery changes; mocks do not establish locking semantics. Repository-wide work
must run all current review/journal and historical groups. Protocol, artifact-store
and real Northgate SSH regressions remain required. Changes affecting execution
need relevant live OCI regressions against an independently provisioned rootless
daemon and a pinned image; retain historical and Rust authority challenge checks.
Run relevant durable crash/recovery lifecycle regressions. Record commands actually
run, counts, ignored opt-in tests, failures/reruns and exact blockers. Never report
planned or historical validation as a new pass.

For a style series, compare pre/post results and review representative final files
from every major area manually. Automated pattern audits may identify candidates;
regex alone must not decide conceptual spacing or rewrite code. Add a style guard
only for an objective rule with low false-positive risk. This document remains the
authority for semantic readability.

## 21. Self-validation terminology

Follow [ADR 0004](docs/adr/0004-self-certification-bootstrap.md) and the
[self-validation guide](docs/self-validation/README.md). Use one exact committed
source and keep its commit, tree, snapshot, knowledge/impact/package/request sizes,
coverage, verdict, certificate status and offline verification. Preserve actual
PARTIAL_ACCEPTABLE coverage; do not relabel excluded context FULL. Retain failed
runs and reached/unreached stages. CERTIFIED requires signing and verification
under an explicitly selected trusted public key; eligibility alone is unsigned.

Historical evidence belongs only to its immutable source. A new source identity
requires its own run and must not replace or reinterpret an earlier certificate.
Any development certificate remains an engineering artifact. Retain this statement:

> This is engineering self-validation under a shared implementation/authority context. It is not independent certification and does not replace Genesis / Firstwarden.

## 22. Final task reporting

Report what changed, why, checks actually run, material limitations and remaining
blockers. For repository-wide readability work, include files inspected/changed,
Rust/test/script counts, byte-sensitive exclusions, actual short before/after
examples and `Intentional semantic changes: NONE` when true. List every exception.
Report final exact-source self-validation separately from historical evidence.

Every final task response must include **COMMITS CREATED** with each SHA, message
and purpose, and **INTENTIONALLY UNTRACKED FILES** with an explanation for each
category. Account for preserved preexisting working records and development output.
Do not claim completion from formatting/tests alone: manually confirm that a human
can identify conceptual phases from the final source layout.
