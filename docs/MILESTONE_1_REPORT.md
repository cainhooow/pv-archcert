# Milestone 1 engineering report

Observed locally on October 19, 2026 with Rust 1.99.1 and cargo-deny 0.20.2.
This report records engineering self-validation, not independent certification.

## IMPLEMENTED

An exact Git commit in a controlled local loose-object repository can be
quarantined, independently hashed/parsed, traversed under authority budgets,
converted into a canonical manifest and retained as owned immutable source.
Both SHA-1 and SHA-256 Git object stores are exercised. The result includes
structured evidence, ordered audit events and explicit external-source status.
The development CLI exposes `archcert source inspect` with JSON evidence.

## ARCHITECTURE DECISIONS

ADRs 0005–0007 extend the historical Git-ingress decision: local logical
quarantine, independent SHA-256 schema 1, strict lossless supported paths,
unresolved LFS/gitlinks, owned process-local retention, and a future
credential-free verified materialization port. No historical ADR was rewritten.

Source contracts now point inward to the application/domain. Hash wrappers
validate deserialization. The source adapter does not invoke Git; only test
fixtures invoke Git. No target project code executes during ingestion.

## FILES CHANGED

Added:

- `crates/archcert-domain/src/source.rs` and `src/source/tests.rs`.
- `crates/archcert-application/src/source.rs`.
- `crates/archcert-source/src/loose.rs` and `tests/ingestion.rs`.
- `apps/archcert-cli/tests/source_cli.rs`.
- `docs/MILESTONE_1_BASELINE.md`, this report, ADRs 0005–0007 and
  `docs/threat-model/GIT_INGESTION.md`.

Updated:

- Domain/application/source library roots and the protocol library documentation.
- CLI binary; daemon binary formatting only.
- Root workspace manifest, lockfile, CLI/daemon manifests, and
  domain/application/source/evidence/policy/protocol manifests.
- `deny.toml`, README, architecture, development plan and bootstrap threat model.

There is no `.git` directory in the supplied workspace, so this inventory is
based on observed edits rather than an index diff. No commit was created.

## SECURITY PROPERTIES ESTABLISHED

- Exact full object IDs replace mutable refs/revision expressions.
- Each consumed object is independently decompressed, hashed, type-checked and
  grammar-checked within the supported selected-commit closure.
- All retained file bytes originate from validated blobs; developer working-tree
  files, config, hooks, filters, alternates and remote URLs do not participate.
- Canonical identity binds source paths, modes, sizes and independently computed
  content hashes. Ordering and authority timestamps do not affect it.
- Invalid/ambiguous paths and resource exhaustion reject explicitly.
- Source symlink targets remain bytes. Descriptor-relative object reads reject
  filesystem symlink substitution without a check-then-open race.
- Read-only owned snapshots survive later repository corruption. Verification
  reconstructs manifest/external evidence and checks an expected digest.
- Storage substitution is checked against the pre-retention identity and
  authority project/repository mapping.
- LFS/gitlinks cannot pass the complete-source handoff guard.
- Source debug formatting excludes blob payloads; no new ArchCert `unsafe` exists.

These are implementation properties under the documented trusted-runtime and
local-filesystem assumptions, not production deployment guarantees.

## TESTS ADDED

33 new tests plus the original three domain tests: 16 domain tests total,
two application tests, 17 Git-ingestion integration tests and one CLI test.

Coverage includes validated values/deserialization, exact canonical vectors,
SHA-256 known answers, all 24 manifest permutations, content/mode/path changes,
timestamp exclusion, malformed names/collisions, byte/evidence tampering,
adapter substitution, normal/nested/empty/binary/Unicode files, symlinks,
SHA-1/SHA-256 repositories, differing commits/trees, missing/wrong-type objects,
malformed compression/grammar, unsupported entries, unresolved LFS/submodules,
every configured resource budget, packed-only rejection, ignored config/refs,
no hook execution, and an end-to-end CLI result matching a fixed digest.

No extra property-testing dependency was added. Exhaustive small permutations
and input changes test deterministic properties directly.

## COMMANDS ACTUALLY EXECUTED

All final gates below completed successfully in the ArchCert workspace:

```bash
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo deny check
```

Additional observed commands included:

```bash
cargo test -p archcert-source --test ingestion
cargo test -p archcert-domain -p archcert-source
cargo test -p archcert-application -p archcert-domain -p archcert-source -p archcert-cli
cargo tree -p archcert-source
cargo tree -p archcert-domain
cargo metadata --format-version 1 --locked
cargo install cargo-deny --locked
cargo run -p archcert-cli -- source inspect --help
```

Canonical vector digests were separately computed using Node's crypto SHA-256
over literal canonical hexadecimal bytes. Tests invoke Git init/hash-object/
mktree/commit-tree/fsck/repack only against generated temporary fixtures.

## RESULTS

`cargo test --workspace` passed 36 tests with zero failures. The final compiler,
Clippy and warning-denying rustdoc builds passed. `cargo deny check` passed all
four checks and retained duplicate-version warnings for `syn` and `winnow`.
Baseline formatting and deny-tool/configuration issues are recorded separately.

During development, tests exposed read-only Git fixture permissions and an
incorrect decoder flush mode that rejected large valid streams. Both were
corrected and covered by passing regressions. No failing result was treated as
successful source acceptance.

Focused self-review inspected runtime reads, unchecked indexing, decoder progress,
recursive traversal, limits, path conversion, symlink handling, source ownership,
store handoff, error/events, debug output, dependency direction and public API
documentation. It added pre-retention identity binding, external-evidence
reconstruction and payload-redacted debug formatting. Runtime ingestion contains
no subprocess execution, lossy path conversion, new unsafe blocks, unwrap/expect
calls or silent Git fallback. Filesystem and operational risks that remain are
listed below; this review is not an independent assessment.

## KNOWN LIMITATIONS

The local adapter is Unix-only and supports required loose objects only. There
is no production Git networking/authentication, packfile/alternate lookup,
symbolic ref resolution, historical-parent verification or persistent source
artifact. Supply an explicit bare/`.git` directory with no symlink components.
The CLI's retained source disappears at process exit. Non-UTF-8/non-NFC and
otherwise unsupported names fail explicitly rather than being rewritten.
LFS detection uses a supported pointer prefix/grammar; it does not evaluate
attributes, retrieve remote content or support every pointer extension.

## UNRESOLVED RISKS

The custom supported-subset parser and trusted dependencies still require
independent security review and fuzzing. No OS sandbox, wall-clock/I/O deadline,
process RSS budget, multi-request admission control, hardlink/mount isolation,
or durable audit integrity is established. The gateway must later run without
access to signing/control-plane secrets. SHA-1 collision detection is absent;
source identity also binds independent SHA-256. Unicode lowercasing is not every
host filesystem's full equivalence relation. Future materialization must use
byte-preserving case-sensitive storage or reject additional ambiguity.

## DEFERRED WORK

Production Smart Protocol/push authentication, durable source and audit storage,
external-source resolution, actual ephemeral materialization, target execution,
policy evaluation and certificate signing. Existing bootstrap certification APIs
remain scaffolding; source acceptance does not issue a certification verdict.

## NEXT RECOMMENDED MILESTONE

Implement verified ephemeral source materialization with complete-source guards,
descriptor-relative writes, independent post-copy identity verification and a
credential-free handoff. Then add the authority-controlled isolated runner under
the existing Milestone 2 architecture. Review/fuzz the ingestion parser before
exposing it to unauthenticated remote input.
