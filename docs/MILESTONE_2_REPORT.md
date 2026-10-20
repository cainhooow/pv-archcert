# Milestone 2 engineering report

Observed on October 19, 2026 using pinned Rust 1.99.1 on the local macOS host.
This is engineering self-validation, not independent certification or a formal
proof of filesystem race freedom.

## IMPLEMENTED

Accepted COMPLETE snapshots can be retrieved through an authority-scoped store
port, independently reverified, and materialized into fresh private Unix
workspaces. The adapter enumerates actual filesystem contents and reconstructs
canonical schema 1, compares expected/observed source SHA-256, applies a limited
read-only permission seal, reverifies after sealing and again at handoff.

The result includes a narrow `RunnerInput<MaterializedDirectory>`, separate
authority cleanup lease, structured evidence and audit events. No target code
executes, and no Git operation or source-access credential is needed by this
materializer. The development `source inspect --materialize-under ROOT` command
demonstrates ingest/materialize/verify/seal/handoff/destruction and emits JSON.

## ARCHITECTURE DECISIONS

ADRs 0008–0010 document verified materialization, descriptor-relative/no-follow
operations, actual filesystem reconstruction, permission sealing, source-only
runner input and cleanup. Historical ADRs were not rewritten. Domain and
application remain independent of filesystems, Docker, databases and Git adapters.

`SourceStore` now supports exact project/repository/full-identity lookup. The
provisional materializer contract now requires source capability identity and
workspace binding. Real platform capability construction is private to the
trusted adapter. Pending and sealed source have distinct types; only final
verification issues runner input. Evidence alone cannot deserialize into it.

The new infrastructure crate uses existing Rustix safe wrappers and adds no new
third-party crate. Its existing process feature supports effective-UID checks.
Temporary directory and Git tooling remain test/development concerns, not the
runtime filesystem implementation. The workspace unsafe-code prohibition remains.

## FILES CHANGED

Added:

- `crates/archcert-domain/src/materialization.rs`.
- `crates/archcert-application/src/materialization.rs`.
- `crates/archcert-materialization/Cargo.toml`, `src/lib.rs`, `src/unix.rs`,
  and `tests/materialization.rs`.
- `docs/MILESTONE_2_BASELINE.md`, this report, ADRs 0008–0010 and
  `docs/threat-model/MATERIALIZATION.md`.

Updated:

- Root `Cargo.toml` and `Cargo.lock` for the new workspace crate/Rustix feature.
- Domain library root and source error model for scoped store lookup failure.
- Application library root/source contracts and the existing test store adapter.
- Source memory-store adapter for authority-scoped immutable retrieval.
- CLI manifest, binary and end-to-end test for development materialization.
- README, architecture, development plan and bootstrap threat-model links.

The supplied workspace has no `.git` metadata; the inventory records observed
edits rather than an index diff. No commit was created.

## SECURITY PROPERTIES ESTABLISHED

- Only exact scoped source is loaded; owned bytes are rehashed before writes.
- Incomplete LFS/submodule source is rejected before destination creation.
- Authority UUIDs and exclusive directory creation prevent workspace reuse;
  pre-existing names are not emptied, repaired or overwritten.
- Source paths are independently validated and resolved through held directory
  descriptors with no-follow semantics. Files are created exclusively.
- Only accepted bytes are written; source modes are applied explicitly through
  descriptors. Symlink targets remain uninterpreted bytes.
- The verifier enumerates all entries, detects extra/missing files and empty
  directories, verifies created inode/device identities, and reconstructs hashes
  from actual regular files and symlink targets without following links.
- Digest mismatch fails closed. No runner input is returned from a rejected phase.
- Verification occurs before seal, after seal and immediately before issuance.
- Runner input contains only source handle, workspace and expected source identity.
  Source-store/Git clients, cleanup parents, credentials and policy/signing
  authority are absent from the actual platform source capability.
- The runtime materializer reads no sensitive environment/configuration and
  invokes no subprocess. Ordinary 022/077 umasks preserve canonical identity.
- Cleanup uses bounded descriptor-relative deletion and never chmods files or
  follows symlink targets. Success and failure are explicitly distinguished.

These properties depend on the documented private-root, trusted-local-filesystem
and trusted owner/kernel assumptions. They do not establish a sandbox.

## MILESTONE 1 DEFECTS FOUND, IF ANY

No reproduced Milestone 1 ingestion defect was identified. Canonical vectors,
NFC path semantics, Git modes, link bytes, owned snapshot identity, external-source
detection and ingestion accounting were reviewed and preserved.

Required contract extensions were documented before implementation: scoped store
retrieval, constrained materialization capability, explicit state/evidence and
cleanup. Schema 1 intentionally omits directories, so actual directory sets are
checked separately. OS-unrepresentable link targets reject explicitly rather than
weakening the source model or silently rewriting payloads.

## TESTS ADDED

29 new tests and an extended CLI end-to-end test. New tests comprise three domain,
two application, three filesystem-adapter unit tests and 21 materialization
integration tests. The workspace now has 65 tests total.

Coverage includes workspace UUIDs, state transitions, error distinctions, sealed
identity/workspace matching, evidence timestamps, independent path rejection,
exclusive creation, prepopulation, text/binary/empty/nested/executable/Unicode
source, raw link bytes, deterministic repeated materialization, incomplete-source
rejection, wrong digests, wrong modes, missing/extra files and empty directories,
changed links, host-link escapes, hardlinks, directory/root replacement, authority
parent rename, phase-boundary mutation, cleanup receipts/failure and all budgets.

An isolated subprocess test poisons HOME, Git configuration, SSH socket, AWS,
database/API credential variables and TMPDIR while testing 022/077 umasks. Tracked
`.gitconfig`/`.ssh/config` bytes are preserved; host files/configuration are absent.
A coordinated thread retains a writable descriptor across chmod sealing, mutates
the file after seal, and verifies rejection at final handoff. This demonstrates
both regression detection and the explicitly limited seal strength.

Existing canonicalization/permutation tests remain in force. No property-testing
framework was added. ArchCert's own test processes execute; fixture project
contents, scripts and executable source remain passive data.

## COMMANDS ACTUALLY EXECUTED

All final gates completed with exit code zero:

```bash
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
env RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps
cargo deny check
cargo test -p archcert-materialization --test materialization -- --test-threads=1
```

Focused development commands also executed included:

```bash
cargo check --workspace --all-targets --all-features
cargo test -p archcert-materialization --test materialization
cargo test -p archcert-materialization --lib
cargo test -p archcert-materialization -p archcert-cli
cargo test -p archcert-materialization -p archcert-application -p archcert-domain
```

## RESULTS

`cargo test --workspace` passed 65 tests with zero failures. The focused final
materialization integration command passed all 21 tests. Formatting, locked
compiler, strict Clippy and warning-denying rustdoc passed. `cargo deny check`
passed advisories, bans, licenses and sources, with the existing duplicate-version
warnings for syn and winnow. Baseline gates passed before edits; there were no
pre-existing failures to repair.

During development, compiler checks caught platform-specific mode widths and the
location of the Rustix umask API. Two new fixtures initially lacked the required
private-root mode; tests were corrected to provide mode 0700, without loosening
the runtime root check. Focused tests then passed. No failed attempt was treated
as a successful materialization.

## KNOWN LIMITATIONS

Unix-first adapter; local execution was on macOS, not every Unix filesystem or
Linux runtime. Roots must be explicitly configured absolute owned mode-0700
directories without symlink components, on a trusted local filesystem with no
ACL/mount behavior that weakens access control. Unsupported source/OS link
representations and unexpected filesystem semantics fail explicitly.

The seal is best-effort Unix permissions, not cryptographic immutability. Actual
runtime mounting/isolation is not implemented. Source handles are for trusted
sandbox setup only: directory FDs alone permit ancestor lookup and must not be
inherited directly into target execution. Authority diagnostic paths can become
stale after rename and must not be used to resolve runner input.

No production workspace persistence, secure deletion, crash recovery, durable
audit logging, wall-clock/I/O deadline, disk quota or global admission control
is implemented. A umask denying owner directory access can make creation fail
closed. Best-effort cleanup can leave an orphan and explicitly reports failure.

## UNRESOLVED RISKS

Same-UID/root writers, retained writable descriptors, a hostile kernel, privileged
mount changes and untrusted FUSE/network filesystem semantics are outside the
permission/descriptor boundary. Final verification narrows but cannot eliminate
the mutation window after handoff. Before target execution, the next runtime
must enforce an isolated read-only source view, close authority descriptors,
build a credential-free environment and verify source in that view.

The focused self-review inspected descriptor lookup/creation, symlink handling,
parent/root identity checks, exclusive writes, permission changes, bounded
traversal/sealing/deletion, errors/states, environment use, source-only capability
fields, post-verification mutation and panic/unsafe/subprocess paths. It tightened
incremental directory accounting, known-inode sealing, cleanup chmod scope and
partial-creation cleanup evidence. No new unsafe blocks, unwrap/expect calls,
shell materializer or runtime credential discovery were introduced. This review
does not replace independent security review/fuzzing or a formal race analysis.

## DEFERRED WORK

Target execution, Docker/gVisor/Firecracker, production Git transport, durable
source/workspace/audit stores, external-source resolution, policy evaluation,
signing, dashboards, release/deployment integrations and external AI services.

## NEXT RECOMMENDED MILESTONE

Milestone 3: trusted isolated runner setup consuming the existing narrow source
capability, with a read-only execution view, identity verification inside that
view, explicit credential/descriptor/environment exclusion, resource quotas and
network denial before any target code starts. Add operational orphan recovery
and independent review of ingestion/materialization before production exposure.
