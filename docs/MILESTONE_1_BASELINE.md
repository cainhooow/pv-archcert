# Milestone 1 baseline

Inspected on October 19, 2026, before implementation: all workspace sources,
manifests, architecture documentation, ADRs, threat model, configuration, and CI.
The supplied directory has no `.git` metadata; changes cannot be compared with
a Git index and no commit is created.

Observed commands with Rust 1.99.1:

| Command | Result |
| --- | --- |
| `cargo fmt --check` | Failed: existing formatting in both application binaries. |
| `cargo check --workspace --all-targets --all-features --locked` | Passed. |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed. |
| `cargo test --workspace` | Passed: three domain unit tests. |
| `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` | Passed. |
| `cargo deny check` | Failed: cargo-deny was not installed. |

## Minimal design corrections

The bootstrap source trait lives in the infrastructure crate. New ingestion and
materialization ports belong in the application crate, preserving dependency
inversion; the old unused trait is superseded by these ports. No certification
job or signing behavior is added.

The bootstrap Git ID and SHA-256 wrappers derived unchecked deserialization.
Deserialization must invoke their validating constructors so API input cannot
bypass invariants. Snapshot records must not be constructible by deserializing
an implementer's claimed evidence.

ADR-0002 remains accepted. Its production transport is deferred: Milestone 1
implements bounded local loose-object reception rather than push authentication
or an SSH/HTTP server. Unsupported storage fails explicitly. This is a
development adapter, not production Git protocol support.

After installing cargo-deny 0.20.2, its first run exposed a further bootstrap
configuration gap: no dependency licenses were allowed, and private workspace
crates have no declared license. The policy now explicitly allows only the four
license identifiers needed by the locked dependencies (MIT, Apache-2.0,
BSD-3-Clause and Unicode-3.0). Existing `publish=false` workspace crates are
excluded from license inference; no ArchCert license is invented. All third-party
dependencies remain checked. No advisory or source check is disabled.

The next deny run also exposed pre-existing unversioned workspace path
dependencies conflicting with `bans.wildcards = "deny"`. All workspace path
dependencies now specify exact version `=0.1.0`; the deny rule remains enabled.
