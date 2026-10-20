# Milestone 3 baseline and trust-chain review

Reviewed October 19, 2026 before implementation: ADRs 0001–0010, Milestone 1–2
baselines/reports, all existing threat models, source domain/application/loose
reader/store, materialization domain/application/Unix adapter, RunnerInput,
cleanup leases, CLI and existing CI. Workspace has no Git metadata.

All baseline gates passed (Rust 1.99.1, cargo-deny 0.20.2):

- `cargo fmt --check`
- `cargo check --workspace --all-targets --all-features --locked`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace` — 65 passed, zero failed/ignored.
- `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps`
- `cargo deny check` — all checks passed, existing syn/winnow duplicate warnings.

## Review findings

Owned snapshots reconstruct canonical source and external-source evidence;
application/store scope checks bind project/repository/full identity. Loose
objects are bounded, independently hashed and parsed without executing Git.
Materialization uses exclusive descriptor-relative writes, checks inode/device,
names/modes/content/directory sets, verifies across sealing and handoff, and
keeps cleanup parent/store authority outside the source capability.

No reproduced historical ingestion/materialization defect was found. Existing
permission sealing is deliberately insufficient against owner/root or retained
write descriptors. Reusing diagnostic workspace paths in an OCI adapter would
introduce a new substitution defect: paths may be stale after rename and do not
carry the existing descriptor guarantee. Source capability must gain a bounded
reverified byte export, and the actual isolated source view must be reconstructed
before any target starts. Regression tests must cover post-handoff mutation,
rename anchoring, and rejected export after cleanup.

Directory descriptors must remain CLOEXEC and must never be inherited by target
code. Symlink targets are source bytes, not host paths. Read-only source does not
make target output authoritative. Source lease destruction remains a control-plane
operation; sandbox/image cleanup belongs to the execution adapter.

## Environment observed

macOS Darwin 25.6.0 x86_64. Docker CLI 29.8.1 exists; configured Colima socket is
absent and `docker version` cannot connect. Colima default profile is stopped.
No running OCI backend/rootless/cgroup guarantees were established by this probe.
Runtime tests must explicitly report unavailable prerequisites, never equate a
mock or macOS VM with tested production Linux isolation.
