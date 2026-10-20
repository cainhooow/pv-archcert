# Milestone 2 baseline and pre-implementation boundary review

On October 19, 2026, reviewed all architecture documents, ADRs 0001–0007,
Milestone 1 reports, source domain/application/adapters and existing tests before
changing materialization code. The supplied workspace still has no Git metadata.

All six baseline commands completed with exit code zero:

```bash
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo deny check
```

Tests: 36 passed. Deny retained duplicate-version warnings for syn and winnow.
No pre-existing gate failure was observed.

## Review findings before implementation

- `SourceStore` exposes retention but no authority-scoped retrieval. Add lookup
  by project, repository and full source identity; reverify returned identity.
- `SourceMaterializer` has an unconstrained associated result and no enforceable
  verification/seal state. Refine it to return structured evidence and a narrow
  handoff capability. Keep workspace cleanup authority out of runner input.
- Immutable snapshot fields and owned payloads are suitable input. Verify again
  against the caller's expected digest before filesystem operations. Never accept
  a deserialized report in place of the snapshot.
- NFC UTF-8 paths are an explicit supported subset, not proof of host filesystem
  equivalence. Revalidate names, use exclusive no-follow creation, then enumerate
  actual names without lossy conversion. Reject round-trip differences.
- Mode mapping must preserve only supported executable semantics while applying
  exact private Unix permissions independent of ordinary umask differences.
- Symlink blobs can contain targets unsupported by an OS (empty/NUL/too long).
  Return an explicit unsupported-feature/creation failure; never rewrite them.
- External-source detection remains the documented supported LFS prefix/grammar.
  Unresolved LFS and gitlinks must fail before destination creation.
- Canonical schema 1 excludes directories. The filesystem verifier must separately
  reject extra empty directories and compare the required directory set.
- Source limits bound ingestion, not disk writes or filesystem traversal. Reuse
  their file/byte/depth budgets and add directory/symlink budgets.
- Ordinary read-only permissions cannot freeze source against the owner/root.
  Reverify at handoff, document the same-UID/privileged-writer exclusion, and
  require a future isolated read-only mount before any untrusted execution.

No reproducible Milestone 1 ingestion defect was identified in this initial
review. These are required extensions and explicit residual assumptions, not
claims that passing Milestone 1 tests proves its implementation correct.
