# Milestone 3.5 baseline

Review completed before code edits on 2026-10-19. This workspace has no Git metadata
or applicable AGENTS.md. Original files were copied to ignored target/m35-review.

Read the complete repository architecture document, ADRs 0001–0018, M1–M3 reports,
all twelve workspace manifests, CLI/daemon, application/domain contracts, strict
CLI configuration parser/example, materialized descriptor export, runner archive,
process/control and stopped-container verification paths, and CI configuration.
No separately named Current Architecture Snapshot exists in this workspace; the
repository ARCHITECTURE.md and the supplied milestone findings are the available
baseline. A request for any separate snapshot was sent to the user.

Observed defects: application imports protocol DTOs; bootstrap returns HTTP 202,
a generated ID and PENDING without persistence; example uses unsupported environment,
toolchains, commands and network tables; CLI run help describes config validation;
run bypasses project configuration; profile node22 implies unobserved version;
runner production dependency owns the concrete materialization contract. Generic
evidence/policy/crypto scaffolds are already absent from active execution links.

All existing gates executed and passed, before changes:

- cargo fmt --check
- cargo check --workspace --all-targets --all-features --locked
- cargo clippy --workspace --all-targets --all-features -- -D warnings
- cargo test --workspace (87 passed, 11 explicitly ignored live OCI tests)
- RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
- cargo deny check (all checks pass, existing syn/winnow duplicate warnings)

Host: Darwin 25.6.0 x86_64; Rust toolchain pinned at 1.99.1. Docker and Colima
exist at /opt/local/bin; default and dedicated archcert-m3 VMs are stopped.
The prior explicit Unix socket exists but does not establish daemon availability.
Native Linux: NOT YET QUALIFIED. No live test result inferred from default tests.
