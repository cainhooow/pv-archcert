# Milestone 4A baseline

Recorded 2026-10-19 (America/Sao_Paulo), before implementation. Engineering
self-validation only. No certificate or independent assessment.

Reviewed MILESTONE_3_5_REPORT.md, CURRENT_ARCHITECTURE_SNAPSHOT.md, ADRs
0001–0021, ValidationPlan/ValidatedExecutionStep and ValidationObservation,
domain source/execution/property/lifecycle types, policy/evidence/crypto
scaffolds, CLI result vocabulary and configuration/execution path, architecture
guard and opt-in live script. The supplied directory has no Git metadata.

The active flow is accepted immutable source → authority-resolved plan →
verified materialization → rootless OCI → typed observations. HTTP submission
remains 501 UNAVAILABLE. Project requests are separate from authority/runtime
configuration. There is no active policy evaluation or signing.

The unused policy scaffold is unsuitable: it accepts EvidenceRecord values
already containing verdicts and returns CertificationStatus, permitting a
premature certification abstraction. Replace it, remove its evidence dependency,
and activate policy only as an inward application/domain consumer. The generic
evidence and crypto scaffolds must remain outside the active execution graph.

Observation conversion checks command/profile/image/limits, but observations
lack an explicit whole-plan identity/schema/profile binding and the evaluator
needs an independently supplied expected execution set. Add these bindings
without importing Docker or filesystem details into policy. Source completeness
must come from existing immutable snapshot status, not duplicated source parsing.

All default baseline gates passed, exit 0:

```text
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo deny check
./scripts/check-architecture
```

Logs: target/m4a/baseline-{0..6}.log. Existing dependency duplicate warnings
remain; no gate was weakened. Default tests retain eleven ignored live groups.
`/opt/local/bin/colima list` reports both default and archcert-m3 Stopped.
No live runtime is readily available at baseline; policy work is not delayed
to start it. Live execution may be provisioned after implementation.

Implementation direction: bounded strict declarative authority TOML, immutable
canonical policy identity, five property verdicts, explicit applicability,
stable findings and fail-closed unsigned eligibility. No API expansion,
database, LLM, certificate format, key loading, signer calls or waiver system.
