# Initial Development Plan

## Current milestone scope

The broad bootstrap sequence below is historical planning with its original
numbering. Actual implementation is recorded by the Milestone 1–3 and 3.5 reports:
immutable ingestion, verified materialization, then isolated hostile execution.
Milestone 3 produces execution evidence only. Milestone 3.5 adds structural validation plans and observations. Durable jobs,
policy evaluation and signing remain future work. Execution decisions are ADRs 0011–0018, refined by ADRs 0019–0021.
The next milestone is Milestone 4 policy evaluation against observations. The old
numbering below is historical planning, not current scope or completed features.

## Milestone 0 — Engineering baseline

Exit criteria:

- exact Rust toolchain pinned;
- workspace builds with `--locked`;
- formatting, Clippy, tests and rustdoc gates are green;
- `cargo-deny` policy is active;
- architecture and threat-model documents are reviewed;
- CI contains no production signing secret.

## Milestone 1 — Immutable source identity

The first development slice implements local loose-object ingestion and owned
in-memory snapshots. Push authentication, a production bare-object gateway and
durable quarantine namespaces remain deferred under ADR-0005. The user-approved
Milestone 1 source-state boundary does not require a production transport server.

Implement:

- Git bare object store;
- push authentication;
- quarantine namespace;
- commit/tree validation;
- normalized source manifest;
- ArchCert SHA-256 snapshot digest;
- source snapshot immutability;
- audit events.

Exit criteria:

Given one pushed commit, ArchCert can independently report and later reproduce the same commit id, tree id and source-manifest digest without using the developer working directory.

## Milestone 2 — Certification job + Docker rootless runner

Implement:

- PostgreSQL job persistence;
- job state machine;
- source materializer;
- ephemeral rootless container runner;
- read-only source mount where possible;
- CPU/memory/PID/time limits;
- deny network during test execution;
- no control-plane or signer credentials in runner;
- structured redacted stdout/stderr evidence.

Exit criteria:

A deliberately malicious fixture repository cannot read ArchCert secrets or reach forbidden control-plane endpoints, and a normal fixture can execute configured authority-approved commands.

## Milestone 3 — Deterministic policy engine

Implement:

- immutable/versioned policy bundles;
- required checks;
- `PROVEN`, `FAILED`, `NOT_PROVEN`, `NOT_APPLICABLE`, `INCONCLUSIVE`;
- policy-to-final-status mapping;
- authority-over-project precedence;
- evidence manifest hashing.

Exit criteria:

A target repository cannot disable a mandatory failing policy through its own configuration.

## Milestone 4 — Certificate genesis

Implement only after a cryptography ADR is approved:

- canonical certificate schema v1;
- canonicalization;
- detached signature;
- isolated development signer first;
- offline verifier;
- certificate binds source, policy, runner identity and evidence manifest.

Exit criteria:

Any mutation to the certificate, evidence manifest reference, source identity or policy identity invalidates verification or changes the signed payload.

## Milestone 5 — Git/CLI vertical slice

Target UX:

```bash
git remote add archcert ssh://git@archcert.local/org/project.git
git push archcert HEAD
archcert submit HEAD --profile standard
archcert status <id>
archcert evidence <id>
archcert verify certificate.json certificate.sig
```

`archcert submit` may wrap source synchronization plus the API request, but Git remains a first-class ingest protocol.

## Deferred until the trust core works

- Web Panel;
- semantic AI reviewer;
- knowledge graph;
- agent claims vs ArchCert evidence UI;
- challenge-test generation;
- gVisor/Firecracker backends;
- client/server envelope encryption hierarchy;
- organization RBAC;
- external AI providers;
- release permits and deployment gate;
- private transparency/Merkle log.

These are planned, not discarded. They are deferred so that the root of trust exists before intelligence and UX are layered on top.

## Milestone 3 implementation update

Rootless OCI execution now has domain/application ports, descriptor source export,
stopped-container source reconstruction, authority image/argv/environment policy,
network denial, resource/time/output enforcement, controller evidence and explicit
sandbox cleanup. See the Milestone 3 report for test results and deployment limits.
Milestone 3.5 now provides transport-independent resolved plans and observations.
Milestone 4 should evaluate authority policy against those facts; issuance/signing
requires separate design and authorization. Independent review, fuzzing, durable storage, recovery and production
Linux runner operations remain necessary; engineering self-validation is not
independent certification.
