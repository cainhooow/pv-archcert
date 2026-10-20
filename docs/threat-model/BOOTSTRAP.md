# Bootstrap Threat Model

The implemented Milestone 1 boundary is analyzed in [Git ingestion](GIT_INGESTION.md).
The Milestone 2 filesystem boundary is analyzed in [materialization](MATERIALIZATION.md).

## Primary assets

- production signing keys;
- published policy bundles;
- certificate integrity;
- source snapshot integrity;
- evidence integrity;
- project confidentiality;
- control-plane credentials;
- organization/project encryption keys.

## Initial threats

1. Malicious Git object graph or repository content.
2. Malicious package install/build/test script.
3. Runner attempting to reach the control plane or signer.
4. Git credentials leaking into target execution.
5. Policy downgrade requested by the target repository.
6. Fake evidence supplied by an implementing agent.
7. TOCTOU between source validation and execution.
8. TOCTOU between policy decision and signing.
9. Certificate payload mutation after approval.
10. Secrets copied into logs or future AI prompts.
11. AI prompt injection embedded in source code or documentation.
12. Compromised dependency or build tool.
13. Operator deleting or rewriting historical findings.
14. ArchCert accidentally treating `NOT_PROVEN` as `PASS`.

## Bootstrap security requirements

- Source snapshots are content-addressed and immutable after acceptance.
- Target-controlled code has no signer access.
- Target-controlled code has no control-plane database access.
- Execution network is denied by default after dependency acquisition.
- Production systems are never reachable from generic certification jobs.
- Mandatory authority policies cannot be disabled by `archcert.toml`.
- Logs and evidence are redacted before persistence.
- `NOT_PROVEN` and `INCONCLUSIVE` are first-class outcomes.

Milestone 3 adds the [hostile execution threat model](EXECUTION.md). Raw runner
output is hostile bounded bytes, not safely redacted text or certification policy.
Secret exclusion is implemented; broad redaction and durable signed evidence
remain deferred. Existing bootstrap requirements are design requirements, not
claims that all production infrastructure already exists.

Milestone 3.5 adds the [architecture alignment threat review](ARCHITECTURE_ALIGNMENT.md):
configuration escalation, transport authority, honest profiles/runtime observations,
truthful API state, contract drift and narrow source-export coupling.
