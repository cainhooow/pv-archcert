# ADR-0024: Eligibility precedes certificate construction and signing

Status: Accepted for Milestone 4A.

`PolicyEvaluation` records source identity, exact plan SHA-256, bundle ID/version/
SHA-256, canonical property evaluations, structured findings, blocking finding
IDs, evaluator version and an explicit audit timestamp. It cannot contain a
certificate or signature. No signing implementation, key loading or signer call
is activated. No HTTP endpoint or persistence service is added.

| Eligibility | Meaning |
| --- | --- |
| ELIGIBLE_FOR_CERTIFICATION | All blocking requirements satisfied; future certificate construction/signing still required |
| NOT_ELIGIBLE | At least one definite blocker: FAILED, NOT_PROVEN or disallowed NOT_APPLICABLE |
| INCONCLUSIVE | Blockers exist and all are INCONCLUSIVE |

A definite blocker dominates an inconclusive blocker across properties. This
preserves both uncertainty and the reason a certificate cannot currently issue.
Every property retains its own verdict even when the aggregate is NOT_ELIGIBLE.
Missing required evidence is always a blocker, never a waiver.

Required evidence uses typed selectors (step/fact/expected execution, snapshot or
nonempty-plan requirement). Actual references hold observation ID plus SHA-256 of
compact key-sorted typed observation JSON, or an immutable snapshot reference.
Different payloads sharing an observation ID remain separately referencable.
Execution payloads/stdout are never duplicated in property results. A future
retained evidence bundle must resolve every reference and authenticate provenance.

A finding has property, severity, verdict status, reason code, references and a
blocking flag. Its correlation ID is SHA-256 of compact key-sorted JSON containing
schema=1, full source identity, exact plan digest, full policy reference, property,
verdict and stable reason code. Prose, audit timestamp and per-run execution UUIDs
are excluded so the same failure can correlate across reruns of the same inputs.
Actual evidence references retain the exact execution identities. Findings are
created only by the evaluator; target processes have no finding interface.

Plan identity hashes compact key-sorted JSON containing schema=1,
kind=ARCHCERT_VALIDATION_PLAN and the entire immutable serialized plan, including
execution order, commands, argv/cwd, resolved image/programs/limits, categories
and authority/project provenance. Observations now bind this digest and profile
with explicit schema=1. This strengthens M3.5 observations; historical unbound
reports are not silently upgraded/reinterpreted as schema-1 policy evidence.

Evaluation is a pure function of explicit inputs. Time is an explicit audit
argument; no decision, digest, finding ID or ordering reads a clock/randomness.
The CLI supplies the current time only after execution. CLI `evaluate` uses the
same source→plan→sandbox flow as `run` and emits JSON headed UNSIGNED POLICY
EVALUATION, NOT A CERTIFICATE and certificate=NOT ISSUED. Exit 0 means the
execution/cleanup and evaluation operation completed, not policy eligibility.
A nonzero execution can still emit a complete FAILED evaluation before exit 1.
The JSON eligibility field is the policy result.

M4B must separately authenticate policy/evidence authority, resolve retained
payloads, construct/version a certificate, and sign successfully before any
CERTIFIED result. Eligibility alone must never invoke an implicit signer.
