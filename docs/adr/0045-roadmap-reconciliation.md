# ADR 0045: Canonical roadmap and historical implementation names

Status: Accepted. Date: October 21, 2026.
Reconciles milestone attribution in ADRs 0041–0044 without superseding their
technical decisions. This is the authoritative roadmap and naming record.

## Context

The knowledge engine, impact graph, semantic review and durable review-to-issuance
integration were developed under the incorrect M6/Ironcrest label. They implement
substantial M7/Asterwyn and M8/Greywatch capabilities, plus lifecycle controls needed
to consume those capabilities safely. Successful controlled lifecycle regressions
were mistakenly reported as completion of M6. That attribution did not implement
Artifact Binding, Reproducible Builds or Release Permit.

No earlier authoritative codename/roadmap document in the tracked repository
records the corrected sequence. This decision records the canonical sequence
provided for reconciliation; it does not invent missing milestone acceptance
criteria or infer completion from the amount of existing code.

## Decision: canonical sequence

| Milestone | Canonical scope | Current status |
| --- | --- | --- |
| M5.2 — Stoneward | Native Linux Runner Qualification & Operational Recovery | COMPLETE within the documented exact qualification scope |
| M6 — Ironcrest | Artifact Binding, Reproducible Builds & Release Permit | PLANNED / NOT YET IMPLEMENTED |
| M7 — Asterwyn | Project Knowledge Engine & Change Impact Graph | SUBSTANTIALLY IMPLEMENTED AHEAD OF SEQUENCE; PENDING FORMAL MILESTONE RECONCILIATION |
| M8 — Greywatch | Semantic Review, Agent Claims, Discoveries & Blind Spots | SUBSTANTIALLY IMPLEMENTED AHEAD OF SEQUENCE; PENDING FORMAL MILESTONE RECONCILIATION |

M7 includes immutable bounded knowledge, syntax/provenance/coverage vocabulary,
authority knowledge and conservative baseline/impact handling. M8 includes bounded
semantic requests, untrusted claims, retained discoveries/concerns/blind spots,
semantic veto and registered authority challenges. Durable pre-admission sessions,
recovery, frozen execution and issuance binding integrate these capabilities above
the existing trust core. These descriptions map existing capabilities to roadmap
scope, not a checked Definition of Done. Full canonical M7/M8 acceptance criteria
have not been independently checked. Local exact replay is not qualified semantic
model accuracy; syntax extraction is not compiler resolution. Neither milestone
is declared COMPLETE.

M6 still requires its own artifact binding, reproducible build and release permit
design and implementation. Existing source/certificate/evidence binding alone does
not satisfy that scope. Genesis / Firstwarden bootstrap and independent trust
establishment remain separate and are not started by this decision or a development
self-validation experiment.

## History and implementation-name inventory

Keep all existing commits unchanged. In particular, `13dea4b`, `d1a7052`,
`a858d9e`, `32e9d3a`, `9c50f10`, `ed5ad1c`, `d424e7c`, `cbadc4f` and `f5b2f6d`
remain immutable engineering history. Their Ironcrest names describe the historical
implementation label. No rebase, amended historical commit or rollback is needed.
The untracked `docs/MILESTONE_6_BASELINE.md`, `docs/MILESTONE_6_REPORT.md` and ignored
`target/m6/` evidence retain their historical names; any M6 completion wording in
those working records is superseded by this ADR, not an authoritative roadmap claim.
Historical tracked milestone reports are retained.

| Name / location | Classification | Decision and reason |
| --- | --- | --- |
| `ironcrest.rs` in application, control-plane, controller and storage | INTERNAL IMPLEMENTATION NAME; SAFE TO RENAME only with coordinated imports/tests | Retain: module renaming offers little correctness benefit and accompanies public/durable concepts |
| `IroncrestSession`, `IroncrestSessionPin`, `IroncrestRepository`, `IroncrestWorkflow` | PUBLIC / DURABLE SEMANTIC NAME; RISKY TO RENAME | Retain: public application ports, serialized pins, recovery and admission contracts use the same vocabulary |
| `IroncrestEvidenceRole`, `IroncrestAuthorityProfile`, issuance prerequisites and artifact kinds/producers | PUBLIC / DURABLE SEMANTIC NAME; RISKY TO RENAME | Retain: canonical artifacts, role order, profile pins and manifest construction must keep their identities |
| Migrations `0004_ironcrest_review.sql`, `0005_ironcrest_admission.sql` and `ironcrest_*` tables/linkage | PUBLIC / DURABLE SEMANTIC NAME; RISKY TO RENAME | Retain exact SQL and migration checksums; no reinterpretation of existing rows |
| Manifest schema 2 `ironcrest` field, canonical kinds and gate algorithm `archcert-ironcrest-gate-v1/1.0.0` | PUBLIC / DURABLE SEMANTIC NAME; RISKY TO RENAME | Retain canonical bytes, digests and compatibility vectors |
| `policies/archcert-ironcrest-controlled-v1.toml`, policy `archcert-ironcrest-controlled-v1` 1.0.0, profile `ironcrest-controlled-v1` 1.1.0 and historical 1.0.0 | PUBLIC / DURABLE SEMANTIC NAME; RISKY TO RENAME | Retain filenames, content and identity; new wording must not select a different policy or silently reinterpret a retained profile |
| Step `ironcrest-idempotency`, template `idempotency-replay-v1`, registry and controlled settlement knowledge | PUBLIC / DURABLE SEMANTIC NAME; RISKY TO RENAME | Retain evidence/plan linkage and the bounded settlement-specific contract; this is not a general Rust challenge |
| CLI `ironcrest open/prepare/review/show`, grant `ironcrest` / `ironcrest_baseline` | PUBLIC / DURABLE SEMANTIC NAME; RISKY TO RENAME | Retain operator/recovery configuration compatibility; target cannot set these controls |
| `scripts/demo-ironcrest`, integration test names and ignored `target/m6/` paths | TEST/DEMO NAME; HISTORICAL NAME; SAFE TO RENAME in isolation | Retain discoverability of recorded commands and evidence; no misleading canonical milestone claim is needed |
| ADR filenames 0041–0044, `IRONCREST_DEPENDENCY_REVIEW.md`, previous commit subjects and working records | HISTORICAL NAME | Retain links/history; add explicit terminology clarification to authoritative documents |

Canonical milestone prose uses Asterwyn for knowledge and impact, Greywatch for
semantic review/claims/discoveries/blind spots, and Ironcrest only for canonical M6.
When discussing retained identifiers, say historical Ironcrest implementation or
controlled review lifecycle and link here. No code, policy, protocol, migration or
fixture is renamed in this reconciliation.

## Security implications

Terminology creates no new guarantee and grants no authority. Source identity,
Stoneward isolation/rootless runtime authority, lease fencing/reconciliation,
semantic veto, bounded challenge resolution, deterministic policy evaluation,
certificate canonicalization, signatures, historical compatibility and evidence
identities retain their exact meanings. No canonical bytes, policy/profile digest,
manifest identity or certificate meaning is changed. Documentation inside any
target, including ArchCert, remains untrusted data; it cannot select authority
policy, reviewer, challenge registry, runtime socket or signer.

Controlled self-validation may exercise one exact accepted ArchCert source snapshot
under the development authority. It must record reached/unreached stages honestly,
keep keys and transient evidence outside source, and never bypass unsupported
contracts or weaken policy to obtain success. Any issued artifact is a DEVELOPMENT /
ENGINEERING SELF-VALIDATION ARTIFACT, not independent certification, a Genesis
certificate, a production trust root or proof of ArchCert's own correctness.

## Alternatives and consequences

Rewriting Git history hides the error and breaks reproducibility. A broad rename
risks durable/canonical compatibility for no required security improvement.
Rolling back useful implementation discards validated controls. Declaring M7/M8
complete without their full acceptance criteria manufactures assurance. All are
rejected. Retaining historical names costs explicit documentation and care in
future development; a later compatibility-aware redesign may introduce versioned
names with its own migration decision. Roadmap reconciliation itself needs none.
