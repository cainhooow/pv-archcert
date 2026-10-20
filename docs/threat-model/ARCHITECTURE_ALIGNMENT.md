# Architecture alignment threats — Milestone 3.5

This extends source/materialization/execution threat models. It does not assert
independent certification. The same runtime/kernel/filesystem/operator trust
assumptions apply; no new network-facing execution endpoint is introduced.

| Threat | Correction and regression | Residual assumption/risk |
| --- | --- | --- |
| Project configuration attempts authority escalation | Strict private wire schema; distinct Project/Authority/RuntimeConfiguration types; no image/endpoint/network/limits/env/mount fields; escalation matrix rejects at every table boundary | A party controlling trusted operator CLI flags/code already has authority; no authentication/organization policy store yet |
| Transport DTO semantics influence application authority | Application owns command/result; protocol performs tested translation; Cargo dependency guard rejects reverse edge | Future authentication/request mapping still needs design before jobs exist |
| Profile name mistaken for installed toolchain/version | Version-suggesting node22 removed; python/rust/node identify executable families; toolchain NotObserved in evidence/observations; mismatched-image test produces no proven fact | Operator must approve actual image contents; no probes or image supply-chain attestation |
| Unsafe runtime configuration injection | No project deserialization path; explicit operator path/endpoint/private root; cleared client env/private empty configuration; rootless preflight before target | Replaced Docker binary, compromised daemon/operator, trusted temporary storage/filesystem remain in TCB; identity is observed only |
| Stale example configuration misleads operators | Full supported example parses in production parser under default CI; unknown fields/schema reject; config-check and run share parser/catalog | Future schema changes must update contract/docs/tests together; strict rejection is intentionally not backward fallback |
| Misleading API job state | Submission disabled with HTTP 501 UNAVAILABLE, no ID/PENDING/202; handler and mapping tests | API liveness does not imply readiness; durable jobs remain absent |
| Adapter coupling leaks privileges | Application VerifiedSourceExport port; runner production adapter dependency removed; descriptor/no-follow/final verification stays in materializer; returned bytes have no FDs/store/cleanup parent | Trait implementations are trusted code, not dynamically loaded/serialized project implementations; same-UID/root mutation/runtime compromise remains outside assumptions |
| Project removes/relabels mandatory checks | Mandatory steps are separate authority input, resolved first; collision rejects, no project provenance/removal field; immutable resolved plan | Trusted future inheritance/dispatcher must preserve required steps; current CLI default mandatory list is empty, not a certification policy |
| Evidence is misattributed/interpreted as policy success | Typed source/execution/step/kind/producer facts; command/profile/image/limit matching; TEST/BUILD labels and exits do not issue verdicts | Unsigned in-process evidence trusts producer; authenticated durable storage/signing/evidence canonicalization are deferred |
| Missing/malformed inspect fields hide failure | OOMKilled must be boolean before ordinary exit classification; regression covers missing/null/nonboolean | Runtime remains trusted and may lie; malformed data can cause operational failure, never establish toolchain/project proof |

No new unsafe Rust is introduced. The existing explicit panic injection is test-only
for unwind cleanup; hostile input paths use typed errors. Parser/runtime fuzzing,
independent review, global admission/storage controls and durable crash recovery
remain necessary. See [qualification](../runner/LINUX_QUALIFICATION.md) for deployment
checks and [TCB review](../architecture/TCB_AND_DEPENDENCIES.md) for dependencies.
