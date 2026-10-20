# Eldermark certificate and signing threat model

Scope: development issuance after trusted controller execution, canonical schema 1,
Ed25519 and pinned offline public-key verification. This is engineering self-validation,
not independent certification. Authority operator/controller/build/runtime/OS are trusted.
Targets, project configuration, output, and incoming certificate files are hostile.

| Threat | Security property | Mitigation | Remaining risk |
| --- | --- | --- | --- |
| Key theft | Only selected authority can sign | Explicit private owned directory/file, no-follow/single-link loading, mode 0600, no ambient discovery | Same-UID/root compromise, ACLs, snapshots, backups, swap and dumps; no HSM |
| Key leakage to sandbox | Target cannot obtain authority secret | No signer/key dependency in execution graph; source-only transfer, fixed environment, no host mounts; key loaded after execution and cleanup | Runtime/kernel/controller compromise defeats isolation |
| Secret diagnostic leakage | Key bytes absent from logs/errors | No signer Debug/Display/serialization/export; fixed errors, zeroizing buffers, canary tests; print public ID only | Memory disclosure or future adapter logging bugs; upstream audit incomplete |
| Wrong key use | Selected authority is exact | Signed digest-based key ID, signer ID check before sign, external public-key pin and envelope match | Incorrect administrative trust-anchor selection |
| Signature substitution | Signature authenticates this exact payload | Strict Ed25519 over canonical payload; cross-certificate/same-key/different-key tests | Authority key compromise |
| Field tampering | All meaningful displayed claims are authenticated | All authority fields inside payload, recompute digest AND verify signature; every-field tamper tests with rehashed digests | Bugs in future schema/display code |
| Canonical ambiguity | Same logical payload has one preimage | Typed bounded parser, duplicate/unknown rejection, sorted ASCII keys, safe integers, fixed vectors and feature tests | New schema governance and parser fuzzing still needed |
| Policy substitution | Certificate binds selected bundle | Exact ID/version/SHA-256 selection and re-evaluation, signed policy identity | Authority can intentionally select bad policy; CLI pins development bundle |
| Evidence substitution | Findings and payload references bind originals | Resolve exact ID+digest, canonical manifest and evaluation digests, re-evaluate consumed observations; signed finding IDs | Original controller provenance is trusted, no authenticated durable store |
| Source substitution | Scope is exact immutable source | Full commit/tree/ArchCert SHA-256 plus project/repository signed; compare accepted snapshot before preparation | Acquisition/runtime trust and source-schema limitations remain |
| Replay | Existing certificate cannot claim new source state | EXACT_SOURCE scope; time is signed audit data only | Reuse for same source is allowed; no freshness, revocation or expiry governance |
| Stale eligibility / mutation | Signed result is exact consumed evaluation | Recompute from original source/plan/policy/observations; consume evaluation; own canonical bytes without mutation API | Trusted controller may fabricate observations; historical JSON is not authority |
| Signing ineligible result | Gate must precede every signer call | Explicit eligibility requirement plus full integrity gate; zero-count tests for Bottle/inconclusive/ineligible | Trusted malicious caller could bypass orchestration and directly use a development signer |
| Signer compromise | Invalid output cannot create certification | Key ID check and immediate verification under pinned key before proof construction | Compromised actual selected key can sign lies; no production key governance |
| Development key misuse | Development assurance is explicit | Signed development classification, CLI labels, no production signer adapter | Users may administratively trust a development key despite warnings |
| Parser confusion | No permissive interpretation or resource ambiguity | 64 KiB envelope bound, fixed-depth strict objects, safe integer/length/identifier checks, no public Deserialize for envelope/proofs | General fuzzing and formal parser proof are deferred |
| Algorithm confusion / bypass | One reviewed verification algorithm | Signed exact Ed25519 metadata, verify_strict, weak-key rejection, no fallback/legacy/hazmat/batch | Upstream dependency/toolchain compromise |

The CLI additionally refuses certificate issuance after execution or cleanup failure.
A core issuance caller is responsible for supplying controller observations only after
untrusted execution ends. The core component never executes targets or accesses keys.
Development local custody shares the trusted controller's OS identity; this is not
an isolated hardware signer, independently attested authority, or production service.

Final review searches cover Debug/Display/errors/tracing/stdout/stderr/panic, key
read/write paths, signer dependencies, configuration selectors, gate ordering,
canonical signing bytes, immutable draft ownership, algorithm fallback and verified
proof construction. See MILESTONE_4B_REPORT.md for commands, results and residual risks.
