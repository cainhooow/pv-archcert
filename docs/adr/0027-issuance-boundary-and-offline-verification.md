# ADR-0027: Proof-backed CERTIFIED transition and pinned offline trust

Status: Accepted for M4B — Eldermark. Extends ADRs 0010–0011 and 0024.

archcert-certificate composes policy/application/domain/evidence and the crypto
port. Application/domain do not depend on it; policy remains independent of signing.
Evidence consumes typed policy results without acquiring a signer. Crypto imports
no other workspace crate. The dependency guard rejects signing authority anywhere
in runner/source/materialization/application/policy/daemon dependency graphs and
checks execution interfaces for signing types. The CLI is trusted composition.

CertificateSigner exposes only stable key_id and sign(message) returning a typed
detached signature/failure. It knows no source, runner, path, environment, KMS or
project configuration. Adapter-specific custody lives outside certificate logic.
ProjectConfiguration rejects signer, key/path, algorithm and authority selectors.

The issuer requires a supplied schema-1 evaluation with exactly
ELIGIBLE_FOR_CERTIFICATION. Missing, NOT_ELIGIBLE, INCONCLUSIVE or unknown-version
results fail before signer invocation. It checks accepted source, immutable plan,
and separately selected immutable policy identities; resolves evidence/finding
references; and recomputes the evaluation from original trusted controller inputs.
Any edited eligibility, result, finding or stale evidence binding rejects. These
inputs are capabilities of the trusted controller, not authenticated arbitrary JSON.
A project cannot submit an evaluation or request an issuance capability directly.

Preparation consumes the evaluation and returns an owned CertificateDraft containing
only frozen canonical payload, manifest and selected public key. There are no
borrowed mutable signing inputs, callbacks into a runner or post-gate payload setters.
Later changes to caller-owned observations cannot alter the draft. A different
certificate requires a new preparation/gate. No ambient clock or randomness is read
by the core pipeline; metadata is explicit.

The CLI completes all target execution and both sandbox/source cleanup before
preparation, and additionally rejects any execution/cleanup failure. Only after
the complete preparation gate does it load the explicitly selected development
private key. It checks signer identity, signs exact canonical bytes, then invokes
the same offline verification API used by the independent verify command.

Only successful verification constructs IssuedCertificate/VerifiedCertificate,
whose fields are private and which have no Deserialize implementations. Their
report emits CERTIFIED. An attempted signature, signature bytes, JSON file or policy
success cannot construct them. The unused, deserializable historical generic domain
Certified variant was removed; no unbacked lifecycle transition remains there.
Failures retain distinct typed errors, never a successful certification status.

Offline verification parses bounded strict schema, validates constants/structural
invariants, rebuilds canonical bytes, recomputes and compares SHA-256, checks exact
selected public key plus signed key ID, and verifies strict Ed25519. No Git,
workspace, Docker, network, database or signing private key is required. A verifier
caller must explicitly supply a trusted public key. Embedded material is convenient
transport, never a trust anchor or a fallback. The CLI requires --public-key.

Verification authenticates the signed ArchCert statement under that key. It does
not re-execute engineering checks, retrieve evidence, decide whether an authority
should be trusted, attest runtime binaries, or establish universal software security.
A verifier reports exact source/policy/certifier identities, valid signature and
structure, DEVELOPMENT CERTIFICATE / NOT PRODUCTION AUTHORITY, no expiry semantics
and revocation NOT IMPLEMENTED. Trust-anchor distribution remains administrative.
