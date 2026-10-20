# ADR-0025: Schema-1 canonical certificates and evidence manifests

Status: Accepted for M4B — Eldermark. Extends ADRs 0006, 0023 and 0024.

The certificate is a small signed authority statement. Detailed observations,
execution records and bounded log excerpts remain in a separate evidence bundle.
The certificate binds that bundle's deterministic manifest by SHA-256. It never
contains private material or raw logs.

## Signed schema

The schema-1 payload contains: schema, domain kind ARCHCERT_CERTIFICATE,
DEVELOPMENT ONLY / NOT PRODUCTION AUTHORITY classification, EXACT_SOURCE scope,
authority project UUID and repository ID, exact Git commit/tree/source SHA-256,
policy ID/version/SHA-256, plan SHA-256, semantic evaluation SHA-256, evidence
manifest SHA-256, sorted finding IDs, ArchCert/evaluator versions, certifier,
runner producer, isolation level, positive issued_at Unix seconds, explicit
expiration/revocation limitations, Ed25519 algorithm and signing key ID.
Every authority-relevant displayed field is inside this signed payload.

The envelope has only payload, certificate_sha256, detached signature (128
lowercase hex digits), and raw public key (64 lowercase hex digits). The last
three are derived verification material: changing the digest fails recomputation;
changing key material fails the signed key-ID and external trust checks; changing
the signature fails verification. There are no unsigned descriptive claims.

The certificate ID is its computed certificate_sha256. It is deliberately not
inside its own hash preimage. Digest and signature are different values and types.
The signature authenticates the complete canonical payload, not its hexadecimal
SHA-256, JSON wrapper, pretty presentation or terminal output.

## Canonical algorithm

Schema 1 uses the restricted applicable JSON rules from
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785). This is not a general JCS library.

1. Parse into fixed typed objects; reject duplicate and unknown fields at every
   depth. Validate schema, exact constant spellings, identifiers, lengths, bounds
   and lowercase hex before use. CertificateEnvelope has no Deserialize API;
   its only parser reads at most 65,536 bytes plus one sentinel before decoding.
2. Object keys are fixed ASCII. Recursively sort every object's keys in ASCII
   order explicitly, including under serde_json/preserve_order feature unification.
3. Strings preserve Unicode scalar contents without normalization. Emit compact
   UTF-8 JSON using deterministic JSON string escaping, lowercase control escapes,
   unchanged Unicode, no insignificant whitespace, BOM or terminal newline.
4. Arrays preserve schema-defined order. Finding IDs are sorted strictly and
   duplicates reject. Manifest observations sort/deduplicate by full payload digest;
   finding references sort by ID. Detailed execution records sort by digest. Evaluation property/actual-reference ordering
   comes from the deterministic M4A evaluator.
5. Only booleans, null, strings, arrays, objects and integers between
   -9,007,199,254,740,991 and 9,007,199,254,740,991 are allowed. No floats or
   host-native representations exist in signed fields. issued_at is positive.
6. Hash exactly these canonical bytes with SHA-256. Sign exactly these same bytes.

Object insertion order, filesystem enumeration, OS, locale and pretty-printing do
not enter this algorithm. Ordinary serde_json serialization without explicit
normalization is not the signing format. Tests include exact bytes/digest,
permutations, Unicode escaping, range rejection and independent OpenSSL signatures.
The fixed format vector is in crates/archcert-certificate/tests/fixtures; it is
synthetic conformance data, not an engineering assessment of its placeholder source.

## Evidence and evaluation identities

Evaluation schema 1 is explicit in M4B. Its identity is SHA-256 of canonical
{schema:1, kind:ARCHCERT_POLICY_EVALUATION, evaluation:<complete evaluation except
 evaluated_at>}. The evaluator version, all property results, findings, blocking
findings, eligibility and exact identities are included. Unknown evaluation schema
or evaluator version rejects. Old unsigned reports cannot be deserialized into an
accepted source/plan/issuance capability.

The manifest contains schema/kind, full source/policy/plan identity, semantic
evaluation SHA-256, sorted typed observation IDs with canonical complete-payload
digests, and sorted finding IDs with full finding digests. Every actual reference
in properties/findings must resolve by both content digest and typed identity.
Source-snapshot references must match exactly. Duplicate identical observations
are idempotent; missing/foreign references reject. The certificate's finding IDs
are also signed directly. Issuance manifests additionally bind the canonical detailed
EvidenceBundle SHA-256. The bundle retains complete consumed observations/findings
and detailed controller execution records, including bounded log prefixes and runtime
audit data; no payload is duplicated into the certificate. Records must reproduce
exactly the consumed observation set against the original plan/execution bindings.
Schema 1 caps each retained execution stream prefix at 65,536 bytes for issuance.
Diagnostic evidence.json is separate presentation; evidence-bundle.json is the
canonical, digest-bound detailed artifact.

issued_at distinguishes certificate instances, not source or engineering evidence.
With fixed issuance metadata the same inputs produce the same bytes/digest and
Ed25519 signature. A changed issuance time creates a new certificate instance;
it does not change semantic evaluation or manifest identity. Audit evaluated_at
is excluded from these semantic identities because M4A defines it as non-decisional.
Execution UUIDs remain in detailed evidence references and distinguish reruns.

## Scope and governance

EXACT_SOURCE means the signed project/repository plus exact immutable commit,
tree and ArchCert SHA-256. It cannot mean main, latest, a working directory,
future commit, release, artifact or deployment. No release permit is created.
NO EXPIRATION SEMANTICS YET. Revocation is NOT IMPLEMENTED. No timestamp is
interpreted as an expiry or freshness guarantee. Future algorithms, schemas,
expiration or revocation policy require explicit reviewed version upgrades.
