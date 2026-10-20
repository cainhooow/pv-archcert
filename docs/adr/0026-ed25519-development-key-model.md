# ADR-0026: Ed25519 and explicit development key custody

Status: Accepted for M4B — Eldermark.

Use maintained ed25519-dalek 3.0.0, pinned exactly, with its default fast and
zeroize features. Use strict Ed25519 verification and reject weak public keys.
No Ed25519ph, batch, legacy compatibility, hazmat or fallback behavior is enabled.
The [upstream documentation](https://docs.rs/crate/ed25519-dalek/3.0.0) documents
key zeroization, misuse protections and strict verification; the maintained
[Dalek repository](https://github.com/dalek-cryptography/curve25519-dalek) contains
the current implementation. See the detailed dependency review for resolved
transitives, unsafe footprint, maintenance evidence and dependency-gate results.

ArchCert implements no arithmetic, hash primitive, entropy source or key encoding.
SHA-256 uses existing RustCrypto sha2. getrandom 0.4.3 supplies OS cryptographic
randomness for a zeroizing 32-byte generation seed. Dalek creates the key and
RustCrypto PKCS#8 encodes/decodes private DER. Key ID is lowercase SHA-256 of the
canonical 32 raw Ed25519 public-key bytes; filenames have no identity authority.
Public keys/signatures use fixed-length lowercase hex in the certificate envelope.
The Ed25519 algorithm is also signed to prevent algorithm confusion.

LocalDevelopmentSigner is **DEVELOPMENT ONLY / NOT PRODUCTION KEY MANAGEMENT**.
It is feature-gated and Unix-only. No production HSM/KMS/PKCS#11 assurance, rotation
policy, custody governance, encrypted-at-rest storage or memory locking is claimed.
PKCS#11, KMS and HSM adapters can implement the same narrow signer port later.

Generation requires an explicit owned mode-private authority directory, exclusive
no-follow mode-0600 file creation and OS randomness. Existing keys are never
replaced. Loading requires a regular, owned, mode-private, single-link no-follow
file, bounded to 4,096 bytes. NONBLOCK avoids hanging on special-file substitutes.
Seed, DER read buffers and Dalek signing keys zeroize on drop. Secret DER encoding
uses the library's SecretDocument. The signer has no Debug, Display, Clone,
serialization or private-byte export API. Errors contain fixed reasons, without
input bytes or raw adapter diagnostics. CLI prints only the public key identity.

Private keys are never stored in source snapshots, RunnerInput, authority execution
profiles, project TOML, source stores, Git adapters, materialization roots, OCI
images/containers, target environment or stdout/stderr. The development CLI rejects
key/public/output paths beneath the target repository or workspace root and loads
the private key only after execution, source/sandbox cleanup and complete draft
integrity checks. Tests use isolated temporary keys with explicit mode-0700 parents.

OS administrator/controller compromise, swap/core dumps, filesystem snapshots,
ACL mistakes, upstream defects and development-key theft remain risks. Permission
checks and zeroization are useful controls, not production custody. The retained
first development certificate's temporary private key was destroyed; only public
verification material is retained. Secure media erasure is not claimed.
