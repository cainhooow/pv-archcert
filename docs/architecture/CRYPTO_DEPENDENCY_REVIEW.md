# Eldermark cryptography dependency review

Reviewed October 20, 2026 against the locked Cargo tree, upstream documentation,
crate source declarations and cargo-deny. This is an integration/security boundary
review, not a complete independent audit of upstream cryptographic arithmetic.

## Selection and maintenance

ed25519-dalek **3.0.0** is pinned exactly. It is the current maintained release
observed through [upstream documentation](https://docs.rs/crate/ed25519-dalek/3.0.0)
and the [active Dalek repository](https://github.com/dalek-cryptography/curve25519-dalek).
The old ed25519-dalek standalone repository is archived because it moved to this
monorepo, not evidence that the selected implementation is unmaintained.

Purpose: Ed25519 signing, public-key validation, weak-key rejection and strict
signature verification. Selected for maintained Rust implementation, typed
private/public keys, strict verification and zeroization support. No new
cryptographic arithmetic/hash/entropy/key-encoding implementation is written.
Default fast/zeroize features stay enabled. local-development enables only
PKCS#8/alloc support in addition. No batch, legacy_compatibility, hazmat, digest
(Ed25519ph), serde private-key support or algorithm negotiation is enabled.

getrandom **0.4.3** was already locked via uuid/tempfile and is now a direct optional
local-key-generation dependency for OS cryptographic randomness. zeroize **1.9.1**
protects local seed/read buffers, Dalek key drop and RustCrypto SecretDocument.
The mature PKCS#8/DER/SPKI stack handles encoding; ArchCert writes no key codec.
Existing sha2 **0.10.9** remains the SHA-256 identity implementation. Dalek uses
sha2 **0.11.1** internally for Ed25519 SHA-512. hex **0.4.3** is public wire encoding;
private keys are bounded PKCS#8 DER, never printed hex.

## Locked additions

These are all newly resolved third-party name/version pairs relative to M4A:

| Package | Version | Purpose |
| --- | --- | --- |
| base64ct | 1.8.3 | Optional upstream encoding dependency, locked but inactive |
| block-buffer | 0.12.1 | Hash block processing |
| const-oid | 0.10.2 | Algorithm object identifiers |
| cpufeatures | 0.3.1 | Runtime backend selection |
| crypto-common | 0.2.2 | Hash/crypto generic types |
| curve25519-dalek | 5.0.0 | Upstream curve arithmetic backend |
| curve25519-dalek-derive | 0.1.1 | Upstream backend proc-macro |
| der | 0.8.2 | Strict ASN.1 DER codec |
| digest | 0.11.3 | Hash traits and buffers |
| ed25519 | 3.0.0 | Signature and key-encoding types |
| ed25519-dalek | 3.0.0 | Signing and strict verification |
| fiat-crypto | 0.3.0 | Alternate upstream arithmetic backend, target/configuration dependent |
| hybrid-array | 0.4.15 | Fixed generic arrays |
| pkcs8 | 0.11.0 | Private-key codec and secret document |
| rustc_version | 0.4.1 | Upstream build-time compiler detection |
| semver | 1.0.28 | Build-time version interpretation |
| sha2 | 0.11.1 | Upstream Ed25519 SHA-512 |
| signature | 3.0.0 | Signature trait contracts |
| spki | 0.8.1 | Public-key codec support |
| subtle | 2.6.1 | Constant-time support |
| zeroize | 1.9.1 | Memory zeroization |

The full tree (`cargo tree -p archcert-crypto --all-features`) is retained in ignored
target/m4b/crypto-tree.txt. Besides this table it reuses cfg-if, getrandom/libc,
hex, sha2 0.10/digest 0.10/generic-array/typenum, rustix/errno/bitflags,
thiserror and the existing proc-macro stack. Build dependencies include
rustc_version/semver and curve25519-dalek-derive with syn/quote/proc-macro2.
Crypto has no workspace dependency. Local filesystem/randomness dependencies
are optional and absent when building only the default offline verifier library.

## Unsafe footprint and trust

ArchCert retains workspace unsafe_code=forbid. ed25519-dalek's production library
forbids unsafe code under this non-batch feature selection. This does not mean
all transitives are unsafe-free: curve25519-dalek contains optimized backend
intrinsics/unsafe sections; cpufeatures uses architecture-specific detection;
zeroize uses volatile writes, pointer operations and fences; DER allows narrow
newtype-reference casts; libc/rustix/getrandom contain OS/backend unsafe code.
No full source audit or formal safety proof is claimed. Backend/platform/compiler
behavior remains in the trusted computing base. Memory zeroization does not
protect against swap, dumps, snapshots, side channels or a compromised controller.

## Dependency gates and independent reproduction

cargo-deny advisories, bans, licenses and sources pass with the locked additions.
New duplicate-version warnings are block-buffer, cpufeatures, crypto-common,
digest and sha2 (the existing identity hashes use the prior API while Dalek uses
the new API); existing syn and winnow duplicates remain. These are warnings,
not disabled advisories. MIT/Apache-2.0/BSD-3-Clause licenses fit the unchanged
allowlist. No unknown registries/Git sources or wildcard exceptions were added.

OpenSSL 3.6.4 independently generated, signed and verified a fixed synthetic
canonical payload. Python json/hashlib independently produced its canonical bytes
and SHA-256. Rust verifies exactly that retained OpenSSL signature/digest. OpenSSL
also decoded the Dalek-generated development PKCS#8 key and independently verified
the real controlled certificate signature over the exact retained canonical bytes.
This independently reproduces cryptography/serialization, not engineering claims
or independent certification of the implementation. Neither OpenSSL nor Python
is a runtime dependency of issuance or offline verification.
