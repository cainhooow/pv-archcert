# Northgate infrastructure and dependency review

Reviewed October 20, 2026. This is engineering dependency assessment, not an
independent audit or executable attestation.

## Selected implementations

| Component | Selected implementation | Reason and constraints |
| --- | --- | --- |
| SSH server/crypto | Operator-managed OpenSSH; development `/usr/sbin/sshd` | Mature public-key authentication and command/forwarding restrictions; no embedded SSH crypto added to Rust or certificate-key dependency graph |
| Git Smart Protocol | Explicit `/usr/bin/git`, observed `git version 2.50.1 (Apple Git-155)` | Maintained receive advertisement/status handling; fresh private repositories and constructed configuration; sees candidate pack only after independent validation |
| Pack entry/header/delta parser | Exactly gix-pack 0.76.0 | Maintained gitoxide implementation; owned Vec-backed File, configured allocation ceiling, prechecked bases/depth/work; generate/streaming-input/default/parallel features disabled |
| Git object-format types | Exactly gix-hash 0.28.0, SHA-1/SHA-256 features | Necessary format variants; ArchCert still recomputes compatibility preimages with its existing hash implementations |
| Pack decoder inflater | Exactly gix-zlib 0.3.0, zlib-rs 0.6.8 | gix-pack's maintained decompressor; bounded output/allocation and no unchecked metadata allocation |
| Packet-line format | Exactly gix-packetline 0.21.0, blocking-io only | Library framing/validation and Git protocol bounds, with a small create-only ingress filter |
| Stream preflight inflater | Existing flate2/miniz_oxide | Fixed 8192-byte output chunks reject declared-size overproduction before Git/gix delta decoding |
| Filesystem/admission/deadline | Existing rustix 1.1.5 plus event feature, tempfile 3.27.0, UUID | Safe APIs, descriptor-relative no-follow storage, exclusive files, flock and stdin poll deadlines; private tempfile directory permissions are explicitly 0700 |

Gitoxide was chosen over libgit2 bindings because the selected pack API exposes
owned backing bytes, exact entry information and explicit allocation limits needed
for pre-decode resource checks. A full gitoxide receive server would still require
more protocol integration. The isolated Git adapter reuses the system protocol
implementation while preventing it from being the source-identity authority.
No custom pack/delta/SSH cryptography is introduced. The short fixed-buffer frame
walk is an admission layer around upstream header parsing and zlib, not a new delta
implementation. Git SHA identity is compatibility provenance; ArchCert's schema-1
SHA-256 is unchanged.

OpenSSH authentication returns public possession identity to a fixed command. Its
API is the authority-owned authorized_keys fingerprint and SSH_ORIGINAL_COMMAND,
not target-supplied actor flags. The deployment configuration is part of the TCB.
OpenSSH host keys are managed outside ArchCert by the operator. The development
harness creates only temporary client/host keys outside source storage. No private
SSH client key API or cryptographic primitive enters gateway crates.

## Transitive footprint

The lockfile pins the tested graph. New gitoxide families include gix-actor/date/
object/hash/hashtable/chunk/path/validate/utils/trace/parallel/error/pack/zlib/
packetline. Dependencies include bstr/regex-automata, faster-hex/heapless/hash32/
byteorder/stable_deref_trait, jiff/jiff-core, prodash/parking_lot/parking_lot_core/
lock_api/scopeguard/smallvec, hashbrown, memmap2, sha1dc, zlib-rs and the SHA-256
0.11 digest/hybrid-array family. Duplicate hash/digest/gix-trace versions are
expected from independently versioned APIs and remain cargo-deny's visible
warnings. No wildcard workspace dependency is permitted.
The crate source review inspected allocation/entry/delta/header implementations
and the upstream unsafe boundaries; it did not audit every line of transitive code.

Exact full trees and feature selection are reproducible with:

```sh
cargo tree -p archcert-source --edges normal
cargo tree -p archcert-source --edges features
cargo tree -p archcert-gateway --edges normal
cargo metadata --format-version 1 --locked
```

ArchCert code keeps unsafe_code=forbid. Upstream unsafe code exists in memory
mapping, decompression, platform bindings, locking and optimized cryptography.
The selected pack path uses owned Vec data rather than the mmap constructor.
sha1dc and platform/runtime code remain trusted transitive implementations even
where Northgate does not directly invoke their APIs. No unsafe-free dependency
claim is made. Advisory/license checks cannot establish parser correctness.

## License decision

Reviewed the pinned zlib-rs 0.6.8 LICENSE: permissive Zlib license, retaining origin,
alteration and notice requirements and an as-is disclaimer. Added a narrow
cargo-deny exception for exactly that package/version/license. The global allowlist,
advisory checks, wildcard ban and unknown registry/git bans remain unchanged.
This is not a blanket allow for unknown licenses. Other selected gitoxide crates
use MIT OR Apache-2.0; their existing transitive licenses satisfy the locked policy.
The first deny run correctly rejected missing workspace version pins and the
unreviewed Zlib license; both were addressed explicitly.

## Upstream references and remaining risks

- [gitoxide pack API](https://docs.rs/gix-pack/0.76.0/gix_pack/)
- [pack allocation-limit contract](https://docs.rs/gix-pack/0.76.0/gix_pack/data/struct.File.html)
- [gitoxide repository](https://github.com/GitoxideLabs/gitoxide)
- [OpenSSH command restrictions](https://man.openbsd.org/sshd.8)
- [Git quarantine and receive behavior](https://git-scm.com/docs/git-receive-pack)

Selected upstream packages expose current documented maintenance/release APIs;
that does not attest binaries, eliminate vulnerabilities or provide an independent
security assessment. Production must maintain patched OpenSSH/Git, contain receiver
CPU/memory/disk/network under a dedicated OS identity and review deployment key
provisioning. Native Linux deployment remains unqualified until that environment
runs the complete transport/OCI suite. HTTPS and embedded SSH are unimplemented.

## Resolved-source extension

The operator-only private LFS/accepted-child adapter, SourceBinding canonicalization,
artifact restoration and credential-free materializer/runner verification add no
third-party package or version. They reuse existing safe filesystem, hashing and
serialization dependencies. Child recipes contain immutable identities only;
source-acquisition capabilities remain in the gateway adapter/application port.
ADRs 0031/0033 and the resolved-source regressions document this additional TCB.
