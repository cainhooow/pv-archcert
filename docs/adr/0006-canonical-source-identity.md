# ADR-0006: Independent SHA-256 source manifest, schema 1

## Status

Accepted. Implements the independent source identity required by ADR-0002.

## Decision

ArchCert preserves the exact Git commit and root tree IDs, and independently
computes SHA-256 over the following canonical binary manifest. JSON diagnostic
output and serialized evidence are not the hash preimage.

All integers are unsigned, fixed-width, big-endian. No native-endian or
platform-sized integers appear in the encoding. There is no BOM or newline.

| Field | Encoding |
| --- | --- |
| Domain separator | 15 bytes: ASCII `ARCHCERT-SOURCE` followed by NUL |
| Schema | u32, value 1 |
| Entry count | u64 |
| For each sorted entry: path length | u64, UTF-8 byte length |
| Path | Exactly that many unchanged UTF-8 bytes |
| Mode | u32: octal 100644, 100755, 120000, or 160000 |
| Content SHA-256 | Exactly 64 lowercase ASCII hexadecimal bytes |
| Payload size | u64, byte length of the hashed payload |

Entries sort lexicographically by unsigned UTF-8 path bytes. Every leaf occurs
once. Directories, including empty directories, are not manifest entries; they
are nevertheless validated for names, collisions, modes and traversal limits.
Git tree IDs preserve any distinction omitted by this source-file identity.
Changing content, path, executable mode, symlink mode/target, or a gitlink commit
changes the corresponding canonical input. Commit metadata, timestamp, project
and repository labels, object packing, filesystem iteration order and local
configuration never enter this hash.

Ordinary/executable file payload is the exact Git blob. Symlink payload is the
exact link-target blob, including arbitrary target bytes; it is never interpreted
as a host path. Submodule payload is the referenced commit's canonical lowercase
ASCII hexadecimal ID (40 or 64 bytes). Its mode distinguishes it from a regular
file with identical content. LFS pointers hash their pointer bytes, with explicit
incomplete status: this digest never claims to identify retrieved external bytes.
The digest is conventionally displayed as `sha256:<lowercase hex>`.

## Path contract

Schema 1 accepts relative UTF-8 NFC names without rewriting their bytes. Invalid
UTF-8, non-NFC names, empty components, `.`, `..`, absolute paths, backslashes,
colons, control characters, Windows reserved characters/device names, trailing
dots/spaces and case-insensitive `.git` components are rejected. Components are
at most 255 UTF-8 bytes and complete paths at most 4096 bytes. This is an explicit
supported subset of Git's byte-oriented names, not a lossy conversion.

Duplicate byte paths and Unicode-lowercase aliases, including directory prefixes
and empty directories, fail with `PathCollision`. Lowercasing only constructs a
collision key; canonical names retain their original bytes. This is not a full
Unicode case-folding or every host filesystem's equivalence model. A future
materializer must use a case-sensitive, byte-preserving filesystem or reject
any additional collision/round-trip ambiguity. Cross-platform hashing does not
imply that every accepted name can be safely materialized on every host.

## Fixed test vectors

Empty manifest canonical bytes (hex):

```text
41524348434552542d534f5552434500000000010000000000000000
```

SHA-256:

```text
7a72bb7d625a4c191642a375d2d51096a904593ce6cb8599c33a32b8389f424c
```

One entry: path `a`, mode 100644, payload ASCII `abc`, size 3. Content SHA-256
is `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
Canonical hex below is line-wrapped only for documentation; concatenate lines:

```text
41524348434552542d534f5552434500000000010000000000000001
000000000000000161000081a4
6261373831366266386630316366656134313431343064653564616532323233
6230303336316133393631373761396362343130666636316632303031356164
0000000000000003
```

SHA-256:

```text
252d8a8aa373a45994b32021ac661a412b3c90138086686e41aaf92a491b2175
```

Vectors were also computed with Node's `crypto.createHash("sha256")` independently
of the Rust manifest implementation. Unit tests assert canonical bytes and both
digests, and exhaust all 24 permutations of a four-entry manifest.

## Consequences

Snapshot fields and retained bytes have no mutation/deserialization API. Sealing
derives metadata from owned bytes. Verification recomputes the manifest and
compares it with both recorded metadata and a caller-supplied expected digest.
Future format changes require a new schema/domain preimage, never a silent
change to schema 1. No signing primitive is implemented here.
