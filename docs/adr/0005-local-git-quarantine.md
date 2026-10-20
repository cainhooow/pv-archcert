# ADR-0005: Bounded local Git quarantine for Milestone 1

## Status

Accepted for the development vertical slice. Extends ADR-0002; it does not
replace the future `git push archcert HEAD` transport model.

## Decision

Git remains the primary source transport. `SourceSubmission` carries authority
project and repository identities and a full, validated SHA-1 or SHA-256 commit
ID. A future Smart Protocol gateway will map authenticated pushes to this same
application request. Authority repository identity is separate from a transport
path; target configuration never supplies it.

The initial Unix-only `LocalGitGateway` reads loose objects from an explicitly
selected bare Git directory or `.git` directory. It does not discover repositories,
resolve refs, peel tags, expand abbreviated IDs, consult alternates, use packfiles,
follow Git configuration, or invoke the system Git executable. A required object
absent from the loose store is reported as a typed missing-object failure, even
if it exists in an unsupported pack or alternate. Worktrees with `.git` files
are unsupported. No network endpoint or push authentication is implemented.

Repository bytes remain logically quarantined until the complete selected
commit/tree/blob closure has validated. This is an in-process, bounded quarantine,
not a filesystem namespace or an OS process sandbox. No accepted snapshot exists
on failure. Historical parents are syntax-checked references, not fetched or
validated history; this milestone validates a source state, not Git history.

Object reads verify zlib stream completion, reject trailing bytes, rehash the
entire Git header and payload, check declared lengths and expected types, then
parse a strict supported commit/tree grammar. Commit signatures are opaque
header data; they confer no authority. Trees must use canonical Git ordering,
supported modes and nonzero object IDs. Unsupported or ambiguous input fails
closed. Unreachable objects are never inspected or accepted as evidence.

File descriptors anchor each local directory component. `openat` with
`O_NOFOLLOW` prevents symlink substitution, `O_DIRECTORY` constrains directory
opens, and `O_NONBLOCK` plus a regular-file check avoids FIFO hangs. The explicit
locator must have no symlink components (including host aliases such as macOS
`/var`; supply `/private/var` when applicable). This avoids a check-then-open
filesystem race. Every byte used after validation is owned by ArchCert.

## Dependency rationale and trusted computing base

No libgit2/gix or Git subprocess enters the runtime boundary. The deliberately
small supported loose format uses `flate2` with the explicit `miniz_oxide`
backend, `sha1` for Git SHA-1 compatibility only, and existing RustCrypto `sha2`
for Git SHA-256 and the independent source identity. `hex` performs fixed-format
encoding; `unicode-normalization` validates NFC without transforming filenames.
`rustix` provides safe wrappers for descriptor-relative filesystem operations.
`tempfile` is test-only; system Git is used only to create independent test
fixtures, and a normal fixture is also checked with `git fsck --strict`.

These crates and their transitive code are trusted dependencies, not evidence
authorities. ArchCert adds no `unsafe`; the inherited workspace forbids it in
ArchCert code. Rustix/libc and cryptographic CPU implementations can contain
unsafe internally. A blanket claim that the dependency tree is unsafe-free is
not made. The lockfile pins the tested resolution. Advisory/license checks are
required but cannot establish dependency correctness. This small custom parser
also requires review and future fuzzing; it is not a complete Git implementation.

## Limits

Development defaults are 10,000 leaf entries, 64 MiB retained payload, 8 MiB per
blob, depth 32, 25,000 object visits, 9 MiB per compressed/inflated object, and
256 MiB aggregate compressed plus inflated work. Reused objects count on every
visit to bound repeated-tree expansion. Gitlink OID text counts toward retained
bytes. A parser recursion ceiling of 128 applies even if the configured depth
is higher. Limits are authority inputs and are recorded in evidence.

These are conservative development budgets, not production capacity claims.
They constrain memory and finite work, but do not impose a wall-clock deadline,
prevent blocking hostile filesystem I/O, limit the number of submissions, or
provide process-wide memory isolation. The gateway must later run without
signing secrets/control-plane credentials, with OS limits and admission control.

## Consequences

There is no dependency on repository-controlled Git behavior or developer
working-tree content. Hash verification binds bytes read despite concurrent
repository mutation; mutation can cause rejection but cannot replace retained
snapshot bytes. SHA-1 collisions are not detected specially; independent SHA-256
source hashing prevents treating Git SHA-1 alone as source evidence. Repository
provenance/authentication remains a future gateway responsibility.

## Format and API references

- [Git loose-object format](https://git-scm.com/docs/gitformat-loose.html)
  defines the zlib-compressed header/payload and Git object preimage.
- [Rustix openat](https://docs.rs/rustix/latest/rustix/fs/fn.openat.html)
  provides the descriptor-relative opening API used by the adapter.
- [Flate2 decompression](https://docs.rs/flate2/latest/flate2/struct.Decompress.html)
  documents streaming progress/termination and flush semantics.
