# ADR-0009: Descriptor-relative ephemeral Unix workspaces and cleanup

## Status

Accepted for Milestone 2. This is a Unix-first development adapter, not portable
filesystem isolation and not an OS sandbox.

## Decision

The authority supplies an explicit absolute workspace root. Every locator
component is opened with directory/no-follow semantics. The final root must be
owned by the effective UID with exact mode 0700. Root location and filesystem
configuration are authority inputs; target source and environment variables do
not select them. Symlinked host aliases must be resolved by the authority before
opening (for example `/private/var`, not macOS `/var`).

Fresh UUID v4 workspace names are generated independently of source paths.
`mkdirat` exclusively creates each child beneath a held root descriptor.
Existing names, even empty directories, are never reused or cleaned to make
creation succeed. A collision fails explicitly. Root emptiness is checked before
writing. No caller-provided existing project directory is accepted as a workspace.

All source directory components are validated and traversed with `openat` using
`O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`. Previously created directories must match
their saved device/inode identity. Newly required directories must be newly
created. Files use `O_CREAT | O_EXCL | O_NOFOLLOW`; permission changes operate on
opened descriptors, not re-resolved paths. Symlinks use `symlinkat`, and their
targets never become lookup paths. Verification opens files nonblocking, checks
regular type and link count one, and rejects unknown inodes/devices and special
files. Directory-relative `statat` uses `SYMLINK_NOFOLLOW`.

The OS umask can restrict creation; explicit descriptor `fchmod` establishes
the supported private modes once descriptors are open. Normal 022/077 umasks
produce identical canonical output. A mask denying owner directory access may
prevent opening a new directory; that attempt fails closed and cleanup is
reported. The implementation never changes the authority process's umask.

## Filesystem assumptions and race limits

The root and its contents must be on a trusted local filesystem that implements
Unix inode/no-follow/exclusive-create semantics. Its configuration must not grant
unrelated identities access through inherited ACLs or other mount/filesystem
features. Mode checks alone do not prove the absence of such ACLs. Root/owner
and mount administrators are trusted. Same-UID malicious processes, a compromised
kernel, hostile FUSE/network filesystems and privileged mount substitution are
outside this adapter's guarantee. Hardlinks to external files are rejected during
verification, and sealing never chmods unknown inodes.

Descriptors preserve lookup anchors if authority parents are renamed; returned
locations are diagnostic only and may become stale. Actual runner setup must use
the verified directory handle, never resolve that location again. A Unix directory
FD is not confinement: trusted sandbox setup must not expose it or inherited
authority FDs directly to target code where `..` could reach host ancestors.

Name/inode checks before/after reads and final handoff verification detect obvious
substitution and mutation but are not a transaction or formal race-freedom proof.
No target code runs during these phases. Tests deliberately mutate phase inputs,
swap directories/files/symlinks, retain a writable descriptor across sealing and
rename an authority parent. They demonstrate rejection/anchoring, not immunity
to all possible concurrent owner/root attacks.

## Cleanup semantics

The control plane retains a `WorkspaceLease` separately from runner input.
Explicit `destroy` performs bounded descriptor-relative deletion and returns a
structured destruction receipt only after success. It verifies the workspace
root name still identifies the originally created inode. A substituted root
is not traversed or deleted, and cleanup failure is reported.

Cleanup restores write permissions only on known authority-created directories.
It never chmods regular files or follows symlinks; file/symlink names are unlinked.
Unknown empty directories may be unlinked without changing their permissions;
unknown nonempty trees, mount/device crossings, unexpected identities and budget
exhaustion fail cleanup and require authority intervention. No broad recursive
path deletion, shell utility or secure-media-erasure claim is used.

On rejection, evidence distinguishes never-created, destroyed and failed cleanup.
Drop is a best-effort safety net without a success/audit claim. Process termination,
crashes and power loss can leave workspaces behind; durable orphan tracking and
recovery are deferred. Workspace deletion does not erase SSD history, snapshots,
open copies or source retained in the source store.

## Dependency reference

[Rustix filesystem APIs](https://docs.rs/rustix/latest/rustix/fs/index.html) supply
safe wrappers for openat, mkdirat, symlinkat, readlinkat, statat, fchmod and unlinkat.
ArchCert retains its workspace-wide unsafe-code prohibition. Transitive platform
bindings remain part of the trusted computing base, as documented in ADR-0005.
