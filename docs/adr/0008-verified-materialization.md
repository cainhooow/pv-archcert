# ADR-0008: Verified materialization of accepted source

## Status

Accepted for Milestone 2. Extends ADRs 0006–0007; their historical text remains
unchanged. This milestone replaces the original broad runner milestone with
source preparation only. No target execution or container runtime is introduced.

## Decision

Domain types model workspace IDs, scoped snapshot references, budgets, structured
errors and forward-only lifecycle states. The application retrieves an immutable
accepted snapshot through `SourceStore::load`, keyed by project, repository and
the full Git/ArchCert identity. It checks the returned scope/identity, rehashes
owned bytes and requires complete source before invoking the filesystem adapter.
The adapter repeats these checks for direct callers of its staged authority API.

`archcert-materialization` implements the infrastructure adapter. It depends
inward on domain/application contracts and uses existing Rustix safe filesystem
wrappers. No new third-party crate is introduced. Rustix's existing `process`
feature provides effective-UID checks; test-only subprocesses use its umask API.
The runtime adapter has no Git, network, credential, shell or source-store client.
Its source reader does not use system Git or any external program.

The actual workflow is:

```text
exact store lookup -> verify snapshot -> require COMPLETE -> apply budgets
 -> create fresh private workspace -> write exact accepted payloads
 -> enumerate actual filesystem -> reconstruct schema 1 -> compare digest
 -> apply read-only permissions -> enumerate/reverify sealed filesystem
 -> reverify at handoff -> issue narrow RunnerInput + separate cleanup lease
```

`PendingMaterialization`, `SealedMaterialization` and `RunnerInput` are distinct
types. Pending source has no runner input. Only successful verification/sealing
can construct the platform source capability. The generic application capability
requires a `MaterializedSource` implementation whose workspace and source identity
must match sealed evidence. Implementing this trait is a trusted adapter duty,
not an opportunity for untrusted serialized evidence to establish authority.

Evidence records snapshot/workspace identities, version, expected/observed
digests, leaf count, written bytes, state, verification, seal strength, budgets
and operational UTC timestamps. Returned events record start, verification,
rejection, sealing, issuance and explicit destruction. No durable audit log or
certificate is claimed.

## Verification semantics

The verifier enumerates actual names, including unexpected entries, rather than
reading only a list of expected files. It validates names again, opens regular
files without following symlinks, and reads symlink targets with bounded
`readlinkat`. It independently derives content hashes, sizes and Git leaf modes,
sorts a new `SourceManifest` and compares its SHA-256 with the accepted digest.
Missing/extra files, mode changes and link-target changes reject. The directory
set is checked separately because canonical schema 1 omits empty directories.
Created inode/device identities are checked to detect substitution and filesystem
crossing. File size/mode/mtime/ctime changes during reads reject; timestamps are
never part of the canonical digest.

Before sealing, regular/executable files have exact modes 0600/0700 and
directories 0700. After sealing, they have modes 0400/0500 and directories 0500.
These private modes map deterministically to Git modes 100644/100755. Symlink
permissions are filesystem-defined and excluded from regular-file mode handling;
their canonical mode is always 120000. No symlink target is chmodded or opened.

The supported NFC UTF-8 names retain their bytes. Enumeration rejects non-NFC,
lossy names and host round-trip differences. Unsupported symlink targets
(empty, NUL-containing, or over the adapter's 4096-byte ceiling) fail before
creation. Filesystems with a lower link-target limit return an explicit creation
failure. Raw non-UTF-8 link targets are supported where the Unix filesystem
supports them. None of these restrictions rewrites the accepted source.

## Budgets

Reuse `SourceLimits` for leaf count, payload bytes, individual payload size and
directory depth; Git-specific fields do not participate here. Add explicit
directory and symlink budgets (development defaults: 10,000 and 1,000). Root
depth is zero; a hard traversal ceiling of 128 applies. Preflight checks budgets
incrementally before destination creation. Every filesystem verification pass
counts leaves/bytes/directories/symlinks again. Sealing checks only known created
inodes under a finite entry/depth budget; cleanup is separately bounded.

These are finite development work bounds, not wall-clock, disk-quota, global RSS
or concurrent-submission admission controls. Production requires those controls.

## Milestone 1 review

No reproduced ingestion defect was found. Its canonical digest, mode mapping,
owned source and incomplete-source rules remain unchanged. Store lookup and
typed materialization results are required extensions to previously provisional
contracts. Empty/NUL symlink payloads remain valid source data but are explicitly
unsupported by this filesystem adapter. The additional directory-set check
preserves schema 1 rather than silently changing its preimage.
