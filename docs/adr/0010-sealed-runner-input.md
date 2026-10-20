# ADR-0010: Best-effort permission seal and credential-free runner input

## Status

Accepted for Milestone 2; refines the future boundary in ADR-0007 without changing
that ADR's historical implementation status. Actual sandbox execution is deferred.

## Decision

Successful materialization progresses through `MATERIALIZING`, `VERIFIED`,
`SEALED`, `HANDED_OFF` and explicit `DESTROYED`. Distinct staged Rust types gate
filesystem verification and handoff. Structured evidence represents states but
cannot be deserialized to manufacture a real platform source capability.

The seal is `UnixPermissionsReadOnly`: owner read-only files/directories with
the supported owner execute bit. It discourages accidental writes and denies
ordinary other-UID writes under the documented root/filesystem assumptions.
It is not cryptographic immutability. The owner/root can chmod files, and writable
descriptors opened before chmod remain writable. A regression deliberately uses
such a descriptor and confirms final handoff verification rejects its mutation.

The adapter reconstructs the filesystem before sealing, after sealing, and again
immediately before issuance. There is inevitably a mutation window after return
against a same-UID/privileged writer. Before target code executes, a future
sandbox adapter must establish an isolated read-only source mount/volume, close
authority descriptors, set an explicit environment allowlist and reverify source
inside that immutable execution view. Do not treat this milestone's chmod seal
as that future isolation mechanism.

`RunnerInput<MaterializedDirectory>` contains only:

- the verified source directory descriptor and a local destroyed marker;
- exact expected Git/ArchCert source identity;
- opaque authority workspace identity.

The source capability has private construction, no cloning/serialization API,
and contains no cleanup parent, repository URL, store, network client, signer,
policy administrator or credentials. Application construction checks source
identity/workspace against verified/sealed evidence. Cleanup and richer audit
evidence stay with the control plane. Successful explicit deletion prevents new
directory-handle borrows, but is not a general revocation system for descriptors
already borrowed by a trusted adapter.

No ambient environment is copied into source or runner input. The runtime adapter
does not read HOME, GIT_CONFIG, GIT_CONFIG_GLOBAL, SSH_AUTH_SOCK, AWS variables,
DATABASE_URL, OPENAI_API_KEY or TMPDIR. UUID generation uses OS randomness;
effective UID, Unix permissions/umask, the explicit root and filesystem behavior
are host dependencies. Tracked files such as `.gitconfig` or `.ssh/config` remain
exact project bytes. Host credentials/configuration are never discovered or
copied; credential-looking source is not scrubbed because that would alter the
accepted identity. `.git` components remain unsupported by source schema 1.

The development CLI `source inspect --materialize-under ROOT` demonstrates the
vertical slice, emits structured evidence, and explicitly destroys the workspace.
It never executes a project or leaves a live workspace advertised as persisted.
Production source storage, credential/process isolation, Docker/gVisor/Firecracker
and certification policy/signing remain separate future work.
