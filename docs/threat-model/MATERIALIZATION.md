# Source materialization threat model

Milestone 2 accepts only authority-scoped complete snapshots and prepares passive
source. The trusted computing base includes ArchCert, Rustix/platform bindings,
the source store, OS randomness, kernel and authority-owned local filesystem.
This is not independent certification, runtime isolation or a claim against
malicious same-UID/root processes. See ADRs 0008–0010 for exact assumptions.

| Threat | Security property | Mitigation | Remaining risk |
| --- | --- | --- | --- |
| Snapshot/store substitution | Prepared bytes bind to accepted scope and identity | Exact project/repository/full identity lookup; verify returned scope; rehash owned source before writes | Store/adapter implementations are trusted code; no remote/durable store yet |
| Path traversal, absolute paths, separators | Writes remain beneath the created source inode tree | Revalidate paths; directory-relative component lookup; exclusive no-follow creation | Filesystem/kernel semantics and authority ownership are prerequisites |
| Symlink escape | Link targets never cause host reads/writes | symlinkat/readlinkat; no-follow stats/opens; no chmod of symlink targets | A future sandbox must confine target access to escaping links during execution |
| Directory/file replacement and TOCTOU | Substituted entries cannot be issued as verified source | Held directory FDs; expected device/inode checks; no-follow lookup; three verification passes | No atomic filesystem transaction; same-UID/root mutation after handoff remains possible |
| Authority parent substitution | Renamed parent does not redirect operations | Root descriptor anchors creation/cleanup; runner source uses descriptor, not diagnostic location | Location may be stale; future adapters must not resolve it again |
| Host file overwrite / hardlinks | Ingestion/materialization cannot overwrite host data | Exclusive creation; hardlink count one for regular verification; seal only created inodes; cleanup never chmods files | Malicious owner/root/kernel can defeat private-root assumptions |
| Workspace collision/prepopulation | Existing project data never becomes output | Random authority UUID plus exclusive mkdir; reject existing name; check emptiness | UUID collision fails; no retry that reuses/deletes an existing destination |
| Credential leakage | Runner input needs no acquisition/control credentials | Source-only opaque handle; cleanup/store outside input; no environment/config discovery or subprocess | Ambient process/FD credentials must be excluded by future runtime setup; tracked secrets remain project source |
| Environment influence | Source identity does not depend on shell secrets/config | Explicit private absolute root; no HOME/Git/SSH/AWS/API/DB/TMPDIR reads; exact descriptor permissions | UID/umask, OS randomness and trusted filesystem configuration still participate operationally |
| Materialization tampering | Actual bytes/modes reproduce accepted source | Enumerate all actual names; read/hash contents and link bytes; canonical schema 1 digest comparison; reject extra directories | Hash assumptions/dependency correctness and trusted kernel remain necessary |
| Post-verification mutation | No knowingly changed source is handed off | Read-only permission seal; reverify post-seal and at issuance; capability private construction | Owner/root or pre-existing writable FD can mutate after return; isolated read-only execution view is deferred |
| Incomplete external source | Partial projects cannot become runner-ready | COMPLETE guard before creation; LFS/gitlink failures return structured rejection | Full retrieval and provenance checking remain unimplemented |
| Resource exhaustion | Materialization has finite per-attempt work | Reused source file/byte/depth limits, symlink/directory caps, bounded readlink, entry/depth caps for seal/cleanup | No I/O deadline, disk quota, process RSS quota or global admission control |
| Cleanup failure / substituted root | Cleanup does not delete unrelated roots or falsely claim success | Explicit bounded no-follow cleanup receipt; inode-anchored root identity; only known directory chmod | Orphans on failure/crash require intervention; Drop is unaudited best effort, not secure erasure |
| Filesystem semantics mismatch / Unicode | No silent normalization or ambiguous entry acceptance | Validate actual UTF-8 NFC names and canonical manifest; exact type/mode checks; reject unsupported targets/types | ACLs, case folding, mount/FUSE/network semantics require deployment constraints; no superficial Windows support |

Tests exercise phase-boundary substitutions, a coordinated writable-descriptor
mutation after sealing, parent rename, credential/environment poisoning in isolated
test processes, 022/077 umasks, timestamps, missing/extra files/directories and all
budgets. These are regression checks, not proof of formal race freedom.
