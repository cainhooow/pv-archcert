# Northgate source-ingress threat model

Trust boundary: hostile Git client -> authenticated/repository-authorized receive
process -> fresh quarantine -> independent bounded object/source validation ->
owned immutable accepted source -> separate M2–M4B controller. Transport has no
certification authority. This document records engineering assessment, not
independent security certification.

| Threat | Security property | Mitigation | Remaining risk |
| --- | --- | --- | --- |
| Unauthorized push / key impersonation | Actor attribution follows key possession | OpenSSH public-key-only authentication, pinned forced-command fingerprint, enabled key mapping | OpenSSH/host compromise or stolen client key; registry rotation is operational |
| Repository authorization bypass | Authentication does not imply scope permission | Explicit device/actor-to-project/repository grant; exact virtual route; no path-derived permission | Misprovisioned authority grant |
| Shell/SCP/SFTP/forwarding abuse | No general-purpose Git account capability | Restricted authorized_keys command, public-key-only auth, no rc/env/PTY, DisableForwarding and explicit denials | Deployment configuration/account administrator remains trusted |
| Malformed protocol / ref or tag confusion | Exactly one unambiguous immutable candidate | gitoxide packet framing, bounded command, canonical full OIDs, create-only refs/heads, no tags/symbolic/deleted/multiple/old refs | Minimal filter and upstream Git need continuing review/fuzzing |
| Malformed pack / missing base | Malformed storage cannot establish source | Mature gitoxide headers/deltas, zlib termination/length/checksum checks, self-contained bases, strict isolated Git fsck, original selected-closure grammar | Bugs in parsers/decompressors/Git are TCB risks |
| Pack bomb / delta bomb | Finite memory and work before Git decoding | Byte/count/entry/aggregate/work/depth/ratio/allocation bounds, known-base resolution before decode, no mmap | Bounded work can still be costly; production needs OS memory/CPU/disk containment |
| Object substitution / invalid hash | Exact selected Git closure binds owned bytes | Rehash Git preimages, exact type/OID/tree checks, independent canonical SHA-256 | SHA-1 compatibility is not a collision-resistance claim; OS authority compromise |
| Force-push mutation / replay confusion | Accepted source cannot be changed by a later push | Fresh empty quarantine per session, nonzero old OIDs reject, distinct submission UUID and candidate identity, retained owned snapshots | A --force creation is wire-equivalent to ordinary creation; replay creates new audit records |
| Git config injection | Candidate/operator ambient config cannot alter receiver behavior | env_clear, fixed HOME/XDG/config files, no template/checkouts, fsmonitor/helpers/replacements/protocol fetch/GC disabled | Configured Git executable itself is trusted, observed but unattested |
| Hook execution | No candidate lifecycle code on receiver | core.hooksPath=/dev/null on every Git call, empty init template, no project repository/config copied | Compromised executable/OS could ignore restrictions |
| Credential leakage | Acquisition authority stops before materialization | No private SSH client keys in store, no credential fields in snapshot/RunnerInput, separate acquisition port, cleared Git env, no ambient agent | Source may itself contain authored secrets; service operator controls credentials |
| LFS substitution / digest bypass | Pointers do not imply available verified bytes | Strict pointer grammar, bounded reader, exact declared SHA-256/size checks, separate immutable schema-2 representation | Private owner-controlled CAS grants; no remote network adapter; missing acquisition remains incomplete |
| LFS credential theft | Target never observes resolver secrets | Private operator-only acquisition capability, bounded digest-addressed regular files, returns bytes/identities only; no target URL/config input | Future adapter implementation must preserve this contract |
| Submodule SSRF | Candidate URLs never select acquisition destinations | No URL parameter; explicit authority repository/path/exact snapshot mapping, no .gitmodules interpretation | Future allowed network adapters need DNS/redirect/address/credential restrictions |
| Submodule substitution | Exact dependency identity binds complete source | Scoped immutable child commit/tree/SHA-256 verification, no branch/latest, incomplete nested child rejects | Authority mapping error; complete resolved children verified recursively under hard depth/work limits |
| Resolved identity substitution / incomplete child concealment | Complete execution binds verified external bytes | New schema-2 snapshot, original identity/claims and unchanged files checked, recursive child manifest/recipe verification, child-specific LFS coverage, artifact/export/stopped-sandbox rehash | Trusted source factory/store/OS remains authority; schema-2 logic needs continuing review/fuzzing |
| Recursive dependency exhaustion | Resolution and rehash have finite work | Complete accepted children only, no implicit fetch, depth 32, binding/entry/canonical-work caps plus source budgets | Bounded work can be expensive; kernel/filesystem blocking still needs operational containment |
| Cross-project object confusion | Repository namespace remains authority scoped | Grant check before quarantine, fresh objects per session, packed gateway mapping check, source store full project/repository/identity comparison | Trusted store/authority implementation can be compromised |
| TOCTOU / workspace collision | Validation bytes equal accepted bytes | Owned pack/object/file bytes, random exclusive storage identities, private roots, descriptor-relative no-follow reads, digest reconstruction on load | Same-UID/root can modify private storage; production separate identities/storage needed |
| Resource exhaustion / auth floods | No unlimited ingress | Single receive lease, max retained attempts, pack/source budgets, stdin and subprocess deadlines/output limits, SSH auth/startup limits | No distributed per-actor rate service, OS quotas, durable orphan recovery or fairness |
| Gateway compromise | Gateway cannot issue or execute certification | Standalone binary and dependency guard exclude runner/Docker/policy/signer/private certificate keys; only source output crosses boundary | Process under an overly privileged service identity can exceed Rust API boundaries; deploy with least privilege |
| Partial acceptance / disconnect | Successful status follows immutable acceptance | Buffer Git response until source publication, atomic private directory publication, no accepted snapshot on validation error | Client may disconnect after publication; crash/recovery semantics are development-only |

Security regressions exercise real SSH push, unknown/disabled key, wrong grant,
command/forwarding denial, malicious command/ref/pack data, environment/hook
canaries, delta/byte/count limits, source identity differential, immutable replay,
store tampering, LFS mismatch and disallowed submodule locations. Existing M1
path/type/hash/UTF-8/NFC/collision/symlink/mode and M2–M4B gates remain authoritative.
