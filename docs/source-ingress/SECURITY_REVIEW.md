# Northgate final engineering security review

October 20, 2026. Engineering self-review and regression evidence, not independent
certification. Governing invariant: transport Git objects, execute immutable
snapshots, and grant the candidate no authority over its certifier.

| Review search/area | Finding and disposition |
| --- | --- |
| clone/fetch/submodule update inside runner | No acquisition command added to runner; no acquisition dependency; export now carries only a credential-free identity recipe |
| Git/LFS/SSH credentials in RunnerInput/materialized source | Only immutable source identity recipes added to snapshot/directory capability; assertions inspect source, binding and runner fields; source-auth identity stays in ingress evidence |
| Private SSH keys in ArchCert storage | No private key API or retained key file; only temporary external test harness client/host keys; source store contains accepted source and public identity evidence |
| Shell-enabled Git account | Real SSH tests reject empty shell, arbitrary command, SCP/SFTP/upload-pack and command injection; fixed authority forced command plus forwarding/rc/PTY restrictions |
| Hooks/global configuration | Every Git call disables hooks and clears ambient environment; no checkout/template/filter invocation; poisoned HOME/global/system/config-count/agent and hook canary tests pass |
| Arbitrary submodule fetch / SSRF | No candidate URL argument or fetch implementation; explicit scoped mapping required; metadata/localhost/file/credential URLs cannot initiate requests |
| LFS digest bypass | Strict pointer grammar; controlled bounded reader must match exact size and digest; mismatch/extra data rejects |
| Duplicate OID delta-base redirection | Keep the first verified base mapping immutable; duplicate-object deltas cannot redirect checked ancestors into themselves or deeper chains; regression added |
| Unbounded pack decoding | Library headers/deltas, fixed-buffer stream admission, count/bytes/work/depth/expansion/allocation caps, finite scan rounds and time checks; malformed/checksum/base/bomb fixtures reject |
| Acceptance before quarantine validation | Raw pack, all delta bytes and selected commit/tree/path closure validate before Git strict receive; immutable storage publishes before client success |
| Mutable snapshot after push | Fresh authority-generated quarantine per session; owned retained bytes, read-only artifact files, rehash on load; replay and later branch mutation tests preserve the original source |
| Gateway signer/Docker/runner/policy dependencies | Direct/transitive dependency guards pass for crate and standalone executable; gateway cannot create jobs, evaluate policy or load a signer |
| Ref/branch/tag/shallow confusion | One create-only refs/heads command; tags/symbolic/deleted/old/multiple updates reject; one shallow declaration must equal selected exact commit; --force cannot mutate stored state |
| Cross-project/source-store confusion | Authorization before reception; exact repository gateway mapping and full project/repository/commit/tree/digest store comparison; no candidate-selected storage path |
| TOCTOU through mutable ancestors/config paths | Final review added trusted-owner and non-writable/sticky ancestor checks, anchored no-follow private configuration reads, and regressions for hostile writable parents and symlink configurations |
| Incomplete source with a weakened authority property selection | Final review added an unconditional NOT_ELIGIBLE floor and independent certificate preparation rejection; tests cover an all-NOT_APPLICABLE authority profile and forged eligibility |
| Sensitive client errors | Only fixed bounded ingress categories are printed; raw Git stderr stays in temporary private files and is destroyed; no credential/packet/source-byte diagnostic echo |
| Concurrent fork temporarily retains an admission descriptor | Store drop explicitly unlocks its lease before descriptor destruction; duplicated-description regression verifies immediate readmission while another descriptor remains open; active-session exclusion is still enforced |
| Publication followed by client disconnect | A successful publication remains accepted even if response delivery fails; failed publication records no SourceSnapshotAccepted event |

Searches used rg across gateway, source, materializer, runner, application and
signer boundaries for clone/fetch/submodule commands, credential/config/hook/key
markers, direct dependencies and acceptance paths. Matches in documentation,
negative fixtures and explicit environment exclusions are intentional. No retained
PEM/OpenSSH private-key marker was found. Runtime/source storage integrity still
assumes a trusted service OS identity; read-only modes do not constrain root or
a compromised same-UID authority process.

Production deployment requires separate OS identities, OS CPU/memory/disk/process
containment, patched trusted OpenSSH/Git, qualified Linux transport/OCI, durable
storage/audit/crash recovery and operational admission controls. Initial network
LFS/submodule remote network acquisition remains unsupported. The operator-only
private LFS/accepted-child adapter and schema-2 execution are exercised end-to-end.
The original incomplete submission is never promoted or mutated. Nested child
coverage follows its own verified binding, so expanding a gitlink cannot conceal
unresolved pointers; recursive depth/work budgets and substitution tests enforce
that boundary. LFS mismatch, storage symlink and wrong-repository child grants
reject before publication. Acquisition files and SSH are removed before the
resolved-source certificate regression. These limits are recorded explicitly rather than being presented as certification.
