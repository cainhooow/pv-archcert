# M6 build and release authorization threat model

Scope: one bounded regular file, two independent same-input rootless builds,
create-only PostgreSQL checkpoints, development Ed25519 permits and an explicit
local deployment gate. Source certification and artifact authorization differ.

| Threat | Required control | Residual limit |
| --- | --- | --- |
| Wrong source certificate | Verify existing structure/signature under selected source key; compare project/repository/full commit/tree/snapshot and approved policy | Source authority and its selected policy remain trusted |
| Target-selected build authority | Fixed versioned recipe selected outside source; frozen manifest; no target shell/env/runtime selectors | Operator and image supply chain are trusted |
| Mutable dependencies/toolchain | Bind authority public bundle/toolchain inventories and digest-pinned image; offline target build | Provisioning assertions are not runtime attestation |
| Output escape/substitution | Fixed runtime-invoked collector; descriptor-relative no-follow/nonblocking file read; before/after mutation checks; no links/devices/extra outputs; immutable upload and readback | Runtime/kernel compromise defeats collection |
| Fake reproducibility | Separate non-expiring execution claims, separate sandboxes/workspaces; compare collected SHA-256 and size | Same toolchain defects may repeat deterministically |
| Infrastructure failure | Explicit INCONCLUSIVE; no permit; uncertain execution claims never automatically retried | Conservative recovery may need a new authority invocation contract |
| Concurrent controllers | Row locks, create-only roles, immutable invocation and payload; one accepted permit | Database owner/controller compromise outside cooperative model |
| Signing crash | Persist payload first, reconstruct exact bytes, deterministic same-message signature, readback envelope then completion | Key availability required; no production custody |
| Missing/corrupt accepted evidence | Re-read and verify every prerequisite before preparing or signing | Object retention/capacity remain operator duties |
| Artifact swap at deploy | Gate reads actual bounded bytes, verifies SHA-256/size, exact project/repository and selected permit key | Caller must deploy those same verified bytes; no external orchestrator integration |
| Target writes collector stdout or signals the reader | Reader runs as separate unprivileged UID/GID 10002; target stays 10001 without capabilities; reader checks its identity | Runtime/kernel compromise remains trusted; target may deny output availability |
| Key/credential disclosure | No keys in runner/worker/input/image; load signer only after execution and confirmed cleanup | Development controller shares OS identity with local signer |
| Semantic approval laundering | Release policy is deterministic and demands all evidence plus REPRODUCIBLE | Source review accuracy is outside artifact reproducibility |
| Cross-protocol signature | Distinct signed ARCHCERT_RELEASE_PERMIT kind and versioned payload | Administrative trust selection remains required |
| Replay/freshness | Bind exact invocation/source/artifact/policy/authority | Exact-byte replay allowed; expiry/revocation NOT IMPLEMENTED |

This is engineering self-validation under a shared implementation/authority context.
It is not independent certification and does not replace Genesis / Firstwarden.
Stoneward's exact historical native qualification does not qualify the new output
collection mechanism. Default and simulated tests cannot establish OCI enforcement,
PostgreSQL locking, native deployment or production release authority.
