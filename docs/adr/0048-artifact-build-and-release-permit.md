# ADR 0048: Artifact binding, independent builds and release permits

Status: Accepted design; implementation and qualification tracked separately.
Date: October 22, 2026. Extends ADRs 0006, 0011–0018, 0025–0027 and 0035–0040.

## Context

Canonical M6 Ironcrest must authorize exact deployable bytes. A schema-1 source
certificate authenticates EXACT_SOURCE claims only. Historical `ironcrest` review
journals, profiles, manifests and policies retain ADR 0045 semantics. Genesis /
Firstwarden remains NOT STARTED. M7/M8 are not redesigned or declared complete.

## Decision

Introduce a separate versioned release namespace and PostgreSQL journal. Admission
freezes a canonical build input manifest identifying project/repository/source,
the cryptographically verified source certificate, the authority recipe, execution
profile/image, authority-prepared public dependency bundle, pinned toolchain,
output contract, release policy and authority public key. Its digest identifies
the invocation. Identity never comes from filenames, branches, tags or job names.
Authority composition selects all capabilities outside the target. Target TOML
cannot provision the recipe, policy, signer, dependency acquisition or runtime.

Initially support one nonempty regular-file Rust executable, bounded to 64 MiB.
The authority recipe fixes offline locked release Cargo, a single authority-selected
binary name, no normalization, source at /source, fresh output at /work/target,
finite resources, denied network and no host mounts or environment inheritance.
The explicit `large-offline-image-v1/60s` runtime profile gives each control
operation a 60-second deadline, recorded in runtime observations and the build
recipe. Historical default construction retains 15 seconds. The source-check CLI
may select this profile explicitly with `--large-offline-image`; target execution
budgets, command authority and historical recovery defaults remain unchanged.
Toolchain and dependency inventory digests are authority provisioning assertions
bound alongside the image digest; they are not independent runtime attestation.
Dependency preparation happens before image provisioning, never during the build.

Execute two separately claimed, non-expiring attempts A/B in distinct sandboxes
with fresh source workspaces. No automatic retry or claim takeover exists. Unknown
execution after process death blocks conservatively; it cannot grant another
execution. Accepted evidence resumes without execution. The initial release path
trades availability for this stronger no-repeat rule and does not reuse Ravenport
lease expiry as permission to run again. Standalone orphan resources are retained
for exact operator investigation; unknown cleanup prevents signing.

The isolated authority launcher runs Cargo with literal arguments. Build logs go
to stderr. After selecting output with descriptor-relative no-follow traversal,
it copies one regular file to /output/artifact and signals readiness, retaining
PID 1 until collection. The daemon archive API omits live tmpfs data. The runner
therefore invokes a fixed authority Python reader through the isolated runtime,
with a literal /output/artifact selector and separate bounded binary channel.
Descriptor-relative no-follow/nonblocking opens, exact directory entries, regular
file/size checks and before/after inode/mode/size/mtime/ctime checks reject links,
special files, extra entries and concurrent mutation. The controller independently
hashes the returned hostile bytes. Collection does not interpret target status or
filename text. After successful transfer, a runtime signal releases the waiting
launcher so ordinary runtime exit status and whole-container cleanup can complete.
The reader shares the sandbox and can be disrupted by hostile descendants; failed
or uncertain collection is infrastructure uncertainty, never a positive verdict. These bytes are hostile output, not authority instructions. Container and
source cleanup must succeed before evidence can support a permit. Existing
execute behavior stays separate. This added mechanism needs live OCI regressions
and native requalification; Stoneward's historical qualification is not extended.

Every accepted role is create-only: stage exact digest/size, upload immutable bytes,
verify readback, then accept transactionally. Build artifacts and canonical results
retain invocation, attempt/execution, source/recipe/environment and output bindings.
Reproducibility compares independently accepted artifacts by SHA-256 and size:
REPRODUCIBLE, NON_REPRODUCIBLE or INCONCLUSIVE. Successful unequal bytes mean
NON_REPRODUCIBLE; missing/infrastructure-impaired completion means INCONCLUSIVE.
Only REPRODUCIBLE may proceed. Semantic CLEAR contributes no release authority.

Prepare a small canonical schema-1 ARCHCERT_RELEASE_PERMIT payload under a separate
signature domain. Bind source/certificate, invocation/recipe/environment, artifact,
reproducibility evidence, exact release policy and authority/key. The permit ID is
SHA-256 of the canonical payload, outside its own preimage. Persist exact payload
before signing. Reconstruct and compare on recovery. Ed25519 signs exact canonical
bytes, with strict selected-key verification before immutable envelope publication.
The existing development signer remains DEVELOPMENT ONLY. No new crypto or source
certificate schema is introduced. At most one payload and accepted envelope can
exist for the same project/invocation. Repeating the identical deterministic signing
operation is permitted; a different message under that invocation is rejected.

An offline deployment gate requires the separately trusted permit key, explicit
expected project/repository and the actual artifact bytes. It verifies structure,
signature/domain, permit digest, scope and artifact SHA-256/size. A source certificate
or a valid permit for different bytes cannot authorize deployment. This is an
explicit local gate, not integration with an external deployment platform. No
expiration, revocation, production custody or independent certification is claimed.

## Security implications

See [the release threat model](../threat-model/RELEASE_PERMIT.md). Domain/application
remain infrastructure- and signer-free. Only certificate/authority composition
acquires crypto; runner/source/worker/storage do not. PostgreSQL is trusted for
coordination; verified immutable bytes are required even when rows say AVAILABLE.
A digest identifies content, while external selection establishes authority.

## Alternatives and consequences

Arbitrary shell recipes, source-certificate reuse as artifact authorization,
stdout-provided filenames, comparing copied output, normalization of differing
bytes and retry-until-reproducible are rejected. OCI/directory/package formats,
remote build workers, automatic uncertain-execution recovery, reproducibility
across different environments, freshness/revocation and production signers are
future work. Historical schemas/migrations/vectors remain byte-compatible.

## Recipe 1.0.1 and early development compatibility

Recipe 1.0.1 explicitly includes the SHA-256 of the fixed authority collector in
its output contract. Its launcher also describes the collection/completion
handshake accurately. Both script preimages contribute to the new recipe/invocation
identity. This deliberately supersedes experimental 1.0.0 preparation from this
implementation series; no stored manifest, failed run, artifact or permit is
rewritten. Recovery of an old invocation requires its original exact authority
implementation and recipe, or blocks. It never substitutes the current recipe for
the retained version. Previously issued development permits remain verifiable under
the unchanged permit schema and their explicitly selected key. Regression checks
reject a changed collector digest and retain the seven-checkpoint lifecycle for the
new recipe. No historical source certificate, review profile or migration changes.
