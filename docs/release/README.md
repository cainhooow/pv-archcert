# Canonical M6 release authorization

Source certification is a prerequisite. It does not authorize deployment of an
arbitrary binary. M6 separately binds exact immutable source and its verified
certificate to one authority-owned offline Rust recipe, two independent fresh
builds, exact regular-file output, deterministic reproducibility evidence and a
small signed Release Permit. See [ADR 0048](../adr/0048-artifact-build-and-release-permit.md)
and the [release threat model](../threat-model/RELEASE_PERMIT.md).

The initial supported artifact is one nonempty regular file, at most 64 MiB,
produced by `cargo build --release --locked --offline --bin AUTHORITY_BINARY`.
The authority launcher, environment, output selector, network denial, limits and
image are frozen in the admitted input manifest. There is no normalization or
project-selected shell recipe. Authority must independently prepare the public
dependency cache and toolchain inventory and approve a digest-pinned image.
Inventories are provisioning assertions, not runtime attestation. Build-time
network is denied. Source stays read-only; each execution has new source and
scratch workspaces. OCI manifests, registries, directories and package formats
are not supported by this version.

## Operator lifecycle

Apply migration 0006 explicitly with migration authority. Historical readiness,
jobs, reviewed admission, source certificates and migrations remain compatible.
Provision a private control-plane configuration and explicit repository grant
using the existing controller `provision` command. Configuration and all keys must
remain outside target source and workspace roots. Development storage is
unencrypted; the local signer is DEVELOPMENT ONLY / NOT PRODUCTION AUTHORITY.

`archcert-controller --config PRIVATE_CONFIG release --help` lists the required
explicit authority parameters: scope/actor, exact accepted source submission,
source certificate and trusted source key/policy, approved image, public dependency
bundle SHA-256, toolchain inventory SHA-256, binary selector, release public/private
key paths, materialization root, Docker executable/endpoint and new export directory.
The source certificate is cryptographically verified before admission, including
exact project/repository/commit/tree/snapshot, policy and selected source key.
It is verified again by permit construction. The release key may differ from the
source key. No semantic response, target TOML or source-store database row selects
these authorities.

The input manifest digest is the admitted invocation identity. For a fixed manifest,
there is one accepted payload/envelope identity per project. Repeat the same command
with the same authority pins to resume. Accepted evidence is re-read and rehashed;
accepted builds are never rerun. Staged references may recover publication only
with the original exact bytes. Missing/corrupt accepted objects block continuation.
Changed source, recipe, policy or key must not reinterpret an existing invocation.

Execution claims never expire or transfer. An interrupted unknown execution with
no recoverable staged result blocks and receives no automatic retry. An unknown
cleanup outcome also blocks a later build or signing. This deliberately conservative
initial profile does not implement remote workers or automatic orphan cleanup.
Never delete unknown runtime resources or clear claims to force a permit.

The strict verdict is REPRODUCIBLE only for two successful independent executions
whose collected artifact SHA-256 and size match. Two completed differing outputs
are NON_REPRODUCIBLE. Missing or infrastructure-impaired completion is INCONCLUSIVE.
Both negative outcomes prohibit preparing a permit payload. The separate source
certificate continues to identify its original immutable source only.

The workflow persists the exact canonical payload before the signer is loaded.
A signature lost during process death may be recreated for those identical bytes.
Verified envelope bytes are uploaded and read back before authorization is reported.
Detailed canonical results and comparison evidence remain separate digest-bound
objects. No logs are embedded in the permit. Exported bytes are convenient copies;
filenames and output directories do not define identity.

## Offline deployment gate

```sh
archcert release-gate release-permit.json \
  --public-key TRUSTED_RELEASE_PUBLIC_KEY \
  --artifact ACTUAL_DEPLOYABLE_FILE \
  --project EXACT_PROJECT_UUID \
  --repository EXACT_REGISTERED_REPOSITORY
```

The gate requires neither PostgreSQL, OCI, source storage nor a private key. It
verifies the distinct permit schema/domain, selected public key, strict signature,
canonical payload identity, project/repository and the actual bounded regular-file
bytes. Source certificates, another project's permit, another key and substituted
artifacts fail. A successful gate reports RELEASE_PERMITTED, DEVELOPMENT ONLY.
The deployment caller must deploy these same verified bytes; an external deployment
platform and its file handoff are not integrated here. Expiration/revocation and
production key custody are NOT IMPLEMENTED. Exact artifact replay is allowed.

## Regressions and qualification

Default application/certificate tests cover identity separation, byte equality,
inconclusive evidence, source/policy substitution, strict parsing, wrong key/scope
and artifact swapping. `scripts/test-ravenport` includes real PostgreSQL release
claim races, immutable publication/recovery and negative comparisons. Synthetic
builder fixtures establish coordination semantics, not execution enforcement.

The opt-in runner release test executes two real deterministic Rust builds and two
real builds with random embedded bytes. `scripts/test-release-permit` additionally
uses authenticated Northgate source, actual source certification, two real builds,
and SIGKILL at seven durable boundaries: input, A, B, comparison, payload, signature
and permit upload. It destroys its temporary private key and repeats the offline
artifact gate, including a substituted-file rejection. Run it against a dedicated
migrated database with explicit `--image`, `--docker`, `--endpoint`, `--dependencies`,
`--toolchain` and a new `--output` below ignored `target/`.

These commands are reproduction instructions, not claims that they passed. Actual
validation is recorded separately. The new collection mechanism and explicit
large-offline-image control profile require native Linux requalification; historical
Stoneward qualification applies only to its documented mechanism and environment.
Colima runs remain development evidence. Canonical M6 completion must not be
inferred from historical `ironcrest` review lifecycle names or prior reports.

This is engineering self-validation under a shared implementation/authority context. It is not independent certification and does not replace Genesis / Firstwarden.
