# Native Linux M6 release qualification

Status: **QUALIFIED for the exact profile below; M6 — Ironcrest — COMPLETE**.
Acceptance date: October 30, 2026 (America/Sao_Paulo). Native execution timestamps
are retained in UTC. Development signing and engineering assurance limits remain.

## Scope and environment

The qualified mechanism is ADR 0048's single regular-file Rust release path,
including recipe `rust-single-file-release-v1/1.0.2`, the separately identified
collector, independent A/B execution, immutable publication, recovery and the
offline artifact gate. The authority ran directly in the existing native KVM Linux
guest. This scope is separate from the historical October 20 Stoneward report.

| Property | Observed value |
| --- | --- |
| Host / authority account | `vps11530.integrator.host`; UID:GID `1001:1001`; SSH alias `archcert-stoneward` |
| Distribution / kernel | Ubuntu 26.04.1 LTS; Linux `7.0.0-31-generic`; x86_64 / KVM |
| Docker / endpoint | Dedicated rootless Docker 29.1.3; `unix:///run/user/1001/docker.sock` |
| Runtime components | runc 1.4.0-0ubuntu1; containerd 2.2.2; rootlesskit 2.0.2; slirp4netns 1.3.3; docker-init 0.19.0 |
| Cgroups / security | v2, systemd; builtin seccomp; rootless and private cgroup namespaces |
| AppArmor | Host enabled; target AppArmorProfile empty; AppArmor confinement is not established |
| Filesystem | Local ext4; Docker overlayfs; authority files under a private owned directory |
| Build / collector identities | Target `10001:10001`; separate unprivileged collector `10002:10002` |
| Toolchain | Rust/Cargo 1.99.1; `x86_64-unknown-linux-gnu` |
| Control profile | Existing release `large-offline-image-v1/60s`; historical default remains 15 seconds |

The existing limits remain 900 seconds per target step, two CPUs, 8 GiB memory,
256 tasks, 6 GiB scratch per mount and one nonempty artifact of at most 64 MiB.
Source stays read-only and target networking stays denied. No rootful daemon,
privileged fallback, host mount or production signer was used. Missing cpuset and
block-I/O controls remain the existing explicit warning allowlist and are not
enforcement claims. Reported runtime identity is an observation, not attestation.

The approved Rust image is
`localhost:5000/archcert-release-rust@sha256:c981c9022a523195edc8d74b7a7098671c7d3bc029502bab3317b4412c9ecc1e`.
Its authority dependency inventory SHA-256 is
`e6e6c4d79d456e95da5168b8978fafee203191a81c30ea5424c32dc220e3e6e6`;
the unchanged Rust toolchain inventory SHA-256 is
`f22d5e4e9ced367e774ce5bc140d9e6b1235c1882fec80d011044851f3ae6369`.
The unchanged collector SHA-256 is
`5f108f041297e89ff10c6c15d2618c0d941c6cd36022905d72f11fb23734c215`.
These inventories are provisioning assertions. The image refresh changes only
public advisory data and its fetch metadata; it does not reinterpret an older
image, recipe, source result or permit.

## Executed qualification

All seven standard gates passed, with 262 workspace tests passing and 37 opt-in
tests ignored across 66 harnesses. The opt-in groups were separately executed:
16 real PostgreSQL cases, 15 OCI cases, three runtime reconciliation cases, two
release runner cases and one historical authority challenge. Protobuf (13 cases),
artifact storage (two cases), real Northgate SSH and the fixed Rust guard passed.

The unchanged generic OCI, PostgreSQL and historical Python challenge groups ran
at `2e4bd47`. The standard gates and Rust release/collector/lifecycle groups ran
again at `71dbcf0` with the refreshed image. That commit changes provisioning
documentation only; each run retains its own source and environment identities.

The release runner executed independent equal-output Rust builds and independent
random-output builds, detecting real nondeterminism. Malicious toolchain and target
requests did not replace the authority selections. Eleven direct collector cases
covered valid bytes, source/host/socket link escapes, directories, FIFOs, sockets,
missing or oversized output, extra output and mutation during transfer. The target
could neither access the collector's output channel nor signal its separate UID.
Every direct probe confirmed container and collector absence afterward.

The authenticated controlled source/build/permit lifecycle passed seven actual
SIGKILL checkpoints: input, A, B, comparison, payload, signature and permit upload.
Accepted roles and invocation identity survived restart without another accepted
build. Distinct A/B execution and workspace IDs, equal SHA-256/size, successful
cleanup and independent object readback were recorded. Substituted artifact bytes
failed the offline gate. Fixture recovery and exact ArchCert source validation
have separate source and certificate identities.

Representative commands actually executed, with the image, endpoint and database
selected outside target data, were:

```sh
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" CARGO_BUILD_JOBS=1 cargo doc --workspace --no-deps --locked
cargo deny check
./scripts/check-architecture
./scripts/test-ravenport
./scripts/test-live-oci
cargo test -p archcert-runner --test release --locked -- --ignored --nocapture --test-threads=1
```

The opt-in commands received explicit `ARCHCERT_TEST_DOCKER`,
`ARCHCERT_TEST_ENDPOINT`, `ARCHCERT_TEST_IMAGE`, `ARCHCERT_TEST_RUST_IMAGE` and
`ARCHCERT_TEST_DATABASE_URL` as appropriate. The existing release and self-validation
harnesses used their required explicit image/inventory/key/scope arguments; exact
argv and exits are retained with the evidence. The private Rust authority recipe
additionally selects `--jobs 1` for rustdoc, retaining warnings denial and every
mandatory check. Private `TMPDIR` and non-group-writable authority ancestors are
part of this observed host setup. The local development inspector received verified
loose Git representations; authenticated ingress still used real packed SSH pushes.

Actual command/exit records remain under ignored `target/m6-native-closure/` and
`target/m6-native-refreshed/`. The prior closure audit and all failed attempts were
preserved. The historical controlled review lifecycle retains its original
16-SIGKILL evidence and source identity; this continuation did not restart that audit.

## Exact-source acceptance evidence

Acceptance-source commit: `71dbcf0161ad676cf5012698019e0182fd674743`. Its tree is
`a85725f55ee9c509b5c734916561473b4faec7fb` and its snapshot SHA-256 is
`f5b1c48512bc3f29e00a2b4d2c7a2f9438be0c5c854d62ec2d54357250b2ffb3`.
The 299-file exact source passed all seven required sandbox steps. Its source
certificate payload identity is
`aee97661d9314a2034d15496cb7541c7f5d18a56fac3127091eeab97b9e8b16b`; selected-key verification returned
`SIGNATURE VALID / CERTIFIED / EXACT_SOURCE`.

Canonical knowledge was 1,879,359 bytes; impact 649,178 bytes; package 567,008
bytes; request 568,928 bytes. The package included 128 files and excluded 171;
its 65,536 excerpt bytes excluded 2,430,012 source bytes. Coverage remained
`PARTIAL_ACCEPTABLE`. Extraction, impact and packaging took 2,241, 90 and 636 ms
respectively; the complete source harness took 637.826 seconds.

Native Build A execution: `3402475e-6af4-40a7-98b3-4486be7d2f91`;
workspace `23e8d6ed-c361-4829-893a-3710a8f7f019`.
Native Build B execution: `c0115375-7dde-430e-bb26-87054fdf866b`;
workspace `b795c2f5-caa0-484a-b810-58eeeaff4909`.
Both completed with confirmed source/runtime cleanup and produced 5,251,512 bytes
with SHA-256 `c567746b88edf2996ebd445f1cfa4f02d20b17e68bc64df1d4c595b73564585c`.
The result was `REPRODUCIBLE`. Recipe identity:
`d9b072f1c7f1c76d1049b62764838c6ede6c2c8ad009183a8e911ba57d35333f`; environment identity:
`fba04309393d45c7566fbaae14c1c8a2d7167f084a5085bb60e3ac5118565f91`.
The Release Permit payload identity is
`1a0571811042357c0be9eba35872982a5fbd03174d9096387ae5b146c022dc37`.

All nine immutable roles passed independent digest/size readback, and completed
permit recovery succeeded after deleting its private key. Source verification and
release authorization passed with a cleared environment and stopped PostgreSQL
and rootless Docker. Six scope/key/content/protocol substitutions were rejected.
Execution-container and preparation-image inventories were empty before shutdown.

The source validation uses the existing bounded Rust engineering policy, local
exact replay and explicit `PARTIAL_ACCEPTABLE` context. Excluded context remains
excluded. Its fixed Rust challenge covers bounded named Cargo dependency closures
and a read-only source mount. It establishes no universal architecture proof or
semantic bug-detection guarantee. Source and release signatures use separately
selected development keys; the private keys are destroyed before public-only
verification. Accepted release roles are independently rehashed on readback.

The offline checks used a selected public key and actual artifact bytes. Both
positive gates and wrong project, repository, key, artifact, rehashed signed payload
and source-certificate-as-permit rejections passed with a cleared environment
and the dedicated database/runtime stopped. Later source commits require their
own runs; an earlier certificate cannot certify this document's later source bytes.
Final-source outputs and retirement records remain separate working evidence.

## Failures and recovery boundaries

The first native OOM probe reported Terminated instead of ResourceLimit. Its exact
cause remains NOT PROVEN. Five fixed diagnostic samples recorded runtime OOM,
ResourceLimit/MemoryLimit, exit 137 and destroyed cleanup; an unchanged full rerun
passed all 18 OCI/reconciliation cases. This is a retained observation limitation,
not a claim of universal deterministic OOM reporting.

The initial image's advisory update archive had normalized `.git/FETCH_HEAD` to
the Unix epoch. A real exact-source run on `2e4bd47` consequently reached
NOT_ELIGIBLE, with no certificate and SUCCEEDED cleanup. Rustdoc and the other
checks passed. The replacement image preserves metadata from a real RustSec fetch
at revision `2295466c4e9df26647fd67d8fa1c705ac2fc7f81`; its frozen offline canary
passed before a fresh source session. No freshness, network, resource or policy
check was relaxed. Commit `71dbcf0` records the provisioning requirement.

Authority preparation also exposed SSH StrictModes rejecting temporary keys under
`/tmp`, group-writable checkout ancestors, a parallel rustdoc output collision and
the development inspector's loose-object requirement. Private owned directories,
serial rustdoc and verified missing loose representations addressed those inputs.
The original attempts remain retained. Temporary audit transfer/copy ordering
errors were corrected before execution; existing Git objects were not replaced.
Unknown creation remains fenced, and no pending gate or non-expiring claim was
cleared to manufacture another execution or signing eligibility.

## Limits

Container escape resistance, independent certification, production signer custody,
host reboot/power-loss recovery, revocation, transparency, multi-host qualification,
other Linux/runtime/toolchain profiles and universal reproducibility remain
NOT PROVEN or NOT IMPLEMENTED. Containers share the guest kernel. The deployment
caller must deploy the same verified bytes; external platform handoff is outside
this local gate. M7/M8 completion and Genesis / Firstwarden remain outside this task.

This is engineering self-validation under a shared implementation/authority context. It is not independent certification and does not replace Genesis / Firstwarden.
