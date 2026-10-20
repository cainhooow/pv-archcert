# Rootless development execution

This emits ENGINEERING_EXECUTION_EVIDENCE. Exit zero means execution completed
successfully, with cleanup; it does not mean validation passed or certification.
Use a dedicated rootless Linux daemon with cgroup v2/systemd and builtin seccomp.
A Unix controller may use an explicit local Unix tunnel. No host paths are mounted.
Rootful Docker/Desktop configurations that fail preflight have no bypass.

Provision a credential-free image before jobs and record its immutable RepoDigests
value. It needs /usr/bin/env and approved executable families; volumes/ONBUILD hooks
reject. No project Dockerfile, automatic pulls or dependency installation occur.
The operator approves supply chain and image contents independently of its digest.

## Unit/default gates

```bash
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo deny check
./scripts/check-architecture
```

These are STATIC / DEFAULT GATES. Fifteen OCI tests are explicitly ignored here.
The architecture test is also part of the default workspace tests.

## Live OCI gates, opt-in

```bash
ARCHCERT_TEST_DOCKER=/usr/bin/docker \
ARCHCERT_TEST_ENDPOINT=unix:///run/user/1000/docker.sock \
ARCHCERT_TEST_IMAGE='python@sha256:AUTHORITY_APPROVED_DIGEST' \
./scripts/test-live-oci
```

This runs all fifteen tests serially and fails on missing settings/prerequisites.
LIVE OCI GATES — NOT RUN IN STANDARD CI. Use the same pinned image and explicit
endpoint for independent cleanup queries. The simulator tests use trusted host
/usr/bin/python3 and never execute project code. Run default and live suites
sequentially to avoid competing resource-exhaustion fixtures/compiler workloads.

Set `ARCHCERT_TEST_EVIDENCE_DIR` to a new directory under ignored `target/` to
retain each successful execution's bounded JSON evidence, including runtime
identity and captured fixture observations. Files use fresh execution UUID names
and create-new writes; no existing output is replaced. These are engineering test
artifacts, not durable Ravenport publication or certification evidence by themselves.

Live tests exercise canary exclusion, source read-only behavior, absent sockets,
loopback-only network/no-route assertions, UID/capability/seccomp state, actual
cgroup limits, OOM/PID/tmpfs exhaustion, deadlines/descendants, binary output and
cleanup. A harmless host-only marker at /etc/archcert-host-only-marker on the
Linux daemon host strengthens the filesystem probe. Verify a numeric HTTP canary
outside isolation before negative network tests; do not use actual secrets.
See [native qualification](LINUX_QUALIFICATION.md) for the complete deployment
checklist. Colima development results do not qualify native production Linux.

Stoneward extends the suite with per-path tmpfs exhaustion, observed CPU throttling,
process churn/nested shells, double-fork descendants, IPv4/IPv6 TCP/UDP route denial
and a positive private loopback exchange. The IPv6 fixture reports AF_INET6
availability and namespace address/disable observations. Available sockets must
fail numeric external TCP and UDP probes with no-route errors, including link-local
and metadata addresses. An unavailable protocol is reported as unavailable.

Process checks observe UID/GID, supplementary groups, UID/GID mappings, CapEff,
CapPrm, CapBnd, NoNewPrivs and Seccomp. setuid/setgid denial is a representative
privilege probe; it does not independently attribute denial to builtin seccomp or
prove every elevation path blocked. Every execution independently checks both
container and preparation-image absence afterward using a cleared CLI environment.

## Project requests and authority setup

```bash
cargo run -p archcert-cli -- config-check --file config/archcert.toml.example
cargo run -p archcert-cli -- source inspect /absolute/project/.git FULL_COMMIT \
  --project AUTHORITY_PROJECT_UUID --repository registered/project

cargo run -p archcert-cli -- run \
  --git-dir /absolute/project/.git --commit FULL_COMMIT \
  --snapshot EXPECTED_SOURCE_SHA256 \
  --project AUTHORITY_PROJECT_UUID --repository registered/project \
  --workspace-root /absolute/private-mode-0700-root \
  --profile rust --image 'approved-rust@sha256:AUTHORITY_APPROVED_DIGEST' \
  --docker /usr/bin/docker --endpoint unix:///run/user/1000/docker.sock \
  --config config/archcert.toml.example
```

The operator's --profile/--image creates one authority registry entry; project TOML
may only request a registered profile. Development catalog IDs: python (python3),
rust (cargo/rustc), node (node/npm/pnpm/corepack). Names do not attest availability
or versions. Evidence explicitly records toolchain NotObserved and observed client/
server/runtime identities, without executable attestation. Operator/runtime flags
must never be populated from untrusted project configuration.

config-check and run share the production parser. Schema 1, every supported field,
defaults and limits are documented in the tested example. Unknown schema/fields,
profiles, duplicate names, invalid argv/cwd and authority overrides reject. TOML
cannot supply image, endpoint, network, mounts, privilege, environment or limits.
config-check checks the development catalog without proving a provisioned runtime.
An external --config file is a development request; it is not source provenance.
Authority-required steps are composed by application types before project steps;
this development CLI currently supplies no mandatory policy by default.

For direct operator argv, omit --config and use:

```text
--working-directory /source -- python3 /source/project_cli.py --version
```

Literal arguments have no shell parsing. Each resolved step receives a fresh
source materialization and sandbox. /source remains immutable; /work, /tmp,
/output and /home/archcert are private bounded tmpfs. Mutable builds must explicitly
prepare a copy inside isolation and use offline dependencies. Artifact export is
not implemented. The CLI collects selected steps and exits nonzero on target,
setup, infrastructure or cleanup failure, preserving evidence where available.

## Reproduce the Bottle demonstration

Trusted test preparation is manual and outside ArchCert. Use fresh directories,
a trusted Git binary/configuration and no project hooks or code execution. The
following acquires packs then explicitly converts them to the supported loose
format; this limitation is visible rather than a hidden source-ingress fallback.

```bash
mkdir -p target/bottle-packs
# Run with a clean trusted Git configuration/environment and no credentials.
git -c core.hooksPath=/dev/null clone --no-checkout --depth 1 --no-tags \
  https://github.com/bottlepy/bottle.git target/bottle-preparation
git -c core.hooksPath=/dev/null --git-dir=target/bottle-preparation/.git \
  fetch --depth 1 origin 8ec5fe29420d14998c0d86885083983eaea8b839
git --git-dir=target/bottle-preparation/.git rev-parse FETCH_HEAD
mv target/bottle-preparation/.git/objects/pack/* target/bottle-packs/
for pack in target/bottle-packs/*.pack; do
  git --git-dir=target/bottle-preparation/.git unpack-objects < "$pack"
done
mkdir -m 700 target/bottle-workspaces
```

Confirm fetched commit equals the requested full ID. No checkout/build/test runs
on the host. This is not authenticated ArchCert Git gateway provenance. The local
repository may contain unrelated objects; ArchCert reads only the selected closure.

ArchCert's trusted execution path starts with these commands (run from repo root;
substitute absolute runtime/endpoint inputs for your dedicated environment):

```bash
cargo run -p archcert-cli -- source inspect \
  "$PWD/target/bottle-preparation/.git" 8ec5fe29420d14998c0d86885083983eaea8b839 \
  --project 00000000-0000-4000-8000-000000000001 --repository bottlepy/bottle

cargo run -p archcert-cli -- run \
  --git-dir "$PWD/target/bottle-preparation/.git" \
  --commit 8ec5fe29420d14998c0d86885083983eaea8b839 \
  --snapshot e3f098f88ca986831b531f2f055c76513ad55360785d81f5f43c34a4d98c92b0 \
  --project 00000000-0000-4000-8000-000000000001 --repository bottlepy/bottle \
  --workspace-root "$PWD/target/bottle-workspaces" \
  --profile python \
  --image python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f \
  --docker /usr/bin/docker --endpoint unix:///run/user/1000/docker.sock \
  --config docs/runner/BOTTLE_REQUEST.toml
```

source inspect must reproduce the expected independent digest. The Bottle request
runs only python3 /source/bottle.py --version. Expected development observation:
Completed, exit 0, stdout bytes for 0.14-dev followed by newline, no test coverage
or certification claim. The operator must first provision the exact pinned image.
No undocumented Python orchestration is needed. M3 historical raw evidence remains
BOTTLE_DRY_RUN.json; the M3.5 command/result is retained in
[BOTTLE_DRY_RUN_M3_5.json](BOTTLE_DRY_RUN_M3_5.json) and the M3.5 report.

Inspect only authority job-labelled objects after execution:

```bash
/usr/bin/docker --host unix:///run/user/1000/docker.sock container ls --all \
  --filter label=archcert.owner=execution-v1
/usr/bin/docker --host unix:///run/user/1000/docker.sock image ls \
  --filter label=archcert.owner=execution-v1
```

Require no remaining job objects and an empty workspace root. Cleanup failure is
explicit; worker crashes/runtime outages still need future durable reconciliation.
Do not prune unrelated runtime objects. No secure media-erasure claim is made.
