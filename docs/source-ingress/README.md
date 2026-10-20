# Northgate development source ingress

Build with `cargo build -p archcert-cli -p archcert-gateway-cli`. Run
`./scripts/test-northgate` for the real OpenSSH Git push and adversarial fixture.
It requires Python 3, Git, OpenSSH ssh/sshd/ssh-keygen and a usable current OS
account. The default gateway integration test runs this fixture too; missing
prerequisites fail explicitly. The harness binds loopback, generates temporary
client/host keys, pins the host key, starts a restricted sshd and cleans up.

The deployment contract is:

```text
OpenSSH authenticated public key
 -> authority-owned restrict,command="... archcert-gateway receive --config ... --device-key PUBLIC_FINGERPRINT"
 -> SSH_ORIGINAL_COMMAND = git-receive-pack 'company/project.git'
 -> exact actor/device/project/repository grant
 -> private per-submission quarantine
 -> bounded Git pack + original ArchCert source validation
 -> immutable accepted source / structured ingress evidence
```

The authority configuration is strict JSON. See the executable fixture for a
complete runnable configuration and SSH server settings. Use canonical private
mode-0700 store directories and private mode-0600 operator configuration outside
all target-controlled paths. Use a dedicated service account with only restricted
keys and no ambient signing/runtime credentials. Install public keys only; host
and client private SSH material are managed by the operator/client, not ArchCert.
Do not enable password/keyboard authentication, user rc/environment/PTY/subsystems,
agent/X11/TCP/Unix forwarding or additional unrestricted keys. Set authentication,
startup, unused-connection and login limits as shown in the fixture. OpenSSH itself runs the fixed
forced command using the account command interpreter; candidate text never enters
that interpreter. No target script or repository hook runs on the gateway host.

The exact virtual route is authority-provisioned. With a configured endpoint:

```sh
git remote add archcert git@cert.example.internal:company/project.git
git push archcert HEAD
archcert source show SUBMISSION_UUID --store /authority/northgate-store
archcert certify --source-submission SUBMISSION_UUID \
  --source-store /authority/northgate-store --snapshot EXPECTED_SOURCE_SHA256 \
  --project PROJECT_UUID --repository REPOSITORY_ID \
  --workspace-root /authority/workspaces --profile python \
  --image python@sha256:AUTHORITY_PINNED_DIGEST \
  --docker /absolute/docker --endpoint unix:///authority/rootless.sock \
  --authority-config /authority/commands.toml \
  --development-key /authority/signing/development.der \
  --public-key /authority/signing/public.hex --output /authority/evidence/new
```

Push output says SOURCE ACCEPTED or SOURCE INCOMPLETE_EXTERNAL_SOURCE. It does not
report test/build/policy/certificate success. The later CLI call separately loads
and verifies immutable bytes, then executes the existing development chain under
its own authority. Ravenport additionally admits separate authenticated durable
certification jobs; see [operations](../architecture/RAVENPORT_OPERATIONS.md). The source
store is reusable across separately selected authority/execution/policy requests.

With the existing rootless OCI environment and pinned image:

```sh
ARCHCERT_TEST_DOCKER=/absolute/docker \
ARCHCERT_TEST_ENDPOINT=unix:///authority/rootless.sock \
ARCHCERT_TEST_IMAGE=python@sha256:AUTHORITY_PINNED_DIGEST \
./scripts/demo-northgate
```

The demo pushes the controlled historical fixture and Bottle through SSH, compares
exact identities, signs/verifies the controlled result and confirms unchanged
Bottle policy rejection. Public evidence is retained under development/. Private
SSH/signing keys remain temporary outside the source store and are destroyed by
harness cleanup. The demo refuses to overwrite retained evidence.

Controlled external resolution is a separate operator action:

```sh
archcert-gateway resolve ORIGINAL_SUBMISSION_UUID --config /authority/resolution.json
archcert source show NEW_SUBMISSION_UUID --store /authority/northgate-store
# A later certify request uses NEW_SUBMISSION_UUID and its new expected digest.
```

The private JSON configuration names `store`, `resolver_actor`, `parent_submission`,
`parent` (project, repository, exact identity), optional `lfs_root`, `lfs` grants
(path, SHA-256, size), and `submodules` grants (path, accepted child submission,
scoped exact source). `scripts/demo-northgate-resolution` contains a complete
runnable example. The LFS directory is private mode 0700, with mode-0600/0400 regular
single-link object files named by lowercase SHA-256. Provision it through an
operator-controlled channel. Candidate paths/URLs never choose storage locations.
The adapter verifies every digest/size and child identity before publishing a NEW
complete snapshot. The original remains incomplete and immutable. Configuration
and acquisition files are no longer needed afterward.

Run `./scripts/demo-northgate-resolution` with the same explicit OCI environment
for actual authenticated pushes, controlled LFS/submodule resolution, independent
Python identity reproduction, actual OCI reads of resolved source, development
signing and offline verification. It removes acquisition files and stops SSH before
execution. Public evidence goes to development/resolved; existing evidence is never
overwritten. `ARCHCERT_DEMO_OUTPUT` and `ARCHCERT_RESOLUTION_OUTPUT` can redirect
fresh demonstration output to an operator-selected directory.

Initial limitations: one session per store, finite local development retention,
self-contained packs, one create-only branch per push, a single selected-commit
shallow declaration, no branch-history certification, no durable jobs/database,
no HTTPS/embedded SSH server and no automatic remote LFS/submodule acquisition or
Git LFS Batch API server. Unresolved pointers/gitlinks remain incomplete and cannot
run or qualify for issuance. Resolved complete child snapshots can be reused;
recursive implicit fetching is unsupported. See ADR-0033 for canonicalization,
credential boundaries and recursive verification limits.
