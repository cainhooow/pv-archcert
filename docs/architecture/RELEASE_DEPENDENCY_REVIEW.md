# M6 dependency and authority build input review

The release domain/application add no new third-party dependency. The offline CLI
uses the already reviewed Rustix filesystem flags directly for no-follow/nonblocking
artifact reads; Cargo.lock adds that existing package to the CLI dependency edge.
Signing reuses the existing strict Ed25519 and SHA-256 implementation. No crypto,
transport, database or provider capability enters domain/application or the runner.
The architecture guard includes the new release interfaces.

## Tokio security patch discovered during validation

On October 22, 2026, the local RustSec checkout consumed by `cargo deny check`
reported RUSTSEC-2026-0384 against the previously locked Tokio 1.54.0. Its recorded
patched range is >=1.54.1; unaffected versions are <1.54.0. The advisory describes
an Interval/time-driver race on the multithreaded runtime. ArchCert's existing
controller uses `tokio::time::interval` for worker heartbeats, so the affected API
is in the operational graph. The initial advisory gate failed and is retained in
ignored execution evidence. No advisory exception or policy downgrade was added.

A separate dependency commit updates only the locked Tokio patch to 1.54.1 and
its registry checksum `b52fd3255258d26fac7264ab5a76b53c13367136dc011d3d6ad4f8ed070396a3`.
Workspace constraints, features, cryptography, migrations, historical canonical
formats and stored evidence are unchanged. This is an intentional dependency fix,
not a readability change. Historical certificates and runtime evidence retain their
original source/dependency identities; the patch does not reinterpret them.

Primary advisory locations recorded by RustSec are
[the advisory](https://rustsec.org/advisories/RUSTSEC-2026-0384.html) and
[the Tokio fix](https://github.com/tokio-rs/tokio/pull/8692). The advisory web page
was unavailable through the browsing tool during this run. The finding and patched
range above come from the actual local RustSec advisory and Cargo gate output.
Re-run all seven standard gates plus real PostgreSQL and runtime/lifecycle groups
for the updated locked graph. Actual pass/failure counts belong to retained run
records, not this dependency design description.

## Offline authority image provisioning

The release environment binds the exact OCI digest plus independently selected
public dependency bundle and toolchain inventory identities. Version output is an
observation; its inventory is a provisioning assertion, not compiler attestation.
The fixed launcher uses read-only image cache data and new writable Cargo/target
state. It does not inherit host Cargo home, Git credentials or ambient environment.

After a lockfile update, provision the new public crate/cache/index bytes outside
target execution. A development image may layer a reviewed public update archive
onto an already approved image. Retain the base digest, public archive digest,
registry crate checksum and canonical dependency descriptor, then publish and
select the resulting repository@sha256 reference. Never copy Cargo credentials,
configuration, user home or signing files. Updating a development tag does not
change an admitted invocation: recovery must select the original exact image and
recipe, or block. Target builds remain locked, offline and network-denied.

These supply-chain assertions and development images do not establish production
release custody, native execution qualification or Genesis / Firstwarden.
