# Controlled Rust image provisioning

This is authority tooling, explicitly selected outside target source. It is never
discovered as a repository execution request. The base is pinned Rust 1.99.1;
provisioning installs rustfmt/Clippy, Python 3, Git and cargo-deny 0.20.2. Copy only
reviewed public Cargo registry/cache/index and RustSec advisory data into a fresh
private context under ignored target/, together with this Dockerfile and launcher.
Fetch Linux dependencies with `cargo fetch --locked --target x86_64-unknown-linux-gnu`
before copying the public cache. Do not copy credentials/configuration from Cargo
home. Pack only those `registry/` and `advisory-dbs/` trees into
`public-cargo-cache.tar.gz` at the context root. This avoids expensive per-file
Docker context imports. Advisory data must be readable without fetching under
denied runtime network. Retain its exact Git revision, archive SHA-256 and cache
inventory in the run evidence. The launcher keeps locks/global-cache state in
writable sandbox Cargo home and links the read-only public registry/advisory trees.

Build with an independently provisioned rootless Docker daemon, publish to an
explicit development registry and resolve the resulting repository@sha256 digest.
Use that exact immutable reference in the external authority grant. A local build
tag or mutable latest reference is insufficient. Installing packages at image
provisioning time is not hermetic image reproduction; the final image digest is
mandatory evidence. Package repository availability and supply chain remain trusted.

The launcher pins offline Cargo, warnings-denied rustdoc, finite compiler jobs and
writable /work target output. Cache/toolchain are image-owned read-only data; no
host bind mount, new runner environment feature or runtime network permission is
needed. Target build scripts/tests run only under the existing OCI boundary.
Workspace tests that require live host services remain separate opt-in regressions.

The authority image is a development engineering input, not a Stoneward-qualified
new toolchain, artifact-binding release or Genesis trust root.
