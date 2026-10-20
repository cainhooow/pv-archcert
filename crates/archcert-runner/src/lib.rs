//! Rootless OCI execution adapter. Hostile commands never execute on the host.
//!
//! Requires an explicitly selected trusted Docker CLI and Unix endpoint, a rootless
//! Linux daemon with cgroup-v2/systemd enforcement and built-in seccomp. No host
//! mounts, Docker context/config credentials or ambient environment are accepted.

#[cfg(unix)]
mod archive;
#[cfg(unix)]
mod docker;
#[cfg(unix)]
mod process;
#[cfg(unix)]
pub use docker::{DockerRootlessRunner, DockerRuntime};
