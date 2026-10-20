# ADR-0018: Immutable source layer, writable bounded work

Status: Accepted for Milestone 3; extends the best-effort handoff in ADR-0010.

The Docker adapter never binds a diagnostic materializer path or exposes a source
directory FD to the target. MaterializedDirectory exports bounded owned bytes
through its held CLOEXEC directory descriptor, rechecking names, directory set,
original inodes/device, no-follow file/link bytes, modes and canonical identity.
Rename anchoring and post-handoff mutation rejection have regressions. There is
no source store or cleanup parent in this capability.

An authority-generated tar contains only source/, expected directories, files
and uninterpreted links. Source goes to an unstarted preparation container from
a locally provisioned digest-pinned authority image. The controller commits its
source layer to a random labeled job image. It then creates the target with a
read-only root filesystem. Before starting it, the controller copies /source out
as a bounded archive, parses without host extraction, reconstructs canonical
schema 1 and directory/mode sets, and checks the accepted source hash. Host source
is checked again. No target process exists during copying/verification.

Source files/directories are 0444/0555 (preserving executable semantics), owned by
10001:10001. /source is part of the immutable image/root view, not a host mount;
read-only root prevents chmod/write even by file owner. Image-declared volumes
and ONBUILD hooks reject; image entrypoint/healthcheck are overridden. Images
must be provisioned by authority, with no credentials and suitable /usr/bin/env
and toolchain binaries; the project cannot select them. Base-image trust is a
prerequisite, not established by merely checking an image digest.

/work, /output, /tmp and /home/archcert are separate bounded private tmpfs mounts.
No host mounts are used at all. /output is not exported as an artifact yet. Builds
requiring a writable source copy can explicitly copy /source to /work from inside
the sandbox and run there; those mutations do not alter accepted identity. No
implicit package installation, source rewriting or output/source conflation occurs.
Runtime-generated hosts/hostname/resolver files and proc/sys/dev namespaces are
container infrastructure, not mounts of host /etc, /tmp, HOME or source storage.

Both containers and the job image carry random authority job/workspace labels.
Cleanup force-removes containers and removes the job image; source cleanup remains
with the caller. Lost replies and crashes can leave labeled orphans; no broad
runtime prune or deletion of other jobs is allowed. Persistent reconciliation,
secure media erasure and image-cache storage quotas are deferred. Job image IDs
are immutable local config/content identities; unlike the approved base image,
they have no registry repository digest because they are never pushed.

References: [stopped container archive copy](https://docs.docker.com/reference/cli/docker/container/cp/),
[commit excludes volumes](https://docs.docker.com/reference/cli/docker/container/commit/).
