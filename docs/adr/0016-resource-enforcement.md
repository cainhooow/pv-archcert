# ADR-0016: Bounded hostile resource consumption

Status: Accepted for Milestone 3.

Authority validates finite policy before setup. Defaults: 30 s target wall-clock,
one CPU quota, 256 MiB cgroup memory, no swap, 64 processes/threads, 1 MiB per
stdout/stderr stream and 8 KiB retained prefixes. /work, /tmp and HOME each have
32 MiB tmpfs bounds; /output has 16 MiB. tmpfs also charges cgroup memory, so an
OOM may occur before the sum of per-mount sizes. /work permits execution for build
outputs; other writable mounts are noexec. All are nosuid/nodev. Root is read-only;
core dumps are disabled and open files capped at 256. No writable target disk
layer, bind mount or daemon logging driver is provided. /dev is runtime-managed;
no additional host devices or IPC shared-memory mount is requested.

CPU is a rate quota, not a separate accumulated CPU-time exit cause. Wall-clock
bounds total target work. PID exhaustion can return EAGAIN while a command later
exits zero; do not infer a ProcessLimitExceeded cause from exit or stdout. Only
runtime OOM metadata establishes MemoryLimit; CPU/PID/disk ceilings are also
verified by fixtures. Unknown signals remain a conventional exit>=128 observation.

Controller uses nonblocking fixed-size pipe reads, incremental SHA-256 and bounded
prefix storage. A flooding stdout cannot starve stderr/deadline checks. Crossing a
stream limit or timeout kills the whole container outside the target, drains for
at most two further seconds, then kills the local CLI if necessary. Controller
kill/control operations have their own 15 s deadline plus 2 s drain, so failed
infrastructure can extend termination latency. Such failure cannot become success.
Sandbox removal is attempted on every return/unwind path. Runtime outages can
prevent termination; independent deployment supervision/orphan recovery is needed.

Source export caps files, directories, payload and archive bytes (10k leaves,
10k nested directories, 64 MiB payload, 96 MiB archive, 8 MiB/file). A bounded
archive writer rejects before growing beyond its limit. Preparation containers
never start target processes. Global admission control, image-cache quotas,
I/O throttling and a persistent supervisor are deferred.

Reference: [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/).
