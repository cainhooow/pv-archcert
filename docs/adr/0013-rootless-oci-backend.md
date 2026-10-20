# ADR-0013: Rootless Docker CLI as the first OCI adapter

Status: Accepted for Milestone 3 development execution.

Use the installed trusted Docker CLI with structural argv and no shell. This
avoids introducing a large daemon-client dependency before the contract settles.
The adapter supplies an absolute executable, explicit Unix endpoint, empty private
Docker configuration, cleared client environment, bounded binary pipes and control
operation deadlines. Docker contexts, user config/proxies/credential helpers and
ambient DOCKER_HOST do not select authority. No automatic image pull or build of
project Dockerfiles occurs. CLI JSON/API-version variability is a fail-closed
compatibility limitation; a typed Engine API adapter remains possible.

Preflight requires Linux, reported rootless operation, cgroup v2/systemd, memory,
swap, PID and CPU-quota support, built-in seccomp, runc and no runtime warnings.
There is no rootful/development bypass. Failure means NOT_PROVEN, not isolation
success. Stop-state inspection checks actual authority controls before start.

Target user is fixed UID:GID 10001:10001. Container root is a namespace identity,
not host root; even container root is unnecessary here. Rootless daemon and target
use subordinate user mappings. Containers share the Linux kernel; they are not
virtual machines. Default seccomp (reported builtin) is required; no complex custom
profile is introduced. Default proc masks remain runtime policy. Rootless mode
and seccomp reduce exposure; neither proves escape resistance.

Docker daemon, CLI, containerd, runc, dependencies and kernel belong to the trusted
host infrastructure. Production needs dedicated Linux runner identities/hosts
without authority secrets. Tests used rootless Docker inside an isolated Ubuntu
Colima VM on macOS, not Docker Desktop and not native bare-metal Linux. VM-level
separation is additional to the tested Linux container controls.

References: [rootless operation](https://docs.docker.com/engine/security/rootless/),
[rootless cgroup limits](https://docs.docker.com/engine/security/rootless/tips/#limiting-resources),
[default seccomp](https://docs.docker.com/engine/security/seccomp/).
