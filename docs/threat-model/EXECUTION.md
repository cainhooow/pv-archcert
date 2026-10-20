# Hostile execution threat model — archcert-docker-cli-v1

Target repository code, package tools, tests, compilers and descendants are hostile.
Accepted source identity proves bytes, not safety. Target output remains hostile.
Trusted components are ArchCert, its dependencies, approved runtime image and
supply chain, Docker CLI/daemon, containerd/runc, Linux kernel, OS randomness and
private authority filesystem. The daemon is authority infrastructure, never a
service exposed to the target. Compromise of this TCB invalidates isolation.

| Threat | Security property | Mitigation | Remaining risk |
| --- | --- | --- | --- |
| Malicious target command/scripts | Code never runs in the control process/host | Narrow SandboxRunner port; fixed profile; literal argv; only isolated target start | Arbitrary code is intentionally allowed within the sandbox; structural allowlist is not semantic safety analysis |
| Container breakout | Reduced kernel/runtime attack surface | Rootless daemon; unprivileged UID:GID; no capabilities; no-new-privileges; built-in seccomp; private namespaces; read-only root | Shared-kernel vulnerabilities and runtime/dependency bugs are not disproven by tests; gVisor/Firecracker remain future adapters |
| Host filesystem access / escaping source links | No host source-store, database, HOME or other workspace mounted | No bind mounts; descriptor-verified source archive into image layer; archive never extracted on host; source links remain raw bytes | Trusted daemon archive extraction and filesystem/kernel correctness remain prerequisites |
| Credential theft | Authority secrets do not enter target environment/files/FDs | Fixed environment, empty synthetic HOME, private empty Docker config, cleared client env, CLOEXEC source descriptors, no host mounts | Source itself may contain project secrets; trusted worker should still run on dedicated hosts with no signing/control credentials |
| Runtime socket exposure | Target cannot control daemon/other jobs | No socket mount, host networking, device or runtime API capability in request | Runtime/worker compromise bypasses this property; endpoint selected only by authority |
| Metadata/network/host-service access | Execution has no external routes | NetworkPolicy::Denied only, network=none, no ports/links/extra-hosts; loopback-only tests; metadata/DNS/TCP/HTTP negative fixtures | Loopback within one job remains possible; future restricted egress needs separate design; image provisioning is outside target execution |
| Environment leakage / CLI proxy injection | No ambient credentials/proxies/config reach target | env_clear for runtime CLI; remove image ENV values; env -i fixed keys; stopped ENV and argv checks; credential canary subprocess | Trusted image binary may be compromised; target can intentionally construct new environment values from its own data |
| Image substitution / mutable tag | Execution records immutable image identity | Authority profile requires repository@sha256; verify local RepoDigests and ID; pull=never; target uses committed immutable job image ID | Digest is identity, not supply-chain approval; job image is local content ID, not a pushed OCI repo digest; image-cache deletion/replacement by runtime admin is trusted |
| Image-controlled volumes, healthcheck, entrypoint | No unexpected startup code or external storage | Reject VOLUME/ONBUILD metadata; explicit env entrypoint/literal command; disable healthcheck; stopped configuration checks | Authority must approve credential-free image filesystem/toolchain; arbitrary project images are unsupported |
| Source mutation / TOCTOU | Actual isolated source equals accepted canonical identity | Rehash descriptor export after handoff; no diagnostic-path lookup; reconstruct stopped target /source; read-only root/image; recheck host source | Owner/root mutation may reject; immutable-view claim depends on runtime/kernel; original Unix permission seal alone remains insufficient |
| Fork bomb / thread exhaustion | Per-job process count finite | Required cgroup support; pids-limit; fixture reaches EAGAIN; namespace kill and mandatory rm | PID exhaustion need not terminate the command; host-wide admission/process accounting still required |
| Memory exhaustion | Target cannot allocate unlimited resident/tmpfs memory | cgroup memory ceiling, swap disabled; runtime OOM evidence; live exhaustion fixture | Kernel/daemon allocations and global concurrent-job pressure are outside this per-container budget |
| CPU exhaustion / infinite loops | Finite rate and controller wall time | cgroup CPU quota; external timeout; KILL container, not only CLI; target ignoring TERM fixture | CPU quota is rate, not distinct accumulated CPU-limit cause; runtime outage can delay/prevent kill |
| Disk/temp/output exhaustion | Target has no unbounded writable disk layer/log | Read-only root; finite tmpfs mounts, cgroup charge, no daemon logging; bounded archive transfer | Trusted image cache/preparation layers need global quota; inode/metadata/kernel accounting and concurrent job admission require deployment limits |
| Log flooding / ANSI injection | Evidence storage bounded and safe to serialize | Fixed-size nonblocking reads; prefix limits; incremental hashes; stream-limit kill; explicit truncated/complete flags; numeric byte arrays | Unobserved bytes after forced disconnect cannot be hashed; UI must never directly render decoded hostile bytes |
| Child process persistence / signal abuse | Cleanup covers descendants even after detachment | Namespace PID1 exit semantics; external KILL; force-remove entire container; no restart; timeout/detached-child fixtures | Daemon/kernel unavailability or worker crash may leave jobs; restart reconciliation requires a revoked exclusive attempt gate; daemon/kernel outages may keep cleanup blocked |
| Procfs / host process observation | Host process namespace not exposed | Private PID/cgroup namespace, UID10001, capability drop, builtin seccomp/default masks; fixture sees only sandbox PID1 | Some shared-kernel/hardware facts remain visible via proc/sys; no claim of complete host-information hiding |
| Runner evidence spoofing | Target cannot assert success/certification | Controller-built source/argv/runtime status/hashes; false PASS text fixture exits 7; client/runtime exit mismatch fails | Runtime/controller compromise invalidates observations; durable authenticated evidence storage is deferred |
| Cleanup failure / late daemon response / crash | No false successful destruction or certification | UUID names and job/workspace/owner labels chosen before create; bounded explicit cleanup on success/error/unwind; failure separate with evidence | Fatal abort/power loss/outstanding daemon operations can leave labeled orphans; persistent exact-attempt fencing/reconciliation handles confirmed creation; uncertain late creation blocks and secure media erasure remains deferred |
| Authority configuration downgrade | Project input cannot alter isolation/resource authority | Private ExecutionProfile fields; no project deserialization; strict TOML request DTOs; no mounts/privilege/network/env API; stopped config rejection matrix | Authority/operator mistakes and malicious changes to trusted ArchCert code are outside project-input validation |
| Runtime endpoint substitution | Only operator-selected runtime authority is used | Explicit bounded Unix endpoint, absolute client path, env_clear and empty private Docker config; no project context/socket/TLS fields; selected endpoint and reported daemon ID retained in execution evidence | Socket forwarding/replacement and same-UID/runtime administrators remain trusted; observed identity is not attestation and a local socket does not prove native execution |

The worker `doctor` command observes the same required rootless/cgroup-v2/systemd,
builtin-seccomp, resource-support and runc reports as execution preflight. It does
not execute a live enforcement probe or establish full worker readiness. Native
Linux qualification is tracked in
[the qualification report](../qualification/NATIVE_LINUX_RUNNER.md); no native
guarantee is inferred from default tests or runtime-reported configuration alone.

Stoneward's durable worker path requires an exact-attempt persistent execution
gate. Revocation precedes the DB fence while the exclusive gate is held; stale
later steps reject before Docker API access. Runtime reconciliation checks the DB
binding, gate, daemon identity, ownership version and exact job/attempt/execution
labels before removal. Unknown ownership is retained. Busy gates, pending creates,
cleanup errors and disagreement block retry. See ADR 0039 for the single-host
trusted-worker assumptions and why an empty inventory is insufficient.

Execution evidence records the local Unix socket's device/inode/change-time
incarnation. A changed endpoint during execution rejects as infrastructure failure
before target-result classification. This is useful for a directly connected
native daemon restart; a macOS forwarded socket does not attest the remote daemon's
incarnation. AppArmorProfile and /proc/self/attr/current observations report actual
availability/assignment without making AppArmor mandatory or claiming attestation.

## What the tests establish

Unit/mock tests validate policy, argument construction, configuration downgrades,
archive reconstruction/substitution, binary output hashing, runtime deadlines,
cleanup failure/disconnection and panic cleanup. Mock fixtures are trusted runtime
simulators and never execute the requested target on the host.

Real rootless OCI fixtures exercise normal/nonzero exits, false status claims,
binary ANSI output, complete-stream prefix hashes, floods, timeout, ignoring TERM,
detached children, OOM, PID exhaustion, actual CPU/memory/swap/PID cgroup values,
disk bounds, clean environment, host credential canaries, read-only source,
escaping source links, host paths/socket, proc/capability/user state and denied
DNS/TCP/HTTP/metadata/gateway routes. They assert runtime removal independently
of target stdout. Ordinary container tests are not proof of escape resistance.

Stoneward adds explicit IPv6 TCP/UDP no-route probes and protocol-availability
observations, IPv4 UDP denial, positive private loopback exchanges, per-path tmpfs
exhaustion, measured CPU throttling, process churn/nested shells, double-fork
descendants, supplementary group/UID-map checks, CapPrm/CapBnd observations and
representative setuid/setgid denial. Socket probes include rootless user sockets,
containerd, Podman and CRI paths. Independent post-execution queries check both
containers and preparation images with no ambient Docker context/TLS environment.
Optional create-new bounded JSON test artifacts retain actual runtime/fixture
observations. These fixtures remain opt-in; their existence is not a native pass.

Observed platform: macOS controller -> forwarded Unix socket -> rootless Docker
29.5.2/runc 1.3.5/containerd 2.2.4 on Ubuntu 24.04.4 Linux 6.8 in a dedicated
Colima VM. macOS HOME sharing and agent forwarding were disabled. Docker Desktop,
alternative backends were not tested; current native observations are recorded in the qualification document.
See the Milestone 3 report for final gate counts and skips.

Milestone 3.5 corrections are tracked in [architecture alignment](ARCHITECTURE_ALIGNMENT.md).
Project requests now resolve through authority-owned profiles/plans. Observed runtime
identity is not attestation; toolchain versions remain NotObserved. Generic verified
source export preserves the same descriptor and stopped-view checks.
