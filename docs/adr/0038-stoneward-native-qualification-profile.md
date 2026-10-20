# ADR 0038: Native Linux qualification profile and runtime observations

Status: Accepted qualification scope; native qualification pending.
Date: October 20, 2026.

## Context

Ravenport demonstrated durable execution under macOS controlling rootless Docker
in Colima. Runtime configuration checks and a Linux guest do not demonstrate
native service, filesystem, namespace, resource or recovery behavior.

## Decision

Qualify the existing OCI tier on one explicitly recorded native Linux x86_64 host
with cgroup v2/systemd delegation, rootless Docker, runc and builtin seccomp.
Keep unsupported configurations unqualified. Record exact distribution, kernel,
architecture, filesystem, security modules and namespace/runtime versions beside
test commands/results. Native qualification requires actual hostile behavior and
crash/recovery tests; static/default/Colima passes cannot promote its status.

Treat the selected Docker Unix endpoint and executable as authority configuration.
Clear ambient Docker context, authentication/TLS/proxy configuration. Record the
selected endpoint and reported daemon/component/security identity in operational
execution evidence. Require the runc default as well as explicit runc selection
for both target and never-started preparation resources. This narrows the initial
profile and avoids relying on a different daemon default for preparation.

The native host reports missing cpuset and block-I/O controller support alongside
reported CPU-quota/memory/PID support. Explicitly allow only those exact
warnings and retain them in evidence. This profile does not claim cpuset pinning
or block-I/O rate enforcement. Unknown warnings or missing required limit support
still reject; no host-wide delegation change or privileged fallback is permitted.

Expose `archcert-worker doctor` as a non-executing prerequisite diagnostic. It
does not claim effective enforcement or full readiness and receives no DB, object
store or signing credentials. Full readiness still requires independently observed
live behavior and healthy authority dependencies.

## Security implications

Endpoint substitution is authority substitution. A socket address or reported
daemon ID is not cryptographic attestation and may identify a forwarded socket.
No project DTO can choose a runtime endpoint/context/TLS identity. Evidence adds
operational facts without changing policy verdicts, eligibility or canonical
certificate semantics. Existing evidence remains readable.

Rootless isolation shares the kernel; container escape resistance remains NOT
PROVEN. Builtin seccomp is runtime-owned, not an independently hashed ArchCert
profile. Native qualification never means universal Linux security or production
certification. Storage encryption and production IAM remain separate milestones.

## Alternatives considered

Calling Colima native qualification would assert unobserved properties. Qualifying
several runtimes at once would expand support beyond available evidence. A new VM
isolation tier would change architecture before qualifying its existing boundary.
Trusting the Docker context would allow ambient authority substitution.

## Consequences

Operations must provide a dedicated native host and record actual outcomes before
marking the profile qualified. Stricter preflight can reject formerly accepted
daemons with a different default runtime; there is no override/fallback. The
[qualification document](../qualification/NATIVE_LINUX_RUNNER.md) is authoritative
for current status and explicitly distinguishes planned commands from executions.
