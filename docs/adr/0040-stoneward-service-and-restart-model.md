# ADR 0040: User services retry durable work without owning job state

Status: Accepted

## Context

The controller composes durable admission, execution and signing. A worker is a
private stdio child with no database, artifact or signing authority. Service
restarts can kill that child while its daemon-owned target survives. Dependency
startup order cannot establish readiness or replace durable PostgreSQL state.

## Decision

Provide dedicated user service examples under `deploy/systemd/user`. The controller
runs one durable unit of work per invocation; a timer retries conservatively.
It resumes evaluation/signing before admitting execution, and startup reconciliation
must finish before replacement target execution. A failed invocation is an
operational failure, not a target verdict. `After=docker.service` provides ordering
only; runtime preflight and dependency checks still determine readiness. No
`Requires` relationship stops unrelated services or makes systemd authoritative.

The worker remains an authority-launched child, not an independently privileged
queue consumer. The separate worker doctor example observes runtime prerequisites;
it does not advertise full certification readiness. API `/healthz` is liveness;
`/readyz` checks PostgreSQL migration/availability and artifact permissions/capacity.
The controller doctor checks these dependencies. Runtime doctor failure rejects
new target admission. No automatic migration or dependency outage fabricates job
progress. Explicit provisioning/migrations precede ordinary service operation.

## Hardening and exceptions

Steady-state services need no root, sudo, CAP_SYS_ADMIN, privileged containers or
membership in the rootful Docker group. Bootstrap provisioning of subordinate IDs,
user namespaces, runtime packages and delegation belongs to the operator.

The examples use NoNewPrivileges, private umask, bounded file descriptors/tasks,
explicit address families and control-group process termination. The controller
requires AF_UNIX for its rootless daemon and AF_INET/AF_INET6 for PostgreSQL;
worker doctor needs AF_UNIX. These service restrictions do not substitute for
container network denial. KillMode stops child workers/CLIs; daemon-owned targets
still require fenced reconciliation. A two-hour service deadline bounds an
invocation; an interrupted target must be reconciled before retry.

ProtectHome is incompatible with user-owned source, gate, artifact and rootless
runtime state. ProtectSystem/PrivateTmp mount namespace hardening is omitted from
these portable user examples: per-user availability depends on kernel, systemd and
user-namespace policy, and isolated temporary paths can hide required socket/state
paths. Deployments may add tested path-specific restrictions. Do not give a worker
controller environment files or signer paths. The supplied environment file is
private mode 0600 and contains only authority configuration such as the database
URL. Signing remains DEVELOPMENT ONLY; these examples do not establish production
IAM, encryption or key management.

[systemd execution documentation](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)
explains the scope and limitations of these directives. NoNewPrivileges constrains
the service process; it does not constrain a separately running daemon through IPC.

## Consequences

Service restarts are repeatable invocations against durable state. Timer timing is
not lease authority. PostgreSQL, local gate tombstones and verified runtime cleanup
remain necessary. A common local authority filesystem/runtime is required; this is
not distributed worker coordination. Full host reboot and power-loss filesystem
durability require separate observations and remain unqualified until tested.
