# ADR-0012: Infrastructure-independent sandbox runner port

Status: Accepted for Milestone 3.

Domain execution types contain identity, argv, network policy, budgets, lifecycle,
structured outcomes and byte evidence. `archcert-application::execution` owns
ExecutionRequest, SandboxRunner, ExecutionResult and ExecutionFailure. The port
uses an associated MaterializedSource and consumes RunnerInput; no runtime type
appears inward of infrastructure. DockerRootlessRunner implements it in the new
archcert-runner crate. GVisorRunner/FirecrackerRunner can implement the same port
with their own actual source capability, without a domain redesign.

Execution is synchronous on a dedicated worker, consistent with existing source
ports. Callers must not block an async reactor. This avoids cancellation silently
dropping an async cleanup future. Ordinary errors and unwinding attempt cleanup;
abort, process death and runtime outage still require orphan recovery. Lifecycle
and audit events distinguish preparation/start/termination/finish/destruction.
No event sourcing or durable-log guarantee is claimed.
