# ADR-0017: Controller-owned execution evidence

Status: Accepted for Milestone 3.

Evidence records execution/workspace/source IDs, adapter/server version, approved
OCI repository digest, base and job image content IDs, literal argv/cwd, profile,
network, budgets, environment keys, effective configured UID:GID, UTC millisecond
timestamps, monotonic duration, runtime exit, termination cause and outcome.
Completed includes nonzero exits. TimedOut, ResourceLimit, StartFailure,
SandboxFailure and Terminated remain distinct from future certification policy.
CLI/client exit disagreement with runtime exit prevents a normal completion claim.

Each stream records SHA-256 of every observed byte, observed byte count, bounded
byte prefix, truncation and EOF completeness. Prefix truncation does not truncate
the hash. After stream flooding/transport failure/forced client closure, bytes
that never reach the controller cannot be hashed; complete=false explicitly means
an observed-prefix digest, not a full target-stream digest. No silent completeness
claim is made. Runtime logging is disabled to avoid unbounded daemon-side files.

Output is hostile binary data, serialized as integer arrays. JSON also escapes
command control characters. Never print excerpts directly into a terminal/UI.
Target-produced status files or text such as ARCHCERT RESULT: PASS have no
authority. Evidence authenticity currently relies on the trusted controller and
runtime; persistence, signatures and independent assessment are deferred.

Sandbox destruction is separately reported. Cleanup failure returns an
ExecutionFailure with any available evidence, even if the target exited zero.
Audit events distinguish creation, start, timeout, completion and destruction or
cleanup failure. Setup failures may have no stream evidence because no target
started. Durable audit events and precise platform-independent signal/PID/CPU
causality are not claimed.
