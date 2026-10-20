# ADR-0015: Denied execution network only

Status: Accepted for Milestone 3.

NetworkPolicy has only Denied. Docker target creation uses network=none, no host
network, published ports, links, extra hosts or host IPC. Stopped configuration
inspection confirms it. The network namespace has loopback only; there is no
external DNS, host gateway or metadata route, including 169.254.169.254. Local
loopback communication among a job's processes is possible and is not egress.

DependencyFetch and Restricted policies require reliable authority-enforced
restricted egress and separate phases. They are deferred; unrestricted network
is not implemented. Runtime image provisioning is a separate trusted operator
operation before execution, never a package-install step run by the project.
Build/test commands do not inherit provisioning network. Projects requesting
network or isolation overrides through TOML fail unknown-field validation.

Live fixtures attempt DNS, numeric TCP, HTTP, metadata and gateway addresses.
Numeric probes require ENETUNREACH/EHOSTUNREACH and assert the loopback-only
interface set, so rejection does not depend on Internet availability or a remote
service refusing connections. An authority-owned local HTTP canary endpoint was
also provisioned in the test VM and verified reachable outside the sandbox.
