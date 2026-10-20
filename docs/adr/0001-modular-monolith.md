# ADR-0001: Start as a modular monolith

## Status

Accepted for bootstrap.

## Decision

ArchCert starts as one Rust workspace with explicit domain/application/infrastructure boundaries. Execution isolation is provided by separate processes/containers rather than premature network microservices.

## Reason

Trust boundaries matter more than deployment count. A modular monolith keeps the trusted computing base understandable while allowing the runner, Git ingress and signer to become independently deployed processes where isolation requires it.
