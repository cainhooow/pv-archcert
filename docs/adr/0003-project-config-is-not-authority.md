# ADR-0003: Project configuration is not certification authority

## Status

Accepted.

## Decision

`archcert.toml` describes project environment, toolchains, services and project-requested checks. It cannot suppress mandatory ArchCert or organization policy.

A lower policy layer may strengthen an inherited requirement but cannot silently weaken it.
