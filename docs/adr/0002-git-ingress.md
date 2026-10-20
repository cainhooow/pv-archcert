# ADR-0002: Git is a first-class source-ingress protocol

## Status

Accepted for bootstrap design.

## Decision

ArchCert will support an ArchCert Git remote over SSH and/or HTTPS. Received objects enter quarantine and are converted into an immutable ArchCert-owned source snapshot before certification begins.

## Consequences

- ZIP upload is not the primary workflow.
- Git commit and tree ids remain part of certificate identity.
- ArchCert additionally records its own SHA-256 source-manifest digest.
- The execution runner never needs repository credentials.
