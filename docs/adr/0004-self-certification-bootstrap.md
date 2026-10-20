# ADR-0004: ArchCert bootstrap and self-validation

## Status

Accepted.

## Decision

ArchCert will run its own checks against itself, but this is called self-validation rather than independent certification. The first trusted release is a documented genesis release. Later releases should be evaluated by an already trusted prior ArchCert release plus required human release controls.
