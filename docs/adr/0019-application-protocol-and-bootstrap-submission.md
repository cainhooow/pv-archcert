# ADR-0019: Application commands, protocol mapping and unavailable bootstrap submission

Status: Accepted for Milestone 3.5. Supersedes the bootstrap submission behavior;
ADRs 0001–0018 and milestone reports remain historical evidence.

The application owns SubmitCertificationCommand, SubmitCertificationResult and
the SubmitCertification port. Protocol owns HTTP DTOs and explicit From mappings.
Dependency direction is protocol -> application -> domain. Application contains
no HTTP status, Axum extractor or protocol dependency. The currently synchronous
capability check needs no async-trait macro; a future real job port may differ.

POST /api/v1/certifications remains discoverable but disabled (option B): valid
requests return HTTP 501 with {"status":"UNAVAILABLE"}. No ID, PENDING, HTTP 202,
queue or persistence is claimed. Malformed requests still reject. No job system
is implemented. Transport/application mappings and the actual handler response
are tested. Health reports process liveness, not certification readiness.

Generating an ephemeral ID would not justify a pending-work response. An in-memory
job facade would obscure the missing durable architecture. The disabled boundary
keeps the transport contract reviewable without widening this milestone.
