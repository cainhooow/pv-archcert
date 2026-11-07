# Local pilot onboarding threat model

Scope: ADR 0070; development loopback identity and bounded project provisioning.
Existing Northgate, Glassmere, Ravenport, execution and signing models still apply.

| Threat | Control | Residual limit |
| --- | --- | --- |
| Public bootstrap takeover | Loopback listener, exact Origin, host-delivered random single-use expiring secret; DB instance binding | Compromised local host/browser remains trusted |
| Concurrent/replayed setup | Singleton conditional transition, account uniqueness and audit in one PostgreSQL transaction | Database owner can defeat operational controls |
| Outage reopening setup | Missing/mismatched state fails closed; initialized transition cannot reopen | Lost database requires complete restoration, never automatic init |
| Interrupted publication | Durable pending marker; host reconstruction; DB generation checked per request | Multiple files are not an atomic filesystem transaction |
| Password cracking | Argon2id 64 MiB/t=3/p=1, random salt, minimum 12 characters | No breached-password service or production IAM qualification |
| Brute force/restart | Shared DB attempt budget, bounded hashing slots and panel HTTP budgets | Local denial of service remains possible |
| Role/session revival | Fresh assignment generation and credential on host recovery/change; exact DB validation | Revocation is a request boundary, not a distributed lease |
| Project escalation | Server UUID, authenticated current admin, independent host-selected profile; transaction/audit; owned project queries | Compromised provisioner can alter its delegated installation |
| CSRF/stored XSS | Exact Origin, session CSRF, strict forms, escaped inert metadata, existing CSP | Same-origin code/browser compromise |
| Git command injection | Validated Ed25519 wire key, fixed virtual UUID route and forced executable; original Northgate receiver | OpenSSH, Git and parsers remain trusted dependencies |
| SSRF/credential disclosure | No external clone/provider endpoint, no target-selected network, no private client key in target | Authored source may contain its own secrets |
| Panel signing/runtime escalation | Separate process/API, transitive guards; no key/endpoint field in application port | Same-UID/root protection is not established |
| False readiness | Dependency observations include timestamp; process liveness separate from runtime doctor and actual job state | Observations are historical and not deployment authorization |
| Backup loss/substitution | Quiescent database dump plus source, artifacts, private configuration, gates, audit and key custody | Private backups need external protection; hashes alone are not authority |

No new native execution qualification, production custody, external model assurance,
complete semantic coverage or independent certification is claimed. M9 remains
INCOMPLETE; M10, M11, Pre-Genesis and Genesis remain NOT STARTED.
