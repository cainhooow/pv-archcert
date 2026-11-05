# Glassmere private panel threat model

Scope: ADR 0051, bounded read-only operational visibility and browser sessions;
ADRs 0053–0064 additionally bound the authenticated workflow/observation commands and browser broker.
Authority records and verifier semantics remain those of M0–M8. The panel observes
authority; it does not become authority. This document declares no qualification.

ADR 0060 places the existing SELECT-only/public-verifier composition in the shared
`archcert-observation` adapter. It adds no HTTP, mutation, runtime, acquisition,
provider or private-key port. Its direct allowlist and transitive capability guard
preserve that boundary for every executable that composes it.

ADR 0061 adds private readiness-request evaluation through this observer and the
existing fenced command journal. It enables no HTTP/browser readiness request.
An immutable receipt records a historical observation, never a current release
lease. New evaluation rechecks current grants and exact scope; publication also
requires the original live coordination generation and immutable source binding.
ADR 0062 adds an identifier-only private controller request, authenticated through
a separate owned private token file. Its schema-2 receipt explicitly labels every
readiness result historical; schema-1 job receipts retain their grammar. The
historical fixture importer is development tooling with explicit database/source
selection, never an HTTP data-repair endpoint or new issuance operation.
ADR 0063 exposes only the identifier-only readiness question through the separately
authenticated opt-in daemon API. Schema 2 is required; it records no posted facts
and performs no inline verification. That transport alone enables no browser request.
ADR 0064 adds the browser question through current role/scope/object/Origin/CSRF
checks, reauthorization after passive lookup and strict separately authenticated
schema-2 broker validation. Its historical receipt has no live-confirmation
attributes; past ALLOWED cannot acquire a current label through receipt refresh.

| Threat / asset | Attacker capability | Control | Remaining limitation |
| --- | --- | --- | --- |
| Stolen session / private state | Replay a cookie | HttpOnly, SameSite Strict, Secure in TLS mode; expiry, server-side logout; grant revision recheck | Compromised browser/host or stolen active cookie can act within its remaining scope |
| Cross-project IDOR / evidence | Forge path/object IDs | Authorize project before query; resolve object through scoped aggregate; uniform NOT_FOUND | Operator must provision correct grants |
| Stored XSS / browser credentials | Control names, findings, claims, source/evidence text | HTML escaping, text-only bounded preview, attachment downloads, strict CSP; no Markdown HTML | Browser implementation and same-origin asset compromise remain trusted |
| CSRF / session and commands | Cross-origin form/fetch | Exact configured Origin; session-bound CSRF for logout and workflow/observation commands; Strict cookie; no mutating GET/CORS | A compromised same-origin script can submit authorized operations |
| Stale green / human decisions | Delay/fail updates, restore old tab | Backend exact-identity readiness, content revision; no-store; initial historical label; freshness invalidation | No browser can provide an atomic authorization lease for a later deployment |
| Inconsistent reads / bindings | Race durable updates | REPEATABLE READ READ ONLY aggregate; immutable exact-object hash checks; no latest-row heuristic | Database operational integrity remains trusted |
| Authorization bypass / authority | Forge direct HTTP requests | Server-side principal/role/project/object checks before broker calls; recheck after passive lookup; independent backend grants; unsupported mutations denied | Release-build commands remain disabled; no human waiver workflow exists |
| Admin abuse / project truth | Obtain panel Administrator role | Project restrictions still apply; no authority policy/user editor, signer, state setter or audit delete | External provisioning administrator remains trusted |
| Credential leakage / secrets | Supply diagnostic/provider/log content | Explicit query fields; no raw DB errors, pins, command environments, connection strings or arbitrary logs | Evidence may itself contain source secrets; access is private and downloads are explicit |
| Arbitrary workflow / runtime | Supply argv or cleanup request | No shell/exec/upload endpoint; no Docker socket, runtime adapter or source/provider credential | A compromised same-UID process may reach separately provisioned host resources |
| Evidence substitution / identity | Replace bytes or cross-bind metadata | Project-scoped references; verify size/hash; selected-key verifier; exact M6 source/recipe/artifact/comparison bindings | Authority storage loss can deny availability |
| Download abuse / availability | Repeated large requests | Fixed size, finite concurrency/rate bounds; digest filename; attachment and nosniff | Host-level network resource protection still needed |
| Search injection / private history | Forge dimensions, values or cursors | Fixed exact vocabulary; canonical 64-byte values; 256-byte project/query-bound cursors; bound SQL; 50 hits; read-only transaction and statement deadline | Pages are fresh reads; new earlier keys require a restarted search and state changes can remove matches |
| Operational request replay / private coordination | Retry with changed or different keys | ADRs 0053/0056/0058 bind exact scope, context, operation and inputs; immutable keys reject substitution; pending/applied/uncertain workflow intent coalesces; only known no-effect rejection permits a fresh workflow key; readiness explicitly allows new observation keys | Command mediation is opt-in; release-build mediation and complete browser qualification remain open; dispatchers must never misclassify an uncertain side effect as rejection |
| Command credential bypass | Reuse a panel broker token on the legacy submission API or post another actor/operation | ADRs 0057–0058/0063–0064 separate token namespaces; strict private per-scope operation mappings; daemon reloads credentials per request and projects safe receipts; context and repository/operation grants checked independently | Release-build mediation and complete browser qualification remain open; panel role alone grants no backend permission |
| Restored role / old session | Keep a cookie unused through revocation and restoration | ADR 0059 binds audited fresh assignment generations into session revisions; command mode rejects unversioned privileged grants | Legacy manual writers do not establish role-cycle history; trusted provisioner/root can replace private files |
| Backend credential forwarding | Forge a destination, redirect or panel principal | Fixed literal loopback endpoint, per-principal/project/repository/operation private mapping, no redirects/proxies, independent tokens, bounded typed responses | Same-UID/root compromise and backend availability remain deployment concerns |
| Stale command dispatcher | Publish after coordination expiry or takeover | Exact database-time lease and opaque generation; immutable request and terminal receipt; grant recheck; local job mutation and receipt share a transaction | Existing execution/provider/build claims remain separate; external workflow integration must reconcile their original immutable identities |
| Reviewed command substitution | Reuse another session/capability or change authority pins | ADRs 0055/0058 require the existing non-deserializable admission; bind session/source/policy/base plan/profile/image/budget; admission/linkage/audit/receipt are atomic; retained-review restoration receives no provider capability | Browser selection must retain exact reviewed session/source IDs; these tests establish no deterministic target proof, native execution or signature issuance |
| Database outage / readiness | Disconnect PostgreSQL | Fresh queries fail unavailable; browser invalidates freshness; no cached live green | Existing historical page content remains inspectable with warning |
| Object outage / verification | Remove/unreadable artifacts | Metadata remains distinct from unavailable bytes; verification incomplete denies | No repair/delete authority in panel |
| Frontend supply chain / browser | Replace dependency or asset | No production JS dependency/CDN; Rust lock and controlled static assets; strict CSP | Compiler, build host and bundled source remain trusted dependencies |
| Brute force / login | Repeated random credentials | 256-bit operator-generated secrets; bounded shared attempt budget; no permanent lockout | Operational denial of service remains possible within host limits |
| Panel outage / workflow durability | Kill panel/browser | No leases, execution or signing owned by panel; re-query durable state after restart | Browser sessions intentionally expire across restart |
| Audit corruption / forensic history | Use ordinary panel requests | No edit/delete audit endpoints; authority audit append-only; separate panel audit sink | Host/DB owners can alter operational storage outside the UI |

The preview must be loopback-only, visibly development data and run without keys,
Docker access or acquisition/provider credentials. Native qualification is shown
only when supported by exact retained qualification evidence; development fixtures
do not qualify a host. M10, M11 and Genesis are not started.

> This is engineering self-validation under a shared implementation/authority context. It is not independent certification and does not replace Genesis / Firstwarden.
