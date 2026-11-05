# Glassmere private panel threat model

Scope: ADR 0051, bounded read-only operational visibility and browser sessions.
Authority records and verifier semantics remain those of M0–M8. The panel observes
authority; it does not become authority. This document declares no qualification.

| Threat / asset | Attacker capability | Control | Remaining limitation |
| --- | --- | --- | --- |
| Stolen session / private state | Replay a cookie | HttpOnly, SameSite Strict, Secure in TLS mode; expiry, server-side logout; grant revision recheck | Compromised browser/host or stolen active cookie can act within its remaining scope |
| Cross-project IDOR / evidence | Forge path/object IDs | Authorize project before query; resolve object through scoped aggregate; uniform NOT_FOUND | Operator must provision correct grants |
| Stored XSS / browser credentials | Control names, findings, claims, source/evidence text | HTML escaping, text-only bounded preview, attachment downloads, strict CSP; no Markdown HTML | Browser implementation and same-origin asset compromise remain trusted |
| CSRF / session and commands | Cross-origin form/fetch | Exact configured Origin; session-bound CSRF for logout; Strict cookie; no mutating GET/CORS | A compromised same-origin script can submit authorized operations |
| Stale green / human decisions | Delay/fail updates, restore old tab | Backend exact-identity readiness, content revision; no-store; initial historical label; freshness invalidation | No browser can provide an atomic authorization lease for a later deployment |
| Inconsistent reads / bindings | Race durable updates | REPEATABLE READ READ ONLY aggregate; immutable exact-object hash checks; no latest-row heuristic | Database operational integrity remains trusted |
| Authorization bypass / authority | Forge direct HTTP requests | Server-side principal/role/project/object checks; unsupported mutations denied | Full workflow command surface remains unimplemented |
| Admin abuse / project truth | Obtain panel Administrator role | Project restrictions still apply; no authority policy/user editor, signer, state setter or audit delete | External provisioning administrator remains trusted |
| Credential leakage / secrets | Supply diagnostic/provider/log content | Explicit query fields; no raw DB errors, pins, command environments, connection strings or arbitrary logs | Evidence may itself contain source secrets; access is private and downloads are explicit |
| Arbitrary workflow / runtime | Supply argv or cleanup request | No shell/exec/upload endpoint; no Docker socket, runtime adapter or source/provider credential | A compromised same-UID process may reach separately provisioned host resources |
| Evidence substitution / identity | Replace bytes or cross-bind metadata | Project-scoped references; verify size/hash; selected-key verifier; exact M6 source/recipe/artifact/comparison bindings | Authority storage loss can deny availability |
| Download abuse / availability | Repeated large requests | Fixed size, finite concurrency/rate bounds; digest filename; attachment and nosniff | Host-level network resource protection still needed |
| Search injection / private history | Forge dimensions, values or cursors | Fixed exact vocabulary; canonical 64-byte values; 256-byte project/query-bound cursors; bound SQL; 50 hits; read-only transaction and statement deadline | Pages are fresh reads; new earlier keys require a restarted search and state changes can remove matches |
| Operational request replay / private coordination | Retry with changed or different keys | ADRs 0053/0056 bind exact scope, context, operation and inputs; immutable keys reject substitution; pending/applied/uncertain intent coalesces; only known no-effect rejection permits a fresh key | Private atomic job mediation exists; HTTP and release/readiness mediation remain unimplemented; dispatchers must never misclassify an uncertain side effect as rejection |
| Command credential bypass | Reuse a panel broker token on the legacy submission API or post another actor/operation | ADR 0057 separates token namespaces; strict private per-scope operation mappings; authority context and repository/operation grants checked independently; no job creation before command acceptance | HTTP composition must reload command credentials per request and explicitly project safe receipts; browser mediation remains unimplemented |
| Stale command dispatcher | Publish after coordination expiry or takeover | Exact database-time lease and opaque generation; immutable request and terminal receipt; grant recheck; local job mutation and receipt share a transaction | Existing execution/provider/build claims remain separate; external workflow integration must reconcile their original immutable identities |
| Reviewed command substitution | Reuse another session/capability or change authority pins | ADR 0055 requires the existing non-deserializable application admission; binds session/source/policy/base plan/profile/image/budget; admission/linkage/audit/receipt are atomic; retained-review restoration receives no provider capability | HTTP mediation remains unimplemented; these tests establish no deterministic target proof, native execution or signature issuance |
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
