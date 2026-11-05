# ADR 0059: Browser job commands and non-revivable provisioned sessions

Status: Accepted design; complete M9 qualification remains separate.
Date: November 5, 2026. Extends ADRs 0051–0058.

## Context

The authenticated job command backend needs browser mediation without giving the
panel database mutation, historical submission, execution or signing authority.
Hashing a principal's role and projects alone also allows an unused old session
to revive when those exact grants are revoked and subsequently restored.

## Decision

Keep observation on its existing SELECT-only port. Add a separate application
broker port containing identifier-only job requests, current context observations
and safe receipts. Presentation has no transport DTO or infrastructure dependency.
The outer panel executable translates through a fixed loopback HTTP client into
the opt-in daemon API from ADR 0058. No browser-provided endpoint, actor, recipe,
policy, limit, credential or claimed review result crosses that boundary.

Enable this path only with an explicit private command configuration. Map each
panel principal, exact project/repository and fixed operation to an independently
provisioned command-only backend bearer. A panel login credential cannot serve as
that bearer. Reject ambiguous mappings and sharing a bearer between principals.
The owned regular file and its directory must be private; reload mappings on
every request. Pin the literal loopback endpoint at startup. A changed endpoint
requires restart; redirects and proxies cannot forward credentials elsewhere.
Use four concurrent backend calls, a two-second connection bound, ten-second
request bound, 4-KiB request body and 128-KiB streamed response ceiling. These
bounds change no authority execution timeout, attempt limit or coordination lease.

Authenticate the browser session and authorize its role and project before object
lookup. Resolve source, reviewed-session, job and attempt identifiers through the
scoped observation port. Require the exact configured Origin and session CSRF
value. Recheck the session and operation after passive lookup, before submission.
Strict forms reject unknown fields, including posted roles. Backend authentication,
current context, repository/operation grants, journal idempotency and locked domain
eligibility remain independent requirements. A visible button grants none of them.

| Operation | Viewer | Operator | Reviewer | Administrator |
| --- | --- | --- | --- | --- |
| Read assigned project/evidence | Yes | Yes | Yes | Yes |
| Inspect panel audit | No | No | No | Yes |
| Request certification | No | Explicit backend grant | No | Explicit backend grant |
| Cancel eligible queued job | No | Explicit backend grant | No | Explicit backend grant |
| Request exact-attempt infrastructure recovery | No | Explicit backend grant | No | Explicit backend grant |
| Request release build/readiness evaluation | Unsupported | Unsupported | Unsupported | Unsupported |
| ReviewDisposition/human waiver | Unsupported | Unsupported | Unsupported | Unsupported |
| Browser user/policy administration | No | No | No | No |
| Direct certificate/permit signing or runtime control | No | No | No | No |

Release and readiness require separate M6/verifier mediation before exposure.
ReviewDisposition remains absent under ADR 0050; this does not invent a waiver or
Crownvale exception. Administrator is a presentation role, never governance or
signing authority. Provisioning stays outside the browser.

Each form carries a fresh random action key. Repeated POSTs retain that key;
different tabs may have different keys. The durable backend coalesces workflow
intent under ADRs 0053/0056, rather than trusting browser click prevention. A
successful POST redirects to a GET receipt. Refresh reads history without another
submission. APPLIED describes the requested application operation, never certified
source, Release Permit issuance, deterministic proof or current release readiness.
The panel audits requested and acknowledged submission separately from durable
authority acceptance; an interrupted response remains resolvable by the same key.

## Grant generation and compatibility

Add an optional private schema-1 principal `grant_generation`, a random 256-bit
lowercase hex nonce included in the existing session grant revision. The audited
provisioning tool selects a fresh generation for bootstrap, add, credential rotate
and every set-grant, including assigning the same role/projects. A restored role
cannot revive an earlier cookie, even if it was unused during revocation. Existing
configuration digests in the provisioning journal bind the change and nonce.

Legacy principals without the optional field preserve their serialized fields and
read-only compatibility. Command-enabled startup refuses unversioned Operator or
Administrator grants, and request authorization repeats this check. Upgrade those
grants through the audited tool with their explicit intended role and project list;
credentials can remain unchanged, but existing sessions must log in again. Legacy
manual configuration writers do not acquire a historical role-cycle guarantee.
No source, signed artifact, protocol or authority identity changes meaning.

## Security, validation and consequences

The web process retains no authority database write, runtime, acquisition, provider
or signer capability. Separate service/OS identities and read-only mounts remain
necessary against same-UID/root compromise. A trusted provisioner can change
grants; the local audit is not Crownvale transparency or tamper-proof host history.
Revocation is checked at each request boundary, not an atomic authorization lease
across independently provisioned files and remote services.

Test the complete four-role/three-operation HTTP matrix, scope, CSRF, posted role
denial, in-flight revocation and receipt refresh. Real TCP client tests cover
credential mapping, redirects, changed endpoints, private-file reload, unknown
schema, wrong bindings and oversized streamed responses. These presentation tests
do not prove durable deduplication: use the real PostgreSQL/daemon suites, browser
journeys and crash/reconnect qualification separately. M9 remains INCOMPLETE;
M10, M11 and Genesis remain NOT STARTED.

Reusing a legacy bearer, exposing database mutation to the panel, accepting posted
authority JSON or relying on disabled buttons was rejected. The additional private
configuration and grant generations require explicit provisioning and operation.
