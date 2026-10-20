# Ravenport durable control-plane threat model

Scope: local development authority, PostgreSQL control plane, immutable filesystem
object adapter, private worker process pipe and existing rootless OCI boundary.
This is engineering review, not independent certification or production qualification.

| Threat | Security property | Mitigation | Remaining risk |
| --- | --- | --- | --- |
| Duplicate submission/timeouts | One scoped request creates bounded work | Unique project/repository/actor/idempotency key; identical input return; changed pins conflict in transaction; real concurrent tests | Clients using new keys can request separate jobs; admission quotas remain future work |
| Double worker execution | Exactly one authoritative active attempt | SKIP LOCKED job row claim, unique partial active-attempt index, random fence, locked state transitions | A partitioned expired target can physically continue; running recovery requires confirmed cleanup |
| Lost worker | No fabricated target failure/completion | Persist worker/attempt/lease/failure; expiry records LOST; fresh AttemptId only within pinned budget | Runtime orphan cleanup requires operator confirmation in this topology |
| Stale lease or renewal replay | Old worker cannot advance job | Check worker/job/attempt/token/state and database expiry under job lock; bounded renewal and total lifetime | Compromised trusted authority process is outside lease capability protection |
| Job-state tampering | Valid transitions and immutable inputs | Checked domain graph, transactional repository preconditions, database triggers/checks, terminal immutability | Database owner can bypass operational safeguards |
| Database compromise | Historical signatures remain independently verifiable | No private signing keys in DB; separate object bytes; exact source/plan/result/issuance revalidation; offline selected-key verification | Database is trusted operational TCB; compromise can corrupt availability/auth/audit and requires issuance shutdown/investigation |
| Object substitution | Metadata and bytes agree | SHA-256 and exact size on every bounded read; structural source/plan/attempt checks before persistence and signing | Authority filesystem/root compromise can destroy objects; trusted worker provenance is not cryptographic attestation |
| Artifact overwrite | Issued evidence bytes never change through adapter | Scoped content keys, atomic create-only link publication, read-only file mode, no replace/repair path; duplicate mismatch rejects | Same-UID/root writers bypass adapter permissions; production object locks/versioning remain adapter qualification |
| Cross-project artifact confusion | Digest dedup does not grant authorization | Project-scoped keys; HTTP scope checks; source project/repository/identity recheck | Trusted operator misprovisioning and database owner remain risks |
| Policy substitution | Evaluation uses admitted policy | Persist ID/version/canonical digest; controller compares exact built-in bundle; reject unavailable version | Only the current built-in development policy is supported; future version registry required |
| Source substitution/mutable refs | Recovery executes exact accepted source | Persist full commit/tree/source SHA-256 and submission/scope; Northgate reload/rehash; worker independent codec/scope checks | Accepted source root backup/durability and hostile same-UID protection remain deployment responsibilities |
| Retry until pass | Target/policy rejection never queues execution | Terminal NOT_ELIGIBLE; infrastructure-only lease-loss recovery; immutable attempt history and max 1–3 attempts | Facts lost before durable acceptance remain uncertainty; trusted controller and runtime/gate integrity remain necessary |
| Signing replay/changed payload | One issuance identity cannot sign changed fields | Canonical validated draft; persist key/time/payload digest before sign; exact compare on retry | Same exact certificate replay is allowed; revocation/expiration semantics remain deferred |
| Crash during signing | Completion has verified persisted envelope | Deterministic same-message Ed25519 recovery; verify selected key; immutable upload before atomic completion/audit | Selected key must remain available; signer failure leaves recoverable SIGNING with classified audit |
| Credential leakage | Target receives no authority credentials | env_clear worker launch; no key/DB/store capability in assignment or RunnerInput; fixed target environment; dependency guards; live credential canary | Trusted local worker/controller share an OS user in development; separate service identities are required for hostile-worker isolation |
| Unauthorized job creation | Source ID alone grants no authority | Private authority bearer hashes, explicit actor/project/repository mappings, persisted grants before lookup, strict DTO, no actor/policy/runtime override fields | Loopback bearer/private-file provisioning is development auth; enterprise IAM/TLS/rate limits deferred |
| Orphan/staging artifacts | Incomplete persistence cannot fabricate availability | STAGING -> checked upload/read -> AVAILABLE; only AVAILABLE advances state; retained attempt-kind metadata | Scoped old unlocked staging cleanup never deletes final objects; final object retention remains an operator responsibility |
| Audit rewrite | Security transitions have durable audit | Audit insert shares state transaction; UPDATE/DELETE reject; history never overwritten on retry | DBA/TRUNCATE/backup tampering needs production role hardening and external audit; hash chaining is future work |
| Worker output confusion | Target text cannot assert eligibility | Captured target bytes remain ExecutionEvidence; private Protobuf process result validates expected job/attempt/source/plan/step/execution and producer; controller reconstructs observations | The authority worker executable/host is trusted; remote worker attestation is not implemented |
| Network partition/database reconnect | Unknown commit is not success | Re-read durable state; idempotent admission, immutable artifact metadata and prepared issuance; fenced result acceptance | Temporary unavailability delays jobs; operators must reconnect/reinvoke controller |

No broker/event platform, event sourcing, cluster membership, general signing RPC,
production encryption hierarchy, cancellation or public transparency system is added.
ArtifactCipher reserves a maintained-provider encryption boundary: root KEK ->
organization/project KEK -> per-artifact DEK. The supplied storage is explicitly
unencrypted development storage, not simulated production encryption.

## Stoneward operational boundaries under qualification

The single-host protocol is defined in ADR 0039. Runtime observations and
qualification results are recorded separately from the mechanism's design.

| Threat | Security property | Mitigation | Remaining risk |
| --- | --- | --- | --- |
| Orphan target/preparation image | Only exact owned resources are removed before retry | Immutable DB runtime binding, ownership/version/job/attempt/execution labels, reinspection and independent absence checks | Unknown/legacy resources are retained and block admission; never global prune |
| Stale lease/live worker/late create | No replacement while old work may execute or be created | Nonrenewable expiry, exclusive persistent execution gate, fsynced irrevocable revocation before DB fence, exact-attempt cleanup SUCCEEDED before recovery | Cooperative trusted worker/single host/shared local gate required; busy or uncertain pending-create gates remain blocked indefinitely |
| Daemon interruption | Runtime uncertainty cannot become target failure | Required preflight, local Unix endpoint incarnation, inspect/status verification, separate cleanup outcome | Same-UID/runtime admin remains trusted; disconnected API is not proof of target death |
| Host reboot | Durable state remains authoritative | PostgreSQL history, immutable object publication, persistent gate tombstones | HOST REBOOT RECOVERY NOT QUALIFIED; power-loss and boot ordering remain unobserved |
| Cleanup error/reconciler crash | No false destruction or retry | Durable PENDING/IN_PROGRESS/SUCCEEDED/FAILED/BLOCKED metadata and audit; exclusive gate retained across removal; retry revalidates exact binding | Late daemon creation remains blocked; availability never overrides uncertain termination |
| Resource exhaustion | Bounded target execution; uncertain infrastructure stays inconclusive | Finite memory/swap/PID/CPU/tmpfs/output/time and actual hostile probes | Per-container limits do not reserve global host/kernel/daemon resources; escape resistance NOT PROVEN |
| Disk/inode exhaustion | Admission fails before unbounded temporary accumulation | 1 GiB/1024-inode floors, bounded inventory, exact owned-image cleanup, locked scoped staging reconciliation | Threshold is not a reservation/scheduler; final immutable objects require operator retention/capacity policy |
| Service-manager/dependency confusion | PostgreSQL owns progress | Liveness/readiness separation, conservative run-once timer examples, no implicit migrations, accepted evidence continuation | User service/kernel hardening compatibility needs deployment checks; development auth/storage/signing remain limited |
| Runtime/DB disagreement | Destroy only DB-known expired/closed owned attempts | Active attempts retained; closed/expired exact binding can be revoked/reconciled; unknown job/attempt reported/blocked | Unknown ownership cannot be guessed; daemon identity/gate mismatch requires investigation |
| Crash after evidence publication | Never rerun committed complete evidence | Exact AVAILABLE result rehash/validation, fenced cleanup, transactional adoption without lease revival | Missing/corrupt committed bytes block; staging metadata alone cannot prove complete evidence |

## Focused implementation review

Searches covered DB/object credentials in runner inputs/environment; private keys
in worker dependencies/assignments; mutable source refs; latest-policy recovery;
claim/result races; retry-to-pass paths; pre-eligibility signing; object replace;
and anonymous admission. Credential search hits in runner tests are exclusion
canaries. HEAD/latest hits are documentation, rejection messages and negative tests.
The sole requeue operation is fenced expiry recovery with authority cleanup and
attempt-budget checks. The sole controller draft.issue call follows persisted
eligibility and exact prepared issuance. The object adapter uses linkat create-only
publication, never replacement. HTTP request types have no authority overrides.

Real PostgreSQL tests exercise concurrent admission, racing workers, wrong/stale
renewals, expiry, bounded retries, terminal/inconclusive rejection, reconnect,
artifact staging and immutable issuance. Default object tests exercise mismatch,
truncation, duplicate upload, overwrite, missing/corrupt object, metadata mismatch,
project isolation and orphan staging. The retained demonstration separately kills
an actual worker during OCI execution and recovers with history, interrupts each
controller persistence/signing phase, verifies a durable certificate offline and
keeps Bottle NOT_ELIGIBLE with its exact historical identity. No secret/private key
is retained with demonstration evidence.
