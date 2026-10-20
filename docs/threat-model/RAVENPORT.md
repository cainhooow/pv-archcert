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
| Retry until pass | Target/policy rejection never queues execution | Terminal NOT_ELIGIBLE; infrastructure-only lease-loss recovery; immutable attempt history and max 1–3 attempts | Facts lost before durable acceptance remain uncertainty; operator cleanup confirmation must be truthful |
| Signing replay/changed payload | One issuance identity cannot sign changed fields | Canonical validated draft; persist key/time/payload digest before sign; exact compare on retry | Same exact certificate replay is allowed; revocation/expiration semantics remain deferred |
| Crash during signing | Completion has verified persisted envelope | Deterministic same-message Ed25519 recovery; verify selected key; immutable upload before atomic completion/audit | Selected key must remain available; signer failure leaves recoverable SIGNING with classified audit |
| Credential leakage | Target receives no authority credentials | env_clear worker launch; no key/DB/store capability in assignment or RunnerInput; fixed target environment; dependency guards; live credential canary | Trusted local worker/controller share an OS user in development; separate service identities are required for hostile-worker isolation |
| Unauthorized job creation | Source ID alone grants no authority | Private authority bearer hashes, explicit actor/project/repository mappings, persisted grants before lookup, strict DTO, no actor/policy/runtime override fields | Loopback bearer/private-file provisioning is development auth; enterprise IAM/TLS/rate limits deferred |
| Orphan/staging artifacts | Incomplete persistence cannot fabricate availability | STAGING -> checked upload/read -> AVAILABLE; only AVAILABLE advances state; retained attempt-kind metadata | Orphans consume space until reviewed reconciliation; no automatic deletion/GC |
| Audit rewrite | Security transitions have durable audit | Audit insert shares state transaction; UPDATE/DELETE reject; history never overwritten on retry | DBA/TRUNCATE/backup tampering needs production role hardening and external audit; hash chaining is future work |
| Worker output confusion | Target text cannot assert eligibility | Captured target bytes remain ExecutionEvidence; private Protobuf process result validates expected job/attempt/source/plan/step/execution and producer; controller reconstructs observations | The authority worker executable/host is trusted; remote worker attestation is not implemented |
| Network partition/database reconnect | Unknown commit is not success | Re-read durable state; idempotent admission, immutable artifact metadata and prepared issuance; fenced result acceptance | Temporary unavailability delays jobs; operators must reconnect/reinvoke controller |

No broker/event platform, event sourcing, cluster membership, general signing RPC,
production encryption hierarchy, cancellation or public transparency system is added.
ArtifactCipher reserves a maintained-provider encryption boundary: root KEK ->
organization/project KEK -> per-artifact DEK. The supplied storage is explicitly
unencrypted development storage, not simulated production encryption.

## Stoneward operational boundaries under qualification

These are current controls and open requirements, not claims that automatic
reconciliation or native service recovery has been implemented.

| Threat | Security property | Current mitigation | Remaining risk / required qualification |
| --- | --- | --- | --- |
| Orphan container or preparation image after worker crash | No owned target survives recovery | Random execution names and owner/workspace labels; bounded in-process removal; RUNNING recovery requires operator confirmation | Durable job/attempt ownership labels and fenced restart reconciliation remain outstanding; never prune the daemon globally |
| Stale lease with a live or suspended worker | No duplicate physical target execution | Expired lease cannot publish/renew; RUNNING recovery blocks without confirmation | Lease expiry is not worker death; even an empty inventory does not prevent a stale worker from creating a later target; automated retry must prevent future creation as well as confirm old target death |
| Daemon restart or runtime transport loss | Infrastructure uncertainty cannot become a target verdict | Runtime/inspect failure rejects positive evidence; cleanup failure remains separate | Native interruption/live-restore behavior and orphan continuation require actual tests; do not infer all targets stopped when API disappears |
| Host reboot | Durable state remains authoritative across lost processes | PostgreSQL state and create-only artifact publication are independent of process memory | HOST REBOOT RECOVERY NOT QUALIFIED; filesystem and runtime boot behavior remain unobserved |
| Cleanup failure or crash during cleanup | No successful certification from unknown cleanup | Separate sandbox/source cleanup flags gate controller observations and issuance | Operational succeeded/incomplete/deferred/failed states, durable retries and restart-safe fencing remain outstanding |
| Resource exhaustion | Target budgets remain bounded and infrastructure uncertainty stays inconclusive | Finite memory/swap/PID/CPU/tmpfs/output/time limits; hostile fixtures test actual enforcement | Colima evidence does not qualify native cgroup delegation; per-container limits do not bound global concurrency or kernel/daemon overhead |
| Host disk or inode exhaustion | Authority cannot silently accumulate unlimited runtime/staging state | Finite transfer/output bounds and create-only artifact publication | Host capacity thresholds, owned-object reconciliation and staging reclamation remain outstanding; immutable objects must not be overwritten/deleted to manufacture progress |
| Service manager confusion or startup dependency outage | PostgreSQL remains control-plane truth | Run-once controller re-reads durable state; failed DB operations cannot fabricate transitions | Native systemd ordering/restart/readiness behavior remains unqualified; process alive does not mean ready; setup/migration authority must remain separate |
| Runtime/DB disagreement or unknown ownership | Only demonstrably owned resources can be destroyed | Existing explicit authority-only manual recovery | No automatic classifier yet; DB state, exact attempt, lease, worker loss and runtime ownership must be reconciled before destructive actions; unknown attempts remain blocked/reported |

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
