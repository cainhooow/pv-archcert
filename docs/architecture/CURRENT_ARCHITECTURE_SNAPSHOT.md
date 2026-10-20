# Current architecture snapshot — Milestone 4A

ArchCert accepts exact supported loose Git objects, owns an independent canonical
source identity, materializes/reverifies source, resolves execution against authority
profiles and executes under the existing rootless OCI controls. The development
CLI can now interpret typed observations with a deterministic authority policy and
emit unsigned certification eligibility. It cannot issue a certificate.

```text
HTTP (disabled submission) -> protocol DTO mappings -> application -> domain
CLI composition ----------> application commands/ports/configuration/plans
CLI evaluation -----------> policy -> application + domain
source adapter -----------> application + domain
materialization adapter --> application VerifiedSourceExport + domain
runner adapter -----------> application VerifiedSourceExport/SandboxRunner + domain
```

No domain→policy, application→policy/HTTP, policy→runner/materialization/source/HTTP,
or production runner→materialization edge exists. The runner's materialization
fixture edge stays dev-only. The architecture guard checks policy dependencies
and prevents inactive evidence/crypto scaffolds entering active CLI/daemon links.

```text
ProjectConfiguration -> additional ProjectExecutionRequest
AuthorityConfiguration + operator-owned mandatory commands -> ValidationPlan
    -> exact-source-bound ExecutionRequest
    -> isolated execution and separate cleanup
    -> versioned ValidationObservations
Authority PolicyBundle + independent policy selection
    + accepted SourceSnapshot + exact plan + independent expected execution IDs
    + observations -> PolicyEvaluation -> unsigned eligibility
```

`run` returns execution evidence. `evaluate` uses the same flow and adds deterministic
policy interpretation. It embeds the pinned `archcert-development-v1` authority
bundle, requiring all seven generic properties. `--authority-config` is a trusted
operator input for mandatory commands, never target-sourced policy authority.
Project requests cannot set a policy, severity, waiver, applicability, runtime,
image, environment, host mounts, network or limits. Requested TEST/BUILD labels
cannot satisfy authority-command properties. Operator access is trusted authority;
this development CLI is not a service authentication boundary.

Plans are immutable and have schema-1 exact JSON identities, including command,
profile/image/programs/limits, order, category and provenance. Observations bind
schema, source commit/tree/snapshot, whole plan digest, step, execution, profile,
fact kind and producer/version. Expected execution IDs arrive separately from
controller dispatch/results; they are not selected from a convenient observation.
A setup/runtime failure without detailed evidence produces only an unavailable
execution fact, never invented source/sandbox/network facts.

Policy TOML is strict, bounded and declarative. Canonical JSON, sorted property/set
arrays and SHA-256 establish identity independently of authoring whitespace/order.
Policy selection checks exact bundle ID/version/digest. Schema/rule/version and
producer support are explicit; no scripts, dynamic plugins or LLM are available.
Observation order and explicit audit time do not change results or findings.

| Layer/vocabulary | Meaning |
| --- | --- |
| SOURCE ACCEPTED / COMPLETE | Validated immutable supported source; COMPLETE excludes unresolved LFS/submodules |
| MATERIALIZED | Verified/sealed source under documented filesystem assumptions |
| OBSERVATION / COMPLETED | Controller fact; normal process exit includes nonzero |
| PROVEN | Required authority evidence establishes this explicitly limited property |
| FAILED | Evidence establishes the property is false |
| NOT_PROVEN | Required evidence is absent/insufficient; neither failure nor success |
| NOT_APPLICABLE | Explicit authority applicability exclusion; missing evidence is insufficient |
| INCONCLUSIVE property | Contradictory, ambiguous, unsupported or infrastructure-impaired evidence |
| ELIGIBLE_FOR_CERTIFICATION | Every blocking requirement satisfied; certificate construction/signing still required |
| NOT_ELIGIBLE / INCONCLUSIVE eligibility | Definite blocker / only unreliable blocking conclusions |
| CERTIFIED | Future M4B result after construction and successful signing; never emitted here |

All mandatory severities and all P0/P1 requirements block unless PROVEN or explicitly
permitted NOT_APPLICABLE. There is no best-effort pass/waiver. Tests/build properties
mean only the authority-designated commands completed exit zero in the bound
execution context, not test coverage, absence of defects or artifact security.
Source completeness consumes existing snapshot status rather than parsing Git.

Verified source export, rootless preflight, stopped source/config verification,
read-only source, cleared/fixed environments, denied network, finite budgets,
bounded capture and separate cleanup remain unchanged. Runtime identity is an
observation, never executable attestation; toolchains remain NotObserved.

POST /api/v1/certifications remains HTTP 501 UNAVAILABLE, without job ID/persistence.
No API expansion, database, certificate format, key loading or signing is present.
Unsigned retained demo JSON can be edited outside the live process and is not an
authenticated evidence bundle. No production policy storage/authentication,
source transport/packfiles/external fetch, durable jobs/recovery, retries, policy
inheritance or independent certification is implemented. Native Linux remains
[NOT YET QUALIFIED](../runner/LINUX_QUALIFICATION.md).

See ADRs [0022](../adr/0022-deterministic-policy-authority-and-verdicts.md),
[0023](../adr/0023-canonical-policy-identity.md),
[0024](../adr/0024-unsigned-eligibility-and-findings.md), the
[policy threat model](../threat-model/POLICY_EVALUATION.md),
[development guide and retained demonstrations](../policy/README.md) and
[TCB inventory](TCB_AND_DEPENDENCIES.md).
