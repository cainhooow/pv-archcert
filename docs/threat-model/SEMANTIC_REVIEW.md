# Ironcrest semantic review threat model

Scope: the design in ADRs 0041–0043. Implementation and executed validation are
listed separately in the current architecture snapshot. This is an engineering
review, not independent certification. Authority provisioning, controller, storage,
build/toolchain and OS remain trusted. Repository bytes and semantic output are
untrusted. A semantic provider is never a deterministic or cryptographic authority.

| Threat | Control | Residual risk | NOT PROVEN |
| --- | --- | --- | --- |
| Prompt injection / social engineering | Separate fixed authority contract; repository text is labeled data; structured response cannot set policy, verdicts or commands | Reviewer may follow hostile prose and miss a concern | Universal injection detection or prevention inside a model |
| Provider compromise | Capability-free port; strict response validation; deterministic gate; all existing checks required | Malicious provider can cause denial or conceal defects | Reviewer honesty or bug-detection completeness |
| Model drift | Retain exact request/accepted response bytes, identities and metadata | New review may differ under the same model name | Remote inference reproducibility |
| Semantic false negative | Semantic clear establishes no deterministic fact | Undetected defect can survive bounded checks | Absence of defects |
| Semantic false positive | Preserve concern/provenance and block conservatively | Valid software may be blocked | Semantic allegation as deterministic proof |
| Malicious repository context | No target instruction/configuration controls authority contract, adapter or registry | Parser bugs and misleading comments remain possible | All repository statements being true |
| Context exhaustion / truncation | Byte/count limits; explicit incomplete state and blind spots; mandatory review fails closed | Bounded context may omit relevant behavior | Complete reasoning over arbitrarily large source |
| Knowledge poisoning | Exact accepted source, observed/inferred provenance, separate authority bundles | Misleading names and syntactically valid deceptive code remain possible | Compiler-quality resolution or faithful author intent |
| Stale baseline | Pin exact authority-selected accepted identity and selection rationale | Authority may provision an unsuitable baseline | Baseline freshness without an authority freshness policy |
| Baseline downgrade | No target baseline field; source/project/repository binding | Compromised authority can select weak history | Honest authority selection |
| Cross-project leakage | Explicit project/global scope; reject foreign bundles/artifacts before packaging | Authority operator/DB/OS can access private data | Protection from a compromised trusted controller |
| Finding/invariant downgrade | Approval/version/supersession controlled outside source; immutable bundle digests | Bad authority approval can weaken knowledge | Correctness of authority assertions |
| Review replay across source/job/project/policy | Compare complete frozen binding, request and knowledge digests | Compromised controller can bypass APIs | Authenticity from a digest alone |
| Challenge command injection | Closed typed proposal; unknown fields reject; authority template resolution only | A badly authored authority template can be unsafe | Safety of arbitrary authority-authored tests |
| Challenge escalation | Model cannot choose executable, image, mounts, network, privilege, credentials or budgets | Trusted registry provisioning remains critical | Sandbox escape resistance |
| Provider outage / timeout / crash | Retained classified failure; required review cannot continue | Availability loss; in-flight outcome may remain uncertain | Uninterrupted service or exactly-once remote inference |
| External source disclosure | No external adapter by default; explicit authority authorization required | Source can itself contain secrets; authorized provider retains its own risk | Confidentiality after authorized external disclosure |
| Semantic result tampering | Exact response/request/artifact hashes; verified immutable storage reads | Same-UID/root/DB authority compromise affects availability and operational trust | Protection from authority host compromise |
| Graph explosion / parser exhaustion | File/byte/node/edge/depth budgets; explicit exhaustion | Finite but expensive parsing; process/global resource limits remain operational | Parser correctness or global denial-of-service immunity |
| Agent self-claims masquerading as evidence | Distinct untrusted claim type; supporting/contradicting references; never a truth score | Evidence interpretation can still be wrong | Claim truth from author confidence |
| Crash after persistence | Durable stage/acceptance metadata; reload and revalidate; no silent re-review or rerun of accepted work | In-flight unaccepted work may require operator recovery | Power-loss durability on unqualified filesystems |
| Semantic clear rescues deterministic failure | Existing evaluator and issuer re-evaluate deterministic evidence independently | Trusted malicious signing composition can sign lies | Production key custody or independent certification of this implementation |

Private authority tests can be withheld from the repository before execution.
Tests and target sharing an execution context do not establish confidentiality of
the test source during execution. Prompt injection fixtures demonstrate authority
containment at software boundaries; they do not prove a model cannot be influenced.

No semantic change may weaken Stoneward execution fencing, cleanup or isolation.
Changes above that boundary do not requalify any broader platform. A change to its
qualified mechanism requires relevant live validation and native requalification.

The reviewed admission API now returns a non-deserializable application capability
only after profile/request/accepted-review checks and immutable gate/plan publication.
The PostgreSQL transaction rechecks the full session pin, all reviewed references,
accepted source/baseline and the locked actor grant before atomically inserting the
reserved job and its create-only evidence linkage. Six interrupted object-publication
boundaries and concurrent/restarted admission are covered by real database tests.
The gate artifact binds its algorithm, exact accepted review and required bounded
challenge identities. Controller/issuance integration remains outstanding; these
controls alone do not prove a complete veto-before-signing lifecycle.
