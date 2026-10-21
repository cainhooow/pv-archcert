//! Authority-owned deterministic projection, independent of canonical extraction.
use super::*;
use archcert_domain::knowledge::{AuthorityEntryKind, NodeKind};
use serde_json::{Value, json};

/// New algorithm identity. Historical direct-embedding requests remain schema 1.
pub const PACKAGER_VERSION: &str = "archcert-semantic-packager-v1/1.1.0";

/// Authority capability, deliberately without a target parser or Deserialize.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticPackagingPolicy {
    version: &'static str,
    maximum_request_bytes: usize,
    maximum_excerpt_bytes: usize,
    maximum_file_excerpt_bytes: usize,
    maximum_nodes: usize,
    maximum_edges: usize,
    maximum_files: usize,
    maximum_findings: usize,
    maximum_invariants: usize,
    maximum_tests: usize,
    maximum_blind_spots: usize,
    accept_partial: bool,
    priority: &'static str,
    fallback: &'static str,
}
impl SemanticPackagingPolicy {
    /// Explicit bounded engineering review. Partial review proves no completeness.
    pub fn rust_controlled() -> Self {
        Self {
            version: "rust-bounded-context-v1/1.1.0",
            maximum_request_bytes: 1024 * 1024,
            maximum_excerpt_bytes: 65536,
            maximum_file_excerpt_bytes: 4096,
            maximum_nodes: 512,
            maximum_edges: 512,
            maximum_files: 128,
            maximum_findings: 128,
            maximum_invariants: 128,
            maximum_tests: 128,
            maximum_blind_spots: 128,
            accept_partial: true,
            priority: "mandatory-identities-policy-authority;changed-files;impacted-nodes;unresolved-edges;tests;migrations-entry-points;excerpts;neighborhood;canonical-ties",
            fallback: "explicit-category-omissions;mandatory-overflow-INCONCLUSIVE-no-provider",
        }
    }
    /// Authority may reduce its request bound, never exceed the fixed ceiling.
    pub fn with_request_limit(mut self, bytes: usize) -> Result<Self, KnowledgeError> {
        if bytes == 0 || bytes > Self::rust_controlled().maximum_request_bytes {
            return Err(KnowledgeError::LimitExceeded);
        }
        self.maximum_request_bytes = bytes;
        Ok(self)
    }
    /// Policy identity is independent of target data.
    pub fn digest(&self) -> Result<Sha256Digest, KnowledgeError> {
        Ok(digest_bytes(&canonical_bytes(self)?))
    }
    /// Exact maximum serialized reviewer request, including all envelopes.
    pub fn request_limit(&self) -> usize {
        self.maximum_request_bytes
    }
}
/// Authority classification; provider output cannot change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SemanticContextCoverage {
    /// All relevant bounded extractor context and source bytes were retained.
    FullContext,
    /// Omitted repository context is explicit and this profile permits bounded review.
    PartialAcceptable,
    /// Mandatory context or an authority completeness requirement is unsatisfied.
    InsufficientContext,
}
/// Separate immutable identity; this is never the canonical KnowledgeArtifact.
#[derive(Debug)]
pub struct BoundedSemanticPackage {
    artifact: CanonicalArtifact,
    policy_sha256: Sha256Digest,
    coverage: SemanticContextCoverage,
}
impl BoundedSemanticPackage {
    /// Canonical package bytes/digest. No target-supplied identity is accepted.
    pub fn artifact(&self) -> &CanonicalArtifact {
        &self.artifact
    }
    /// Explicit authority coverage decision.
    pub fn coverage(&self) -> SemanticContextCoverage {
        self.coverage
    }
    /// Exact authority packaging policy identity.
    pub fn policy_digest(&self) -> &Sha256Digest {
        &self.policy_sha256
    }
}

#[derive(Default, Serialize)]
struct Counts {
    files: usize,
    nodes: usize,
    edges: usize,
    findings: usize,
    invariants: usize,
    tests: usize,
    blind_spots: usize,
    excerpt_bytes: usize,
}
/// Each item is serialized at most once; selection uses a finite byte budget,
/// no graph traversal or recursively expanded references.
fn retain<T: Serialize>(
    items: impl IntoIterator<Item = T>,
    maximum: usize,
    budget: &mut usize,
) -> Result<Vec<Value>, KnowledgeError> {
    let mut output = Vec::new();
    for item in items.into_iter().take(maximum) {
        let value = serde_json::to_value(item).map_err(|_| KnowledgeError::Invalid)?;
        let cost = canonical_bytes(&value)?.len() + 1;
        if cost > *budget {
            break;
        }
        *budget -= cost;
        output.push(value);
    }
    Ok(output)
}

impl SemanticReviewRequest {
    /// Package accepted immutable evidence under an explicit new authority policy.
    /// Mandatory overflow returns INCONCLUSIVE before any provider capability is used.
    pub fn prepare_bounded(
        context: ReviewContext<'_>,
        selection: ReviewerSelection,
        limits: SemanticLimits,
        policy: SemanticPackagingPolicy,
    ) -> Result<Self, KnowledgeError> {
        // Shared validation, claims, observations and legacy identity checks remain
        // identical to schema 1. Projection occurs before any full graph encoding.
        Self::prepare_impl(context, selection, limits, Some(policy))
    }
    pub(super) fn package_request(
        context: &ReviewContext<'_>,
        binding: &ReviewBinding,
        selection: &ReviewerSelection,
        limits: SemanticLimits,
        policy: SemanticPackagingPolicy,
        claims: &[ClaimAssessment],
    ) -> Result<(BoundedSemanticPackage, CanonicalArtifact), KnowledgeError> {
        if limits.request_bytes != policy.maximum_request_bytes
            || limits.excerpt_bytes < policy.maximum_excerpt_bytes
            || limits.file_excerpt_bytes < policy.maximum_file_excerpt_bytes
        {
            return Err(KnowledgeError::BindingMismatch);
        }
        let profile_bytes = context
            .authority_profile_bytes
            .ok_or(KnowledgeError::BindingMismatch)?;
        if profile_bytes.len() > 65536
            || digest_bytes(profile_bytes) != binding.authority_profile_sha256
        {
            return Err(KnowledgeError::BindingMismatch);
        }
        let profile_body: Value =
            serde_json::from_slice(profile_bytes).map_err(|_| KnowledgeError::Invalid)?;
        if canonical_bytes(&profile_body)? != profile_bytes {
            return Err(KnowledgeError::Invalid);
        }
        let k = context.knowledge.body();
        let i = context.impact.body();
        let findings = context
            .bundles
            .iter()
            .flat_map(|b| b.entries())
            .filter(|e| {
                e.approval == ApprovalState::Approved && e.kind == AuthorityEntryKind::Finding
            })
            .count();
        let invariants = context
            .bundles
            .iter()
            .flat_map(|b| b.entries())
            .filter(|e| {
                e.approval == ApprovalState::Approved && e.kind == AuthorityEntryKind::Invariant
            })
            .count();
        if findings > policy.maximum_findings || invariants > policy.maximum_invariants {
            return Err(KnowledgeError::LimitExceeded);
        }
        let policy_sha256 = policy.digest()?;
        let authority: Vec<Value> = context
            .bundles
            .iter()
            .map(|b| {
                serde_json::from_slice(b.artifact().bytes()).map_err(|_| KnowledgeError::Invalid)
            })
            .collect::<Result<_, _>>()?;
        let policy_body: Value =
            serde_json::from_slice(context.policy_bytes).map_err(|_| KnowledgeError::Invalid)?;
        let review_files: BTreeSet<_> = i.review_files.iter().collect();
        let relevant_bytes: usize = context
            .source
            .files()
            .iter()
            .filter(|f| review_files.contains(f.path()))
            .map(|f| f.bytes().len())
            .sum();
        let totals = Counts {
            files: k.files.len(),
            nodes: k.nodes.len(),
            edges: k.edges.len(),
            findings,
            invariants,
            tests: k.nodes.iter().filter(|n| n.kind == NodeKind::Test).count(),
            blind_spots: k.blind_spots.len() + i.blind_spots.len(),
            excerpt_bytes: relevant_bytes,
        };
        let mut body = json!({"schema":1,"kind":"ARCHCERT_SEMANTIC_PACKAGE",
            "binding":binding,"packager_version":PACKAGER_VERSION,"packaging_policy":policy,
            "packaging_policy_sha256":policy_sha256,
            "authority_context":{"policy":policy_body,"knowledge_bundles":authority,"profile":profile_body},
            "coverage_dimensions":k.coverage,
            "impact_summary":{"full_review":i.full_review,"baseline_knowledge_sha256":i.baseline_knowledge_sha256,
                "changed_files":i.changed_files.len(),"added_files":i.added_files.len(),"deleted_files":i.deleted_files.len(),
                "changed_nodes":i.changed_nodes.len(),"dependent_nodes":i.dependent_nodes.len(),
                "unresolved_edges":i.unresolved_impact_edges.len()},
            "untrusted_repository_context":{"files":[],"nodes":[],"edges":[],"excerpts":[],"blind_spots":[],"claims":claims},
            "controller_observations":context.observations,
            "coverage":SemanticContextCoverage::InsufficientContext,
            "included":Counts::default(),"excluded":totals,
            "blind_spots":[{"code":"SEMANTIC_CONTEXT_PARTIAL","reason":"COUNT_OR_REQUEST_BYTE_OR_EXCERPT_LIMIT","categories":"files,nodes,edges,tests,blind_spots,excerpt_bytes;impact-lists-digest-only"}],
            "configured_request_bytes":policy.maximum_request_bytes,"actual_package_bytes":0});
        let envelope = |body: &Value, digest: &Sha256Digest| {
            json!({
                "schema":2,"kind":"ARCHCERT_SEMANTIC_REQUEST","binding":binding,"reviewer":selection,
                "authority_contract":AUTHORITY_REVIEW_CONTRACT,"external_source_disclosure":false,
                "package_sha256":digest,"package":body,"limits":limits,"actual_request_bytes":0
            })
        };
        let base_size = canonical_bytes(&envelope(&body, &digest_bytes(b"")))?.len();
        if base_size > policy.maximum_request_bytes {
            return Err(KnowledgeError::LimitExceeded);
        }
        // Fixed allowance covers count-width growth, size fields and coverage text.
        // Actual full serialization below is always the final authority check.
        let mut budget = policy
            .maximum_request_bytes
            .saturating_sub(base_size + 1024);
        let changed: BTreeSet<_> = i.changed_files.iter().chain(&i.added_files).collect();
        let impacted: BTreeSet<_> = i.dependent_nodes.iter().collect();
        let mut files: Vec<_> = k.files.iter().collect();
        files.sort_by_key(|f| {
            (
                !changed.contains(&f.path),
                !review_files.contains(&f.path),
                &f.path,
            )
        });
        let selected_files = retain(files, policy.maximum_files, &mut budget)?;
        let mut nodes: Vec<_> = k.nodes.iter().collect();
        nodes.sort_by_key(|n| {
            (
                match n.kind {
                    NodeKind::Invariant | NodeKind::KnownFinding | NodeKind::Policy => 0,
                    _ if n.path.as_ref().is_some_and(|p| changed.contains(p)) => 1,
                    _ if impacted.contains(&n.id) && n.kind != NodeKind::Test => 2,
                    NodeKind::Test => 3,
                    NodeKind::Migration | NodeKind::EntryPoint => 4,
                    _ => 5,
                },
                &n.id,
            )
        });
        let mut test_candidates = 0;
        let selected_nodes = retain(
            nodes.into_iter().filter(|n| {
                if n.kind != NodeKind::Test {
                    return true;
                }
                test_candidates += 1;
                test_candidates <= policy.maximum_tests
            }),
            policy.maximum_nodes,
            &mut budget,
        )?;
        let selected_ids: BTreeSet<_> = selected_nodes
            .iter()
            .filter_map(|n| n["id"].as_str())
            .collect();
        let mut edges: Vec<_> = k
            .edges
            .iter()
            .filter(|e| {
                selected_ids.contains(e.from.as_str()) && selected_ids.contains(e.to.as_str())
            })
            .collect();
        // Stable canonical input order breaks ties. No labels or repository claims
        // can provide priority; unresolved is extractor-owned provenance.
        edges.sort_by_key(|e| !e.unresolved);
        let selected_edges = retain(edges, policy.maximum_edges, &mut budget)?;
        let selected_blind = retain(
            k.blind_spots.iter().chain(&i.blind_spots),
            policy.maximum_blind_spots,
            &mut budget,
        )?;
        let paths: BTreeSet<_> = selected_files
            .iter()
            .filter_map(|f| f["path"].as_str())
            .collect();
        let mut excerpts = Vec::new();
        let mut excerpt_bytes = 0;
        for f in context
            .source
            .files()
            .iter()
            .filter(|f| review_files.contains(f.path()) && paths.contains(f.path().as_str()))
        {
            let available = policy
                .maximum_excerpt_bytes
                .saturating_sub(excerpt_bytes)
                .min(policy.maximum_file_excerpt_bytes);
            if available == 0 {
                break;
            }
            let retained = f.bytes().len().min(available);
            let item = json!({"classification":"UNTRUSTED_REPOSITORY_DATA","path":f.path(),"content_sha256":digest_bytes(f.bytes()),
                "full_size":f.bytes().len(),"truncated":retained!=f.bytes().len(),"bytes":&f.bytes()[..retained]});
            let cost = canonical_bytes(&item)?.len() + 1;
            if cost > budget {
                break;
            }
            budget -= cost;
            excerpt_bytes += retained;
            excerpts.push(item);
        }
        let tests = selected_nodes
            .iter()
            .filter(|n| n["kind"] == "TEST")
            .count();
        let included = Counts {
            files: selected_files.len(),
            nodes: selected_nodes.len(),
            edges: selected_edges.len(),
            findings,
            invariants,
            tests,
            blind_spots: selected_blind.len(),
            excerpt_bytes,
        };
        let excluded = Counts {
            files: totals.files - included.files,
            nodes: totals.nodes - included.nodes,
            edges: totals.edges - included.edges,
            findings: 0,
            invariants: 0,
            tests: totals.tests - tests,
            blind_spots: totals.blind_spots - included.blind_spots,
            excerpt_bytes: totals.excerpt_bytes - excerpt_bytes,
        };
        // Impact selection lists are summarized even if the graph happens to fit.
        let partial = excluded.files
            + excluded.nodes
            + excluded.edges
            + excluded.blind_spots
            + excluded.excerpt_bytes
            > 0
            || !i.deleted_files.is_empty()
            || !i.changed_nodes.is_empty()
            || !i.dependent_nodes.is_empty();
        let coverage = if !partial {
            SemanticContextCoverage::FullContext
        } else if policy.accept_partial {
            SemanticContextCoverage::PartialAcceptable
        } else {
            SemanticContextCoverage::InsufficientContext
        };
        body["coverage"] = json!(coverage);
        body["included"] = json!(included);
        body["excluded"] = json!(excluded);
        if !partial {
            body["blind_spots"] = json!([]);
        }
        body["untrusted_repository_context"]["files"] = json!(selected_files);
        body["untrusted_repository_context"]["nodes"] = json!(selected_nodes);
        body["untrusted_repository_context"]["edges"] = json!(selected_edges);
        body["untrusted_repository_context"]["blind_spots"] = json!(selected_blind);
        body["untrusted_repository_context"]["excerpts"] = json!(excerpts);
        stabilize_size(&mut body, "actual_package_bytes")?;
        let artifact = CanonicalArtifact::freeze(&body, policy.maximum_request_bytes)?;
        let mut request = envelope(&body, artifact.digest());
        stabilize_size(&mut request, "actual_request_bytes")?;
        let request = CanonicalArtifact::freeze(&request, policy.maximum_request_bytes)?;
        Ok((
            BoundedSemanticPackage {
                artifact,
                policy_sha256,
                coverage,
            },
            request,
        ))
    }
    /// Separate immutable package; legacy requests have none.
    pub fn package(&self) -> Option<&BoundedSemanticPackage> {
        self.package.as_ref()
    }
    /// Authority permits this context for bounded review, not a complete-source claim.
    pub fn context_sufficient(&self) -> bool {
        self.package.as_ref().map_or(self.complete, |p| {
            p.coverage != SemanticContextCoverage::InsufficientContext
        })
    }
}
fn stabilize_size(value: &mut Value, key: &str) -> Result<(), KnowledgeError> {
    // Decimal size has at most seven digits under the fixed 1 MiB ceiling.
    for _ in 0..8 {
        let size = canonical_bytes(value)?.len();
        if value[key] == json!(size) {
            return Ok(());
        }
        value[key] = json!(size);
    }
    Err(KnowledgeError::Invalid)
}
