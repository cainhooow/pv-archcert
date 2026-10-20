//! Conservative immutable manifest/graph impact, with explicit review expansion.
use super::*;

/// Immutable impact summary. Relation uncertainty can only expand review.
#[derive(Debug, Serialize)]
pub struct ImpactBody {
    schema: u32,
    kind: &'static str,
    /// Authority scope.
    pub project: ProjectId,
    /// Exact target identity.
    pub source: SourceIdentity,
    /// Exact target knowledge identity.
    pub knowledge_sha256: Sha256Digest,
    /// Selected trusted baseline identity, if available.
    pub baseline_source: Option<SourceIdentity>,
    /// Exact baseline knowledge used, if available.
    pub baseline_knowledge_sha256: Option<Sha256Digest>,
    /// Uncertainty requires full review, not an invented empty delta.
    pub full_review: bool,
    /// Same path with different bytes or Git mode.
    pub changed_files: Vec<SourcePath>,
    /// Newly present paths.
    pub added_files: Vec<SourcePath>,
    /// Previously present paths, including removed tests/authority associations.
    pub deleted_files: Vec<SourcePath>,
    /// Changed, added or removed structural identities.
    pub changed_nodes: Vec<String>,
    /// Conservatively selected target files; never removes deterministic steps.
    pub review_files: Vec<SourcePath>,
    /// Nodes reached mechanically or included by conservative full review.
    pub dependent_nodes: Vec<String>,
    /// Syntactically associated tests; this is not behavioral coverage proof.
    pub related_tests: Vec<String>,
    /// Authority invariant IDs in impact scope.
    pub related_invariants: Vec<String>,
    /// Authority policy associations in impact scope.
    pub related_policies: Vec<String>,
    /// Authority findings in impact scope.
    pub related_findings: Vec<String>,
    /// Explicit syntactic relationships that lack resolution.
    pub unresolved_impact_edges: Vec<KnowledgeEdge>,
    /// Persistent omissions from both source states and impact traversal.
    pub blind_spots: Vec<BlindSpot>,
}
/// Frozen impact evidence; callers cannot mutate a selected baseline or result.
#[derive(Debug)]
pub struct ImpactArtifact {
    body: ImpactBody,
    artifact: CanonicalArtifact,
}
impl ImpactArtifact {
    /// Read-only impact scope and uncertainty.
    pub fn body(&self) -> &ImpactBody {
        &self.body
    }
    /// Canonical evidence bytes/digest.
    pub fn artifact(&self) -> &CanonicalArtifact {
        &self.artifact
    }
}
/// Compare immutable source manifests and supported graph relations. A baseline
/// artifact must reproduce the authority-selected exact project/repository/source.
pub fn analyze_impact(
    target: &KnowledgeArtifact,
    baseline: Option<&KnowledgeArtifact>,
) -> Result<ImpactArtifact, KnowledgeError> {
    let t = target.body();
    match (&t.baseline, baseline) {
        (Some(selected), Some(b))
            if selected.project == b.body.project
                && selected.repository == b.body.repository
                && selected.source == b.body.source
                && t.project == b.body.project
                && t.repository == b.body.repository => {}
        (None, None) => {}
        _ => return Err(KnowledgeError::BindingMismatch),
    }
    let old: BTreeMap<_, _> = baseline
        .into_iter()
        .flat_map(|b| &b.body.files)
        .map(|f| (&f.path, f))
        .collect();
    let new: BTreeMap<_, _> = t.files.iter().map(|f| (&f.path, f)).collect();
    let changed_files: Vec<_> = new
        .iter()
        .filter(|(p, f)| {
            old.get(*p)
                .is_some_and(|o| o.sha256 != f.sha256 || o.git_mode != f.git_mode)
        })
        .map(|(p, _)| (*p).clone())
        .collect();
    let added_files: Vec<_> = new
        .keys()
        .filter(|p| !old.contains_key(*p))
        .map(|p| (*p).clone())
        .collect();
    let deleted_files: Vec<_> = old
        .keys()
        .filter(|p| !new.contains_key(*p))
        .map(|p| (*p).clone())
        .collect();
    let old_nodes: BTreeMap<_, _> = baseline
        .into_iter()
        .flat_map(|b| &b.body.nodes)
        .map(|n| (&n.id, n))
        .collect();
    let new_nodes: BTreeMap<_, _> = t.nodes.iter().map(|n| (&n.id, n)).collect();
    let mut changed_nodes = BTreeSet::new();
    for (id, n) in &new_nodes {
        if old_nodes.get(id).is_none_or(|old| *old != *n) {
            changed_nodes.insert((*id).clone());
        }
    }
    for id in old_nodes.keys() {
        if !new_nodes.contains_key(id) {
            changed_nodes.insert((*id).clone());
        }
    }
    let mut blind_spots: BTreeMap<_, _> = t
        .blind_spots
        .iter()
        .chain(baseline.into_iter().flat_map(|b| &b.body.blind_spots))
        .map(|b| Ok((canonical_bytes(b)?, b.clone())))
        .collect::<Result<_, KnowledgeError>>()?;
    let mut full_review = baseline.is_none()
        || !blind_spots.is_empty()
        || baseline.is_some_and(|b| {
            b.body.extractors != t.extractors || b.body.authority_bundles != t.authority_bundles
        });
    let all_edges: Vec<_> = t
        .edges
        .iter()
        .chain(baseline.into_iter().flat_map(|b| &b.body.edges))
        .collect();
    let unresolved_impact_edges: Vec<_> = all_edges
        .iter()
        .filter(|e| e.unresolved)
        .map(|e| (*e).clone())
        .collect();
    if !unresolved_impact_edges.is_empty() {
        full_review = true;
    }
    let mut affected: BTreeSet<String> = changed_nodes.clone();
    for p in changed_files
        .iter()
        .chain(&added_files)
        .chain(&deleted_files)
    {
        affected.insert(file_id(p));
    }
    for depth in 0..=t.limits.impact_depth {
        let mut next = affected.clone();
        for e in &all_edges {
            if affected.contains(&e.from) || affected.contains(&e.to) {
                next.insert(e.from.clone());
                next.insert(e.to.clone());
            }
        }
        if next == affected {
            break;
        }
        if depth == t.limits.impact_depth {
            full_review = true;
            let b = BlindSpot {
                code: "IMPACT_DEPTH_EXHAUSTED".into(),
                path: None,
                reason: "Bounded impact traversal exhausted; all target files require review"
                    .into(),
            };
            blind_spots.insert(canonical_bytes(&b)?, b);
            break;
        }
        affected = next;
    }
    if full_review {
        affected.extend(new_nodes.keys().map(|s| (*s).clone()));
        affected.extend(old_nodes.keys().map(|s| (*s).clone()));
    }
    let related = |kind| {
        new_nodes
            .values()
            .chain(old_nodes.values())
            .filter(|n| n.kind == kind && affected.contains(&n.id))
            .map(|n| n.id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    let body = ImpactBody {
        schema: 1,
        kind: "ARCHCERT_IMPACT",
        project: t.project,
        source: t.source.clone(),
        knowledge_sha256: target.artifact.digest().clone(),
        baseline_source: baseline.map(|b| b.body.source.clone()),
        baseline_knowledge_sha256: baseline.map(|b| b.artifact.digest().clone()),
        full_review,
        changed_files,
        added_files,
        deleted_files,
        changed_nodes: changed_nodes.into_iter().collect(),
        review_files: t
            .files
            .iter()
            .filter(|f| full_review || affected.contains(&file_id(&f.path)))
            .map(|f| f.path.clone())
            .collect(),
        related_tests: related(NodeKind::Test),
        related_invariants: related(NodeKind::Invariant),
        related_policies: related(NodeKind::Policy),
        related_findings: related(NodeKind::KnownFinding),
        dependent_nodes: affected.into_iter().collect(),
        unresolved_impact_edges,
        blind_spots: blind_spots.into_values().collect(),
    };
    let artifact = CanonicalArtifact::freeze(&body, 32 * 1024 * 1024)?;
    Ok(ImpactArtifact { body, artifact })
}
