//! Bounded knowledge composition over accepted snapshots, never a mutable checkout.

use archcert_domain::{
    ProjectId, Sha256Digest, SourceIdentity,
    knowledge::*,
    source::{RepositoryId, SourceFile, SourceMode, SourcePath, SourceSnapshot, digest_bytes},
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

mod impact;

pub use impact::*;

/// Fixed upper bounds; authority may lower them, never select an unlimited mode.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct KnowledgeLimits {
    /// Accepted inventory entry count.
    pub files: usize,
    /// Aggregate retained source bytes visited.
    pub source_bytes: usize,
    /// Structural parser byte budget per file.
    pub structural_file_bytes: usize,
    /// Total graph nodes.
    pub nodes: usize,
    /// Total graph edges.
    pub edges: usize,
    /// Retained omissions.
    pub blind_spots: usize,
    /// Maximum relation closure depth.
    pub impact_depth: usize,
}

impl Default for KnowledgeLimits {
    fn default() -> Self {
        Self {
            files: 10_000,
            source_bytes: 64 * 1024 * 1024,
            structural_file_bytes: 128 * 1024,
            nodes: 40_000,
            edges: 100_000,
            blind_spots: 20_000,
            impact_depth: 16,
        }
    }
}

impl KnowledgeLimits {
    fn validate(self) -> Result<(), KnowledgeError> {
        let max = Self::default();

        for (value, ceiling) in [
            (self.files, max.files),
            (self.source_bytes, max.source_bytes),
            (self.structural_file_bytes, max.structural_file_bytes),
            (self.nodes, max.nodes),
            (self.edges, max.edges),
            (self.blind_spots, max.blind_spots),
            (self.impact_depth, max.impact_depth),
        ] {
            if value == 0 || value > ceiling {
                return Err(KnowledgeError::LimitExceeded);
            }
        }

        Ok(())
    }
}

/// Fixed failures contain no hostile source or provider diagnostics.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KnowledgeError {
    /// Counts or bytes exceeded an explicit authority bound.
    #[error("knowledge resource limit exceeded; completeness not established")]
    LimitExceeded,
    /// Invalid source, graph, authority input or canonical value.
    #[error("invalid knowledge input or artifact")]
    Invalid,
    /// Project/repository/source/baseline substitution.
    #[error("knowledge scope or immutable binding mismatch")]
    BindingMismatch,
}

/// Restricted canonical JSON from ADR 0041. No arbitrary map keys, floats or
/// unsafe integer ranges. This does not redefine existing source/certificate bytes.
pub fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, KnowledgeError> {
    fn valid(v: &Value) -> bool {
        match v {
            Value::Object(m) => m.iter().all(|(k, v)| k.is_ascii() && valid(v)),
            Value::Array(a) => a.iter().all(valid),
            Value::Number(n) => {
                n.as_u64().is_some_and(|n| n <= 9_007_199_254_740_991)
                    || n.as_i64().is_some_and(|n| {
                        (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&n)
                    })
            }
            _ => true,
        }
    }

    let mut value = serde_json::to_value(value).map_err(|_| KnowledgeError::Invalid)?;

    if !valid(&value) {
        return Err(KnowledgeError::Invalid);
    }

    value.sort_all_objects();
    serde_json::to_vec(&value).map_err(|_| KnowledgeError::Invalid)
}

/// Immutable canonical bytes with an independently calculated identity.
/// Debug deliberately omits payload bytes which may contain private source.
pub struct CanonicalArtifact {
    bytes: Vec<u8>,
    digest: Sha256Digest,
}

impl std::fmt::Debug for CanonicalArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanonicalArtifact")
            .field("sha256", &self.digest)
            .field("size", &self.bytes.len())
            .finish()
    }
}

impl CanonicalArtifact {
    /// Freeze an already validated model under a finite serialized artifact bound.
    pub fn freeze(value: &impl Serialize, maximum: usize) -> Result<Self, KnowledgeError> {
        let bytes = canonical_bytes(value)?;

        if bytes.len() > maximum {
            return Err(KnowledgeError::LimitExceeded);
        }

        Ok(Self {
            digest: digest_bytes(&bytes),
            bytes,
        })
    }

    /// Exact canonical bytes for immutable persistence.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Exact canonical SHA-256, never a signature or proof.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
}

/// Frozen authority data, never parsed from target source/configuration.
#[derive(Debug)]
pub struct AuthorityKnowledgeBundle {
    id: String,
    version: String,
    scope: KnowledgeScope,
    entries: Vec<AuthorityKnowledgeEntry>,
    artifact: CanonicalArtifact,
}

impl AuthorityKnowledgeBundle {
    /// Trusted provisioning only. Versions and supersession are immutable content;
    /// this API provides no target-controlled approval/downgrade operation.
    pub fn approve(
        id: String,
        version: String,
        scope: KnowledgeScope,
        mut entries: Vec<AuthorityKnowledgeEntry>,
    ) -> Result<Self, KnowledgeError> {
        if !identifier(&id) || !identifier(&version) || entries.len() > 128 {
            return Err(KnowledgeError::Invalid);
        }

        entries.sort_by(|a, b| a.id.cmp(&b.id));
        let mut ids = BTreeSet::new();

        for e in &mut entries {
            if !identifier(&e.id)
                || !identifier(&e.version)
                || !identifier(&e.authority)
                || e.scope != scope
                || e.description.is_empty()
                || e.description.len() > 4096
                || e.origin.is_empty()
                || e.origin.len() > 512
                || e.paths.len() > 128
                || e.policy_sha256.len() > 32
                || !ids.insert(e.id.clone())
                || e.supersedes.as_ref().is_some_and(|s| {
                    !identifier(&s.id)
                        || !identifier(&s.version)
                        || (s.id == e.id && s.version == e.version)
                })
            {
                return Err(KnowledgeError::Invalid);
            }

            e.paths.sort();
            e.paths.dedup();
            e.policy_sha256.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            e.policy_sha256.dedup();
        }

        let artifact = CanonicalArtifact::freeze(
            &serde_json::json!({
                "schema": 1,
                "kind": "ARCHCERT_AUTHORITY_KNOWLEDGE",
                "id": id,
                "version": version,
                "scope": scope,
                "entries": entries
            }),
            1024 * 1024,
        )?;

        Ok(Self {
            id,
            version,
            scope,
            entries,
            artifact,
        })
    }

    /// Canonical immutable bundle identity and bytes.
    pub fn artifact(&self) -> &CanonicalArtifact {
        &self.artifact
    }

    /// Stable authority bundle label.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Immutable authority version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Explicit project/global visibility.
    pub fn scope(&self) -> &KnowledgeScope {
        &self.scope
    }

    /// Read-only assertions including approval and supersession history.
    pub fn entries(&self) -> &[AuthorityKnowledgeEntry] {
        &self.entries
    }
}

/// Exact authority baseline selection. No target wire/configuration constructor.
#[derive(Debug, Clone, Serialize)]
pub struct SelectedBaseline {
    project: ProjectId,
    repository: RepositoryId,
    source: SourceIdentity,
    reason: String,
}

impl SelectedBaseline {
    /// Trusted operator/application selection from an already accepted snapshot.
    pub fn accepted(snapshot: &SourceSnapshot, reason: String) -> Result<Self, KnowledgeError> {
        snapshot
            .verify(&snapshot.identity().snapshot_sha256)
            .map_err(|_| KnowledgeError::Invalid)?;
        snapshot
            .require_complete()
            .map_err(|_| KnowledgeError::Invalid)?;

        if reason.is_empty() || reason.len() > 512 {
            return Err(KnowledgeError::Invalid);
        }

        Ok(Self {
            project: snapshot.project(),
            repository: snapshot.repository().clone(),
            source: snapshot.identity().clone(),
            reason,
        })
    }

    /// Exact selected source; cannot be replaced with a target-requested revision.
    pub fn source(&self) -> &SourceIdentity {
        &self.source
    }
}

/// Complete file inventory, including non-executable and unsupported data.
#[derive(Debug, Clone, Serialize)]
pub struct InventoryFile {
    /// Exact accepted relative path.
    pub path: SourcePath,
    /// Digest independently derived from accepted bytes.
    pub sha256: Sha256Digest,
    /// Original Git leaf mode, including symlink and executable distinctions.
    pub git_mode: u32,
    /// Exact retained payload bytes.
    pub size: u64,
    /// Bounded observational classification, not language correctness proof.
    pub classification: String,
}

/// An immutable read model. Only KnowledgeEngine can construct an accepted artifact.
#[derive(Debug, Serialize)]
pub struct KnowledgeBody {
    schema: u32,
    kind: &'static str,
    /// Authority scope.
    pub project: ProjectId,
    /// Authority repository.
    pub repository: RepositoryId,
    /// Full immutable target identity.
    pub source: SourceIdentity,
    /// Separately selected baseline, if any.
    pub baseline: Option<SelectedBaseline>,
    /// Versioned extractor semantics in canonical order.
    pub extractors: Vec<String>,
    /// Canonical authority bundle identities in sorted order.
    pub authority_bundles: Vec<Sha256Digest>,
    /// All accepted source entries in exact path order.
    pub files: Vec<InventoryFile>,
    /// Typed graph sorted by node ID.
    pub nodes: Vec<KnowledgeNode>,
    /// Typed graph sorted by canonical edge bytes.
    pub edges: Vec<KnowledgeEdge>,
    /// Persistent uncertainty, sorted/deduplicated by canonical bytes.
    pub blind_spots: Vec<BlindSpot>,
    /// Independent dimensions with reasons.
    pub coverage: Vec<KnowledgeCoverage>,
    /// Bounds are part of identity.
    pub limits: KnowledgeLimits,
}

/// Digest-bound knowledge; no mutation or Deserialize acceptance capability.
#[derive(Debug)]
pub struct KnowledgeArtifact {
    body: KnowledgeBody,
    artifact: CanonicalArtifact,
}

impl KnowledgeArtifact {
    /// Immutable structured context.
    pub fn body(&self) -> &KnowledgeBody {
        &self.body
    }

    /// Canonical persistent bytes and digest.
    pub fn artifact(&self) -> &CanonicalArtifact {
        &self.artifact
    }
}

/// Structural extractor port: no path to a checkout, source mutation, execution,
/// network, credentials or authority bundle editor is available.
pub trait KnowledgeExtractor: Send + Sync {
    /// Authority-selected semantic version, never read from target configuration.
    fn identity(&self) -> &'static str;

    /// Bounded classification match; symlink payloads are never parsed as files.
    fn supports(&self, file: &SourceFile) -> bool;

    /// Emits only structural facts through the restricted bounded sink.
    fn extract(
        &self,
        file: &SourceFile,
        sink: &mut StructuralSink<'_>,
    ) -> Result<(), KnowledgeError>;
}

/// A restricted graph writer. Extractors cannot insert authority facts or proofs.
pub struct StructuralSink<'a> {
    path: &'a SourcePath,
    graph: &'a mut Graph,
}

impl StructuralSink<'_> {
    /// Adds observed syntax under a stable extractor-local key.
    pub fn node(
        &mut self,
        key: &str,
        kind: NodeKind,
        label: String,
        syntax: &[u8],
    ) -> Result<String, KnowledgeError> {
        if key.is_empty()
            || key.len() > 4096
            || label.len() > 4096
            || !matches!(
                kind,
                NodeKind::Symbol
                    | NodeKind::Module
                    | NodeKind::Dependency
                    | NodeKind::Test
                    | NodeKind::Migration
                    | NodeKind::EntryPoint
            )
        {
            return Err(KnowledgeError::Invalid);
        }

        let id = format!(
            "syntax:{}",
            digest_bytes(&canonical_bytes(&(self.path, key))?).as_str()
        );
        self.graph.node(KnowledgeNode {
            id: id.clone(),
            kind,
            path: Some(self.path.clone()),
            label,
            content_sha256: digest_bytes(syntax),
            provenance: Provenance::DirectlyObserved,
        })?;
        self.graph.edge(KnowledgeEdge {
            from: file_id(self.path),
            to: id.clone(),
            kind: RelationKind::Defines,
            unresolved: false,
            provenance: Provenance::DirectlyObserved,
        })?;

        Ok(id)
    }

    /// Relates syntax only. Unresolved imports/references never become resolved calls.
    pub fn edge(
        &mut self,
        from: String,
        to: String,
        kind: RelationKind,
        unresolved: bool,
    ) -> Result<(), KnowledgeError> {
        if !matches!(
            kind,
            RelationKind::Defines
                | RelationKind::Imports
                | RelationKind::References
                | RelationKind::Tests
                | RelationKind::Implements
        ) || (matches!(kind, RelationKind::Imports | RelationKind::References) && !unresolved)
        {
            return Err(KnowledgeError::Invalid);
        }

        self.graph.edge(KnowledgeEdge {
            from,
            to,
            kind,
            unresolved,
            provenance: Provenance::DirectlyObserved,
        })
    }

    /// The exact containing source node, for syntactic import relationships.
    pub fn file_node(&self) -> String {
        file_id(self.path)
    }

    /// Retains a bounded omission instead of fabricating a fact.
    pub fn blind_spot(&mut self, code: &str, reason: &str) -> Result<(), KnowledgeError> {
        self.graph.blind(BlindSpot {
            code: code.into(),
            path: Some(self.path.clone()),
            reason: reason.into(),
        })
    }

    /// Maximum parser input bytes; exceeding it must retain an explicit omission.
    pub fn file_byte_limit(&self) -> usize {
        self.graph.limits.structural_file_bytes
    }
}

fn file_id(path: &SourcePath) -> String {
    format!("file:{}", path.as_str())
}

struct Graph {
    nodes: BTreeMap<String, KnowledgeNode>,
    edges: BTreeMap<Vec<u8>, KnowledgeEdge>,
    blind_spots: BTreeMap<Vec<u8>, BlindSpot>,
    limits: KnowledgeLimits,
}

impl Graph {
    fn node(&mut self, n: KnowledgeNode) -> Result<(), KnowledgeError> {
        if self.nodes.len() >= self.limits.nodes {
            return Err(KnowledgeError::LimitExceeded);
        }

        if self.nodes.insert(n.id.clone(), n).is_some() {
            return Err(KnowledgeError::Invalid);
        }

        Ok(())
    }

    fn edge(&mut self, e: KnowledgeEdge) -> Result<(), KnowledgeError> {
        if self.edges.len() >= self.limits.edges {
            return Err(KnowledgeError::LimitExceeded);
        }

        if !self.nodes.contains_key(&e.from) || !self.nodes.contains_key(&e.to) {
            return Err(KnowledgeError::Invalid);
        }

        self.edges.insert(canonical_bytes(&e)?, e);

        Ok(())
    }

    fn blind(&mut self, b: BlindSpot) -> Result<(), KnowledgeError> {
        if !identifier(&b.code) || b.reason.is_empty() || b.reason.len() > 2048 {
            return Err(KnowledgeError::Invalid);
        }

        if self.blind_spots.len() >= self.limits.blind_spots {
            return Err(KnowledgeError::LimitExceeded);
        }

        self.blind_spots.insert(canonical_bytes(&b)?, b);

        Ok(())
    }
}

/// Explicit extractor registry; no source-controlled discovery or dynamic plugins.
pub struct KnowledgeEngine {
    extractors: Vec<Box<dyn KnowledgeExtractor>>,
    limits: KnowledgeLimits,
}

impl KnowledgeEngine {
    /// Authority constructs a bounded versioned registry.
    pub fn new(
        mut extractors: Vec<Box<dyn KnowledgeExtractor>>,
        limits: KnowledgeLimits,
    ) -> Result<Self, KnowledgeError> {
        limits.validate()?;

        if extractors.len() > 16 {
            return Err(KnowledgeError::LimitExceeded);
        }

        extractors.sort_by_key(|e| e.identity());
        let mut ids = BTreeSet::new();

        for e in &extractors {
            if !identifier(e.identity()) || !ids.insert(e.identity()) {
                return Err(KnowledgeError::Invalid);
            }
        }

        Ok(Self { extractors, limits })
    }

    /// Digest of the complete authority-selected inventory/extractor registry,
    /// available before source or private knowledge is read.
    pub fn registry_digest(&self) -> Result<Sha256Digest, KnowledgeError> {
        Ok(digest_bytes(&canonical_bytes(
            &self.extractor_identities(),
        )?))
    }

    fn extractor_identities(&self) -> Vec<String> {
        std::iter::once("archcert-inventory-v1/1.0.0".into())
            .chain(self.extractors.iter().map(|e| e.identity().into()))
            .collect()
    }

    /// Rehashes exact accepted bytes. Caller supplies authority-owned bundles and
    /// baseline; repository files are never interpreted as either capability.
    pub fn extract(
        &self,
        source: &SourceSnapshot,
        bundles: &[AuthorityKnowledgeBundle],
        baseline: Option<&SelectedBaseline>,
    ) -> Result<KnowledgeArtifact, KnowledgeError> {
        if source.files().len() > self.limits.files
            || source.total_bytes() > self.limits.source_bytes as u64
            || bundles.len() > 16
        {
            return Err(KnowledgeError::LimitExceeded);
        }

        source
            .verify(&source.identity().snapshot_sha256)
            .map_err(|_| KnowledgeError::Invalid)?;
        source
            .require_complete()
            .map_err(|_| KnowledgeError::Invalid)?;

        if bundles.iter().any(|b| !b.scope.permits(source.project()))
            || baseline.is_some_and(|b| {
                b.project != source.project() || b.repository != *source.repository()
            })
        {
            return Err(KnowledgeError::BindingMismatch);
        }

        let mut graph = Graph {
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            blind_spots: BTreeMap::new(),
            limits: self.limits,
        };
        let mut files = Vec::new();

        for f in source.files() {
            let entry = f.manifest_entry();
            let regular = matches!(f.mode(), SourceMode::File | SourceMode::Executable);
            let classification = if !regular {
                "NON_REGULAR"
            } else if f.path().as_str().ends_with(".rs") {
                "RUST"
            } else if f.path().as_str().ends_with(".sql") {
                "SQL"
            } else if std::str::from_utf8(f.bytes()).is_ok() {
                "OTHER_TEXT"
            } else {
                "BINARY"
            };
            files.push(InventoryFile {
                path: f.path().clone(),
                sha256: entry.content_sha256().clone(),
                git_mode: f.mode().git_mode(),
                size: entry.size(),
                classification: classification.into(),
            });
            graph.node(KnowledgeNode {
                id: file_id(f.path()),
                kind: NodeKind::SourceFile,
                path: Some(f.path().clone()),
                label: f.path().as_str().into(),
                content_sha256: entry.content_sha256().clone(),
                provenance: Provenance::DirectlyObserved,
            })?;
            let mut supported = false;

            if regular {
                for e in &self.extractors {
                    if e.supports(f) {
                        supported = true;
                        e.extract(
                            f,
                            &mut StructuralSink {
                                path: f.path(),
                                graph: &mut graph,
                            },
                        )?;
                    }
                }
            }

            if classification == "SQL" {
                let mut sink = StructuralSink {
                    path: f.path(),
                    graph: &mut graph,
                };
                sink.node(
                    "sql-file",
                    NodeKind::Migration,
                    "SQL file; migration intent unverified".into(),
                    f.bytes(),
                )?;
                sink.blind_spot(
                    "UNSUPPORTED_SQL",
                    "SQL bytes inventoried; schema, ordering and migration safety are not analyzed",
                )?;
            } else if !supported {
                graph.blind(BlindSpot {
                    code: "UNSUPPORTED_STRUCTURE".into(),
                    path: Some(f.path().clone()),
                    reason:
                        "Inventory only; structural relationships are unavailable for this entry"
                            .into(),
                })?;
            }
        }

        let mut authority_digests = Vec::new();
        let mut bundle_names = BTreeSet::new();

        for b in bundles {
            if !bundle_names.insert(b.id()) {
                return Err(KnowledgeError::Invalid);
            }

            authority_digests.push(b.artifact.digest().clone());

            for e in &b.entries {
                if e.approval != ApprovalState::Approved {
                    graph.blind(BlindSpot {
                        code: "UNAPPROVED_AUTHORITY_KNOWLEDGE".into(),
                        path: None,
                        reason: format!("Authority entry {} is not approved", e.id),
                    })?;
                    continue;
                }

                let id = format!("authority:{}:{}", b.artifact.digest().as_str(), e.id);
                let (kind, relation) = match e.kind {
                    AuthorityEntryKind::Invariant => {
                        (NodeKind::Invariant, RelationKind::RelatedToInvariant)
                    }
                    AuthorityEntryKind::Finding => {
                        (NodeKind::KnownFinding, RelationKind::RelatedToFinding)
                    }
                    AuthorityEntryKind::PolicyAssociation => {
                        (NodeKind::Policy, RelationKind::GovernedBy)
                    }
                };
                graph.node(KnowledgeNode {
                    id: id.clone(),
                    kind,
                    path: None,
                    label: e.id.clone(),
                    content_sha256: digest_bytes(&canonical_bytes(e)?),
                    provenance: Provenance::AuthorityAsserted,
                })?;

                for f in &files {
                    if e.paths.is_empty() || e.paths.contains(&f.path) {
                        graph.edge(KnowledgeEdge {
                            from: file_id(&f.path),
                            to: id.clone(),
                            kind: relation,
                            unresolved: false,
                            provenance: Provenance::AuthorityAsserted,
                        })?;
                    }
                }
            }
        }

        if bundles.is_empty() {
            graph.blind(BlindSpot {
                code: "AUTHORITY_KNOWLEDGE_UNAVAILABLE".into(),
                path: None,
                reason: "No authority invariant/finding bundle was selected; domain knowledge is incomplete".into()
            })?;
        }

        if baseline.is_none() {
            graph.blind(BlindSpot {
                code: "MISSING_TRUSTED_BASELINE".into(),
                path: None,
                reason: "No authority-selected trusted baseline; full review is required".into(),
            })?;
        }

        authority_digests.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        authority_digests.dedup();

        let coverage = vec![
            coverage(
                CoverageDimension::SourceInventory,
                CoverageState::Complete,
                "Every accepted source entry, byte digest and mode is inventoried",
            ),
            coverage(
                CoverageDimension::RustStructure,
                if graph.nodes.values().any(|n| {
                    n.kind != NodeKind::SourceFile
                        && n.path.as_ref().is_some_and(|p| p.as_str().ends_with(".rs"))
                }) {
                    CoverageState::Partial
                } else {
                    CoverageState::NotAvailable
                },
                "Syntax only; unsupported constructs and macro expansion remain explicit",
            ),
            coverage(
                CoverageDimension::ReferenceResolution,
                CoverageState::NotAvailable,
                "No compiler name, type or dynamic dispatch resolution",
            ),
            coverage(
                CoverageDimension::DatabaseSchema,
                CoverageState::NotAvailable,
                "SQL identity only; no schema model or database connection",
            ),
            coverage(
                CoverageDimension::TestMapping,
                CoverageState::NotAvailable,
                "Test declarations may be observed; intended behavioral relationships are unresolved",
            ),
            coverage(
                CoverageDimension::GitBaseline,
                if baseline.is_some() {
                    CoverageState::Complete
                } else {
                    CoverageState::NotAvailable
                },
                "Authority-selected immutable identity only; impact scope remains conservative",
            ),
            coverage(
                CoverageDimension::SemanticReview,
                CoverageState::NotAvailable,
                "Structural extraction does not perform semantic review",
            ),
        ];

        let body = KnowledgeBody {
            schema: 1,
            kind: "ARCHCERT_KNOWLEDGE",
            project: source.project(),
            repository: source.repository().clone(),
            source: source.identity().clone(),
            baseline: baseline.cloned(),
            extractors: self.extractor_identities(),
            authority_bundles: authority_digests,
            files,
            nodes: graph.nodes.into_values().collect(),
            edges: graph.edges.into_values().collect(),
            blind_spots: graph.blind_spots.into_values().collect(),
            coverage,
            limits: self.limits,
        };

        let artifact = CanonicalArtifact::freeze(&body, 32 * 1024 * 1024)?;

        Ok(KnowledgeArtifact { body, artifact })
    }
}

fn coverage(dimension: CoverageDimension, state: CoverageState, reason: &str) -> KnowledgeCoverage {
    KnowledgeCoverage {
        dimension,
        state,
        reason: reason.into(),
    }
}
