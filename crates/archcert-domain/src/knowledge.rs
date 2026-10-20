//! Knowledge vocabulary. Observation, authority assertion and inference are distinct.
use crate::{ProjectId, Sha256Digest, source::SourcePath};
use serde::{Deserialize, Serialize};

macro_rules! vocabulary {
    ($name:ident, $doc:literal, {$($variant:ident => $description:literal),+ $(,)?}) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
        pub enum $name { $(#[doc = $description] $variant),+ }
    };
}
vocabulary!(NodeKind, "Generic typed knowledge; no language-specific graph schema.", {
    SourceFile => "An exact accepted source entry.",
    Symbol => "An observed syntactic declaration.",
    Module => "An observed module declaration.",
    Dependency => "An observed import or unresolved reference spelling.",
    Test => "A syntactically identified test declaration, not test quality proof.",
    Migration => "A migration file, not an inferred database schema.",
    EntryPoint => "An observed entry point, with extractor-specific evidence.",
    Policy => "A separately provisioned authority policy association.",
    Invariant => "A separately provisioned authority invariant.",
    KnownFinding => "A separately provisioned authority finding.",
    AgentClaim => "An untrusted author claim.",
    CertificationEvidence => "An exact prior evidence reference selected by authority.",
    BlindSpot => "An explicitly unresolved knowledge area."
});
vocabulary!(RelationKind, "Relations describe observations, never an invented resolved call graph.", {
    Defines => "A source or syntactic container declares a node.",
    Imports => "An observed import spelling; resolution is separately recorded.",
    References => "A syntactic reference, not a resolved call.",
    Tests => "A test relationship established by the named extractor.",
    Affects => "A conservative bounded impact relationship.",
    Implements => "An observed implementation relationship.",
    GovernedBy => "An authority-provisioned policy association.",
    RelatedToFinding => "An authority-provisioned finding association.",
    RelatedToInvariant => "An authority-provisioned invariant association.",
    Claims => "An untrusted claim about another node.",
    Contradicts => "A referenced evidence item contradicts an untrusted claim."
});
vocabulary!(Provenance, "Evidence confidence is categorical provenance, separate from coverage.", {
    DirectlyObserved => "Retained source syntax or exact canonical bytes.",
    DeterministicallyDerived => "A mechanical derivation from bound inputs.",
    AuthorityAsserted => "A separately approved authority assertion.",
    SemanticallyInferred => "A semantic hypothesis, never deterministic proof.",
    Unresolved => "No supported derivation establishes the relationship."
});
vocabulary!(CoverageState, "Dimensional coverage, never a correctness percentage.", {
    Complete => "The explicitly bounded dimension was fully inventoried.",
    Partial => "Supported observations exist with explicit omissions.",
    NotAvailable => "This dimension has no supported analysis."
});
vocabulary!(CoverageDimension, "Independent coverage dimensions.", {
    SourceInventory => "Accepted source inventory.",
    RustStructure => "Rust syntax, excluding compilation and macro expansion.",
    ReferenceResolution => "Name/type/call resolution.",
    DatabaseSchema => "Database schema analysis.",
    TestMapping => "Mapping tests to intended behavior.",
    GitBaseline => "Authority-selected exact baseline availability.",
    SemanticReview => "Accepted semantic context and response availability."
});
vocabulary!(ApprovalState, "Authority-owned approval state; source cannot approve anything.", {
    Draft => "Not approved as authority knowledge.",
    Approved => "Approved by the separately provisioned authority.",
    Retired => "Retained history that is no longer approved for new composition."
});
vocabulary!(KnowledgeSeverity, "Authority assertion priority, separate from deterministic verdicts.", {
    Critical => "Critical authority concern.",
    High => "High-priority authority concern.",
    Medium => "Additional authority scrutiny.",
    Informational => "Context only."
});
vocabulary!(AuthorityEntryKind, "Types that only authority composition may contribute.", {
    Invariant => "A domain rule asserted by the authority.",
    Finding => "An owner, auditor, incident, postmortem or certification finding.",
    PolicyAssociation => "A reference to an immutable authority policy requirement."
});

/// Scope is explicit; absence of a project never implicitly means global access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "project",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum KnowledgeScope {
    /// Explicitly shared authority knowledge.
    Global,
    /// Knowledge private to one authority project.
    Project(ProjectId),
}
impl KnowledgeScope {
    /// Checks scope before packaging any private content.
    pub fn permits(&self, project: ProjectId) -> bool {
        matches!(self, Self::Global) || *self == Self::Project(project)
    }
}
/// An omission that must survive into immutable evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindSpot {
    /// Stable machine code, not interpreted free text.
    pub code: String,
    /// Exact source path where applicable.
    pub path: Option<SourcePath>,
    /// Human explanation of the unproven area.
    pub reason: String,
}
/// Coverage of one dimension; reasons are part of artifact identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeCoverage {
    /// Dimension being reported.
    pub dimension: CoverageDimension,
    /// Degree of supported observation, not correctness.
    pub state: CoverageState,
    /// Explicit scope and limitations.
    pub reason: String,
}
/// A graph node. Its producer and provenance govern interpretation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeNode {
    /// Stable local identity, independent of descriptive text.
    pub id: String,
    /// Closed generic vocabulary.
    pub kind: NodeKind,
    /// Source location, when observed.
    pub path: Option<SourcePath>,
    /// Untrusted syntax or authority description according to provenance.
    pub label: String,
    /// Exact source/content or normalized syntax digest, according to producer.
    pub content_sha256: Sha256Digest,
    /// How this fact was established.
    pub provenance: Provenance,
}
/// A typed relationship with explicit unresolved semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeEdge {
    /// Existing local node ID.
    pub from: String,
    /// Existing local node ID.
    pub to: String,
    /// Actual observed/derived relationship.
    pub kind: RelationKind,
    /// Whether this relationship remains unresolved.
    pub unresolved: bool,
    /// Derivation category, never a probability.
    pub provenance: Provenance,
}
/// Explicit supersession reference; cannot mutate the previous immutable entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Supersession {
    /// Previous stable ID.
    pub id: String,
    /// Previous authority version.
    pub version: String,
    /// Previous canonical entry identity.
    pub sha256: Sha256Digest,
}
/// Trusted authoring input. Frozen bundles validate it; no target decoder exists.
#[derive(Debug, Clone, Serialize)]
pub struct AuthorityKnowledgeEntry {
    /// Stable authority identifier, for example PAYMENT-001.
    pub id: String,
    /// Explicit immutable version.
    pub version: String,
    /// Invariant, known finding or policy association.
    pub kind: AuthorityEntryKind,
    /// Explicit visibility.
    pub scope: KnowledgeScope,
    /// Authority-selected priority.
    pub severity: KnowledgeSeverity,
    /// Approving authority identity.
    pub authority: String,
    /// Assertion text, not a deterministic property proof.
    pub description: String,
    /// Audit origin, such as auditor or incident identifier.
    pub origin: String,
    /// Approval is controlled outside the repository.
    pub approval: ApprovalState,
    /// Explicit prior immutable identity, if superseded.
    pub supersedes: Option<Supersession>,
    /// Exact paths selected by authority; empty means project-wide relevance.
    pub paths: Vec<SourcePath>,
    /// Immutable policy associations; knowledge cannot edit these policies.
    pub policy_sha256: Vec<Sha256Digest>,
}
