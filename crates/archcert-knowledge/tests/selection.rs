//! Exact restoration and deterministic scenario contracts, independent of M8.

use archcert_application::knowledge::*;
use archcert_domain::{GitObjectId, ProjectId, knowledge::*, source::*};
use archcert_knowledge::RustSyntaxExtractor;

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn source(project: ProjectId, repository: &str, commit: char, text: &[u8]) -> R<SourceSnapshot> {
    Ok(SourceSnapshot::seal(
        project,
        RepositoryId::parse(repository)?,
        GitObjectId::parse(commit.to_string().repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![SourceFile::new(
            SourcePath::from_bytes(b"shared.rs")?,
            SourceMode::File,
            text.to_vec(),
        )],
        1,
        1,
    )?)
}

fn engine() -> R<KnowledgeEngine> {
    Ok(KnowledgeEngine::new(
        vec![Box::new(RustSyntaxExtractor)],
        KnowledgeLimits::default(),
    )?)
}

fn bundle(project: ProjectId, version: &str) -> R<AuthorityKnowledgeBundle> {
    Ok(AuthorityKnowledgeBundle::approve(
        "invariants".into(),
        version.into(),
        KnowledgeScope::Project(project),
        vec![AuthorityKnowledgeEntry {
            id: "GLOBAL-SECURITY".into(),
            version: version.into(),
            kind: AuthorityEntryKind::Invariant,
            scope: KnowledgeScope::Project(project),
            severity: KnowledgeSeverity::Critical,
            authority: "test-authority".into(),
            description: "Baseline architecture and supply-chain requirements".into(),
            origin: "authority-fixture".into(),
            approval: ApprovalState::Approved,
            supersedes: None,
            paths: vec![],
            policy_sha256: vec![],
        }],
    )?)
}

#[test]
fn restore_rejects_scope_source_registry_limits_and_authority_replay() -> R {
    let project = ProjectId::new();
    let accepted = source(project, "project/repository", 'a', b"pub fn work() {}")?;
    let bundles = [bundle(project, "1")?];
    let engine = engine()?;
    let knowledge = engine.extract(&accepted, &bundles, None)?;
    let bytes = knowledge.artifact().bytes();
    let digest = knowledge.artifact().digest();

    assert_eq!(
        engine
            .restore_exact(&accepted, &bundles, None, bytes, digest)?
            .artifact()
            .bytes(),
        bytes
    );

    for foreign in [
        source(
            ProjectId::new(),
            "project/repository",
            'a',
            b"pub fn work() {}",
        )?,
        source(project, "other/repository", 'a', b"pub fn work() {}")?,
        source(project, "project/repository", 'c', b"pub fn work() {}")?,
        source(project, "project/repository", 'a', b"pub fn other() {}")?,
    ] {
        assert!(
            engine
                .restore_exact(&foreign, &bundles, None, bytes, digest)
                .is_err()
        );
    }

    assert!(
        engine
            .restore_exact(&accepted, &[bundle(project, "2")?], None, bytes, digest)
            .is_err()
    );
    let changed_registry = KnowledgeEngine::new(vec![], KnowledgeLimits::default())?;
    assert!(
        changed_registry
            .restore_exact(&accepted, &bundles, None, bytes, digest)
            .is_err()
    );
    let changed_limits = KnowledgeEngine::new(
        vec![Box::new(RustSyntaxExtractor)],
        KnowledgeLimits {
            impact_depth: 1,
            ..KnowledgeLimits::default()
        },
    )?;
    assert!(
        changed_limits
            .restore_exact(&accepted, &bundles, None, bytes, digest)
            .is_err()
    );
    let baseline =
        SelectedBaseline::accepted(&accepted, "Different baseline interpretation".into())?;
    assert!(
        engine
            .restore_exact(&accepted, &bundles, Some(&baseline), bytes, digest)
            .is_err()
    );

    Ok(())
}

#[test]
fn corrupted_bytes_reject_even_with_a_recomputed_untrusted_digest() -> R {
    let project = ProjectId::new();
    let source = source(project, "project/repository", 'a', b"pub fn work() {}")?;
    let engine = engine()?;
    let knowledge = engine.extract(&source, &[], None)?;
    let original = knowledge.artifact().bytes();
    let mut mutation = original.to_vec();
    mutation[0] ^= 1;
    let mut trailing = original.to_vec();
    trailing.extend_from_slice(b"\n{}");
    let mut metadata: serde_json::Value = serde_json::from_slice(original)?;
    metadata["schema"] = 99.into();
    let mut extractor = metadata.clone();
    extractor["schema"] = 1.into();
    extractor["extractors"] = serde_json::json!(["substituted-profile/99"]);

    for corrupt in [
        mutation,
        original[..original.len() - 1].to_vec(),
        trailing,
        canonical_bytes(&metadata)?,
        canonical_bytes(&extractor)?,
        Vec::new(),
    ] {
        assert!(
            engine
                .restore_exact(&source, &[], None, &corrupt, knowledge.artifact().digest())
                .is_err()
        );
        assert!(
            engine
                .restore_exact(&source, &[], None, &corrupt, &digest_bytes(&corrupt))
                .is_err()
        );
    }

    assert!(
        engine
            .restore_exact(&source, &[], None, original, &digest_bytes(b"wrong digest"))
            .is_err()
    );

    Ok(())
}

// Trusted test adapter deliberately emits only an inventory-complete finite
// dimension. This tests selection mechanics without claiming Rust resolution.
struct InventoryOnly;

impl KnowledgeExtractor for InventoryOnly {
    fn identity(&self) -> &'static str {
        "finite-test-inventory/1"
    }

    fn supports(&self, _: &SourceFile) -> bool {
        true
    }

    fn extract(&self, _: &SourceFile, _: &mut StructuralSink<'_>) -> Result<(), KnowledgeError> {
        Ok(())
    }
}

fn catalog(project: ProjectId, reverse: bool) -> R<ScenarioCatalog> {
    let mut scenarios = vec![
        ValidationScenario {
            id: "architecture".into(),
            requirement: ScenarioRequirement::Mandatory,
            triggers: vec![],
        },
        ValidationScenario {
            id: "supply-chain".into(),
            requirement: ScenarioRequirement::Mandatory,
            triggers: vec![],
        },
        ValidationScenario {
            id: "invariant".into(),
            requirement: ScenarioRequirement::ImpactSelected,
            triggers: vec![ScenarioTrigger::AuthorityEntry {
                id: "GLOBAL-SECURITY".into(),
            }],
        },
        ValidationScenario {
            id: "shared".into(),
            requirement: ScenarioRequirement::ImpactSelected,
            triggers: vec![ScenarioTrigger::Path {
                path: SourcePath::from_bytes(b"shared.rs")?,
            }],
        },
        ValidationScenario {
            id: "unrelated".into(),
            requirement: ScenarioRequirement::ImpactSelected,
            triggers: vec![ScenarioTrigger::Path {
                path: SourcePath::from_bytes(b"unrelated.rs")?,
            }],
        },
    ];

    if reverse {
        scenarios.reverse();
    }

    Ok(ScenarioCatalog::approve(
        "authority-scenarios".into(),
        "1".into(),
        KnowledgeScope::Project(project),
        scenarios,
    )?)
}

#[test]
fn selection_records_change_relation_invariant_scenario_and_retains_mandatory_checks() -> R {
    let project = ProjectId::new();
    let before = source(project, "project/repository", 'a', b"old")?;
    let after = source(project, "project/repository", 'c', b"new")?;
    let selected = SelectedBaseline::accepted(&before, "Authority-selected exact baseline".into())?;
    let engine = KnowledgeEngine::new(vec![Box::new(InventoryOnly)], KnowledgeLimits::default())?;
    let bundles = [bundle(project, "1")?];
    let baseline = engine.extract(&before, &bundles, Some(&selected))?;
    let target = engine.extract(&after, &bundles, Some(&selected))?;
    let catalog = catalog(project, false)?;

    let selection = select_validation_scenarios(&catalog, &target, Some(&baseline))?;

    assert!(!selection.impact().body().full_review);
    assert_eq!(
        selection
            .selected()
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>(),
        ["architecture", "invariant", "shared", "supply-chain"]
    );
    let invariant = selection
        .selected()
        .iter()
        .find(|s| s.id == "invariant")
        .ok_or("invariant missing")?;
    let ScenarioReason::RelationClosure {
        changed_node,
        affected_node,
        relations,
    } = &invariant.reason
    else {
        return Err("relation trace missing".into());
    };

    assert_eq!(changed_node, "file:shared.rs");
    assert_eq!(relations.len(), 1);
    assert_eq!(&relations[0].from, changed_node);
    assert_eq!(&relations[0].to, affected_node);
    assert_eq!(relations[0].kind, RelationKind::RelatedToInvariant);
    assert_eq!(relations[0].provenance, Provenance::AuthorityAsserted);
    assert!(
        selection
            .selected()
            .iter()
            .filter(|s| s.id == "architecture" || s.id == "supply-chain")
            .all(|s| matches!(s.reason, ScenarioReason::Mandatory))
    );

    let unchanged = select_validation_scenarios(&catalog, &baseline, Some(&baseline))?;
    assert_eq!(
        unchanged
            .selected()
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>(),
        ["architecture", "supply-chain"]
    );

    Ok(())
}

#[test]
fn uncertainty_selects_all_scenarios_and_ordering_cannot_change_the_result() -> R {
    let project = ProjectId::new();
    let source = source(project, "project/repository", 'a', b"mod unresolved;")?;
    let target = engine()?.extract(&source, &[bundle(project, "1")?], None)?;
    let forward = catalog(project, false)?;
    let reverse = catalog(project, true)?;

    let selection = select_validation_scenarios(&forward, &target, None)?;
    let reordered = select_validation_scenarios(&reverse, &target, None)?;

    assert_eq!(selection.selected().len(), 5);
    assert!(selection.impact().body().full_review);
    assert_eq!(selection.artifact().bytes(), reordered.artifact().bytes());
    assert_eq!(forward.artifact().bytes(), reverse.artifact().bytes());
    assert!(
        select_validation_scenarios(&catalog(ProjectId::new(), false)?, &target, None).is_err()
    );

    Ok(())
}

#[test]
fn authority_mapping_changes_and_removed_files_cannot_be_hidden() -> R {
    let project = ProjectId::new();
    let before = source(project, "project/repository", 'a', b"old")?;
    let after = SourceSnapshot::seal(
        project,
        before.repository().clone(),
        GitObjectId::parse("c".repeat(40))?,
        before.identity().tree.clone(),
        vec![],
        1,
        2,
    )?;
    let selected = SelectedBaseline::accepted(&before, "Deletion baseline".into())?;
    let engine = KnowledgeEngine::new(vec![Box::new(InventoryOnly)], KnowledgeLimits::default())?;
    let bundles = [bundle(project, "1")?];
    let baseline = engine.extract(&before, &bundles, Some(&selected))?;
    let target = engine.extract(&after, &bundles, Some(&selected))?;

    let selection =
        select_validation_scenarios(&catalog(project, false)?, &target, Some(&baseline))?;

    assert!(!selection.impact().body().full_review);
    assert!(selection.selected().iter().any(|s| s.id == "invariant"));
    assert!(selection.selected().iter().any(|s| s.id == "shared"));
    assert_eq!(
        selection.impact().body().deleted_files,
        [SourcePath::from_bytes(b"shared.rs")?]
    );

    let changed_authority = engine.extract(&after, &[bundle(project, "2")?], Some(&selected))?;
    let expanded = select_validation_scenarios(
        &catalog(project, false)?,
        &changed_authority,
        Some(&baseline),
    )?;
    assert!(expanded.impact().body().full_review);
    assert_eq!(expanded.selected().len(), 5);
    assert_ne!(expanded.artifact().digest(), selection.artifact().digest());

    Ok(())
}

#[test]
fn invalid_catalogs_cannot_create_unbounded_or_ambiguous_mappings() -> R {
    let scope = KnowledgeScope::Global;
    let optional = ValidationScenario {
        id: "optional".into(),
        requirement: ScenarioRequirement::ImpactSelected,
        triggers: vec![],
    };
    assert!(
        ScenarioCatalog::approve("catalog".into(), "1".into(), scope.clone(), vec![optional])
            .is_err()
    );
    let mandatory = ValidationScenario {
        id: "mandatory".into(),
        requirement: ScenarioRequirement::Mandatory,
        triggers: vec![],
    };
    assert!(
        ScenarioCatalog::approve(
            "catalog".into(),
            "1".into(),
            scope.clone(),
            vec![mandatory.clone(), mandatory.clone()]
        )
        .is_err()
    );
    assert!(
        ScenarioCatalog::approve("catalog".into(), "1".into(), scope, vec![mandatory; 129])
            .is_err()
    );

    Ok(())
}
