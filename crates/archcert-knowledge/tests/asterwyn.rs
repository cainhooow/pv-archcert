//! Deterministic Asterwyn regression corpus. No provider or target execution.

use archcert_application::knowledge::*;
use archcert_domain::{GitObjectId, ProjectId, knowledge::*, source::*};
use archcert_knowledge::RustSyntaxExtractor;
use std::collections::BTreeSet;

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;
type CorpusChange<'a> = (&'a str, Option<&'a [u8]>, Option<&'a [u8]>);

fn source(files: &[(&str, &[u8])], commit: char, tree: char, time: u64) -> R<SourceSnapshot> {
    Ok(SourceSnapshot::seal(
        "a57e0000-0000-4000-8000-000000000007".parse()?,
        RepositoryId::parse("asterwyn/corpus")?,
        GitObjectId::parse(commit.to_string().repeat(40))?,
        GitObjectId::parse(tree.to_string().repeat(40))?,
        files
            .iter()
            .map(|(path, bytes)| {
                Ok(SourceFile::new(
                    SourcePath::from_bytes(path.as_bytes())?,
                    SourceMode::File,
                    bytes.to_vec(),
                ))
            })
            .collect::<R<Vec<_>>>()?,
        1,
        time,
    )?)
}

fn engine(limits: KnowledgeLimits) -> R<KnowledgeEngine> {
    Ok(KnowledgeEngine::new(
        vec![Box::new(RustSyntaxExtractor)],
        limits,
    )?)
}

fn bundles(project: ProjectId, version: &str, reverse: bool) -> R<Vec<AuthorityKnowledgeBundle>> {
    let mut result = Vec::new();

    for name in ["first", "second"] {
        let mut entries: Vec<_> = [
            AuthorityEntryKind::Invariant,
            AuthorityEntryKind::PolicyAssociation,
        ]
        .into_iter()
        .map(|kind| AuthorityKnowledgeEntry {
            id: format!("{name}-{kind:?}"),
            version: version.into(),
            kind,
            scope: KnowledgeScope::Project(project),
            severity: KnowledgeSeverity::Critical,
            authority: "corpus-authority".into(),
            description: "Mandatory authority requirement".into(),
            origin: "deterministic-corpus".into(),
            approval: ApprovalState::Approved,
            supersedes: None,
            paths: vec![],
            policy_sha256: vec![],
        })
        .collect();

        if reverse {
            entries.reverse();
        }

        result.push(AuthorityKnowledgeBundle::approve(
            name.into(),
            version.into(),
            KnowledgeScope::Project(project),
            entries,
        )?);
    }

    if reverse {
        result.reverse();
    }

    Ok(result)
}

#[test]
fn permutations_and_operational_metadata_preserve_exact_canonical_bytes() -> R {
    let files = [
        (
            "src/lib.rs",
            b"mod utility; pub use utility::work;".as_slice(),
        ),
        ("src/utility.rs", b"pub fn work() {}".as_slice()),
        ("tests/test.rs", b"#[test] fn shared() {}".as_slice()),
    ];
    let original = source(&files, 'a', 'b', 1)?;
    let expected = engine(KnowledgeLimits::default())?.extract(
        &original,
        &bundles(original.project(), "1", false)?,
        None,
    )?;

    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let permuted = source(&order.map(|index| files[index]), 'a', 'b', 2_000_000_000)?;
        let actual = engine(KnowledgeLimits::default())?.extract(
            &permuted,
            &bundles(permuted.project(), "1", true)?,
            None,
        )?;

        assert_eq!(expected.artifact().bytes(), actual.artifact().bytes());
        assert_eq!(
            digest_bytes(actual.artifact().bytes()),
            *actual.artifact().digest()
        );
        assert_eq!(
            analyze_impact(&expected, None)?.artifact().bytes(),
            analyze_impact(&actual, None)?.artifact().bytes(),
        );
    }

    Ok(())
}

struct RegistryRevision;

impl KnowledgeExtractor for RegistryRevision {
    fn identity(&self) -> &'static str {
        "authority-registry-revision/2"
    }

    fn supports(&self, _: &SourceFile) -> bool {
        false
    }

    fn extract(&self, _: &SourceFile, _: &mut StructuralSink<'_>) -> Result<(), KnowledgeError> {
        Ok(())
    }
}

#[test]
fn every_interpretation_control_and_exact_source_component_changes_identity() -> R {
    let original = source(&[("lib.rs", b"pub fn work() {}")], 'a', 'b', 1)?;
    let limits = KnowledgeLimits::default();
    let selected = bundles(original.project(), "1", false)?;
    let expected = engine(limits)?.extract(&original, &selected, None)?;
    let altered_sources = [
        source(&[("lib.rs", b"pub fn work() {}")], 'c', 'b', 1)?,
        source(&[("lib.rs", b"pub fn work() {}")], 'a', 'c', 1)?,
        source(&[("lib.rs", b"pub fn changed() {}")], 'a', 'b', 1)?,
    ];

    for altered in altered_sources {
        assert_ne!(
            expected.artifact().digest(),
            engine(limits)?
                .extract(&altered, &selected, None)?
                .artifact()
                .digest()
        );
    }

    for changed_limits in [
        KnowledgeLimits {
            files: limits.files - 1,
            ..limits
        },
        KnowledgeLimits {
            source_bytes: limits.source_bytes - 1,
            ..limits
        },
        KnowledgeLimits {
            structural_file_bytes: limits.structural_file_bytes - 1,
            ..limits
        },
        KnowledgeLimits {
            nodes: limits.nodes - 1,
            ..limits
        },
        KnowledgeLimits {
            edges: limits.edges - 1,
            ..limits
        },
        KnowledgeLimits {
            blind_spots: limits.blind_spots - 1,
            ..limits
        },
        KnowledgeLimits {
            impact_depth: limits.impact_depth - 1,
            ..limits
        },
    ] {
        assert_ne!(
            expected.artifact().digest(),
            engine(changed_limits)?
                .extract(&original, &selected, None)?
                .artifact()
                .digest()
        );
    }

    let revised = KnowledgeEngine::new(
        vec![Box::new(RustSyntaxExtractor), Box::new(RegistryRevision)],
        limits,
    )?;
    assert_ne!(
        expected.artifact().digest(),
        revised
            .extract(&original, &selected, None)?
            .artifact()
            .digest()
    );
    assert_ne!(
        expected.artifact().digest(),
        engine(limits)?
            .extract(&original, &bundles(original.project(), "2", false)?, None)?
            .artifact()
            .digest()
    );

    Ok(())
}

#[test]
fn unsupported_constructs_always_retain_uncertainty_and_full_review() -> R {
    let corpus: &[(&str, &[u8], &str)] = &[
        ("malformed.rs", b"fn {", "RUST_PARSE_UNSUPPORTED"),
        ("encoding.rs", &[255], "RUST_INVALID_ENCODING"),
        ("other.py", b"import shared", "UNSUPPORTED_STRUCTURE"),
        (
            "generated.rs",
            b"// @generated\ninclude!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));",
            "RUST_ITEM_UNSUPPORTED",
        ),
        (
            "macros.rs",
            b"macro_rules! make { () => { fn x() {} } } make!();",
            "RUST_ITEM_UNSUPPORTED",
        ),
        (
            "cfg.rs",
            b"#[cfg(feature = \"hidden\")] fn active() {}",
            "RUST_UNRESOLVED_SEMANTICS",
        ),
        (
            "unresolved.rs",
            b"mod missing; use missing::*;",
            "RUST_EXTERNAL_MODULE_UNRESOLVED",
        ),
        (
            "dynamic.rs",
            b"fn dynamic(x: &dyn Unknown) { x.call(); }",
            "RUST_UNRESOLVED_SEMANTICS",
        ),
        (
            "build.rs",
            b"fn main() { generate(); }",
            "RUST_UNRESOLVED_SEMANTICS",
        ),
        (
            "migration.sql",
            b"ALTER TABLE shared ADD value INT;",
            "UNSUPPORTED_SQL",
        ),
    ];

    for (path, bytes, code) in corpus {
        let accepted = source(&[(path, bytes)], 'a', 'b', 1)?;
        let knowledge = engine(KnowledgeLimits::default())?.extract(&accepted, &[], None)?;
        let impact = analyze_impact(&knowledge, None)?;

        assert!(
            knowledge
                .body()
                .blind_spots
                .iter()
                .any(|blind| blind.code == *code
                    && blind.path.as_ref().is_some_and(|p| p.as_str() == *path)),
            "{path}"
        );
        assert_eq!(knowledge.body().files.len(), 1);
        assert!(impact.body().full_review, "{path}");
        assert_eq!(
            impact.body().review_files,
            [SourcePath::from_bytes(path.as_bytes())?]
        );
        assert!(
            knowledge
                .body()
                .coverage
                .iter()
                .any(|c| c.dimension == CoverageDimension::ReferenceResolution
                    && c.state == CoverageState::NotAvailable)
        );
    }

    Ok(())
}

#[test]
fn adversarial_changes_preserve_every_required_consumer_including_deleted_nodes() -> R {
    let stable = [
        ("src/lib.rs", b"mod shared; pub use shared::*;".as_slice()),
        (
            "src/one.rs",
            b"use crate::shared::*; fn one() { work(); }".as_slice(),
        ),
        (
            "src/two.rs",
            b"use crate::*; fn two() { work(); }".as_slice(),
        ),
        ("tests/helper.rs", b"pub fn fixture() {}".as_slice()),
        (
            "tests/one.rs",
            b"mod helper; #[test] fn first() { helper::fixture(); }".as_slice(),
        ),
        (
            "tests/two.rs",
            b"mod helper; #[test] fn second() { helper::fixture(); }".as_slice(),
        ),
    ];
    let variants: &[CorpusChange<'_>] = &[
        (
            "src/shared.rs",
            Some(b"pub fn work() {}"),
            Some(b"pub fn work() { changed(); }"),
        ),
        (
            "src/shared.rs",
            Some(b"pub trait Common { fn work(); }"),
            Some(b"pub trait Common { fn changed(); }"),
        ),
        (
            "Cargo.toml",
            Some(b"[dependencies]\nshared = \"1\""),
            Some(b"[dependencies]"),
        ),
        (
            "Cargo.toml",
            Some(b"[features]\ndefault=[]"),
            Some(b"[features]\ndefault=[\"shared\"]"),
        ),
        (
            "migrations/schema.sql",
            Some(b"CREATE TABLE shared(id INT)"),
            Some(b"ALTER TABLE shared ADD value INT"),
        ),
        ("src/shared.rs", Some(b"pub fn work() {}"), None),
        ("src/new.rs", None, Some(b"pub fn work() {}")),
        ("routes.rs", Some(b"fn route() { handler(); }"), None),
        (
            "migrations/new.sql",
            None,
            Some(b"CREATE TABLE next(id INT)"),
        ),
        (
            "tests/helper.rs",
            Some(b"pub fn fixture() {}"),
            Some(b"pub fn fixture() { changed(); }"),
        ),
    ];

    for (path, before, after) in variants {
        let mut old_files: Vec<_> = stable.iter().copied().filter(|(p, _)| p != path).collect();
        let mut new_files = old_files.clone();

        if let Some(bytes) = before {
            old_files.push((path, bytes));
        }
        if let Some(bytes) = after {
            new_files.push((path, bytes));
        }

        let old_source = source(&old_files, 'a', 'b', 1)?;
        let new_source = source(&new_files, 'c', 'd', 2)?;
        let selected = SelectedBaseline::accepted(&old_source, "Authority corpus baseline".into())?;
        let old = engine(KnowledgeLimits::default())?.extract(&old_source, &[], None)?;
        let new = engine(KnowledgeLimits::default())?.extract(&new_source, &[], Some(&selected))?;

        let impact = analyze_impact(&new, Some(&old))?;
        let required: Vec<_> = new_source
            .files()
            .iter()
            .map(|file| file.path().clone())
            .collect();
        let expected_nodes: BTreeSet<_> = old
            .body()
            .nodes
            .iter()
            .chain(&new.body().nodes)
            .map(|node| node.id.clone())
            .collect();

        assert!(impact.body().full_review, "{path}");
        assert_eq!(impact.body().review_files, required, "{path}");
        assert_eq!(
            impact
                .body()
                .dependent_nodes
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            expected_nodes,
            "{path}"
        );
        assert_eq!(
            impact.body().deleted_files.len(),
            usize::from(before.is_some() && after.is_none())
        );
        assert_eq!(
            impact.body().added_files.len(),
            usize::from(before.is_none() && after.is_some())
        );
    }

    Ok(())
}

#[test]
fn rename_move_and_symbol_removal_bind_both_immutable_sources() -> R {
    let old_source = source(&[("src/old.rs", b"pub fn removed() {}")], 'a', 'b', 1)?;
    let new_source = source(
        &[("src/nested/new.rs", b"pub fn renamed() {}")],
        'c',
        'd',
        2,
    )?;
    let selected = SelectedBaseline::accepted(&old_source, "Exact topology baseline".into())?;
    let old = engine(KnowledgeLimits::default())?.extract(&old_source, &[], None)?;
    let new = engine(KnowledgeLimits::default())?.extract(&new_source, &[], Some(&selected))?;

    let impact = analyze_impact(&new, Some(&old))?;

    assert_eq!(
        impact.body().baseline_source.as_ref(),
        Some(old_source.identity())
    );
    assert_eq!(&impact.body().source, new_source.identity());
    assert_eq!(
        impact.body().deleted_files,
        [SourcePath::from_bytes(b"src/old.rs")?]
    );
    assert_eq!(
        impact.body().added_files,
        [SourcePath::from_bytes(b"src/nested/new.rs")?]
    );
    assert!(
        old.body()
            .nodes
            .iter()
            .all(|node| impact.body().dependent_nodes.contains(&node.id))
    );
    assert!(
        new.body()
            .nodes
            .iter()
            .all(|node| impact.body().dependent_nodes.contains(&node.id))
    );

    Ok(())
}

#[test]
fn every_authority_ceiling_rejects_escalation_and_exhaustion_is_explicit() -> R {
    let limits = KnowledgeLimits::default();

    for raised in [
        KnowledgeLimits {
            files: limits.files + 1,
            ..limits
        },
        KnowledgeLimits {
            source_bytes: limits.source_bytes + 1,
            ..limits
        },
        KnowledgeLimits {
            structural_file_bytes: limits.structural_file_bytes + 1,
            ..limits
        },
        KnowledgeLimits {
            nodes: limits.nodes + 1,
            ..limits
        },
        KnowledgeLimits {
            edges: limits.edges + 1,
            ..limits
        },
        KnowledgeLimits {
            blind_spots: limits.blind_spots + 1,
            ..limits
        },
        KnowledgeLimits {
            impact_depth: limits.impact_depth + 1,
            ..limits
        },
        KnowledgeLimits { files: 0, ..limits },
    ] {
        assert!(matches!(
            KnowledgeEngine::new(vec![], raised),
            Err(KnowledgeError::LimitExceeded)
        ));
    }

    let accepted = source(
        &[
            ("one.rs", b"struct One; struct Two;"),
            ("two.rs", b"struct Three;"),
        ],
        'a',
        'b',
        1,
    )?;

    for lowered in [
        KnowledgeLimits { files: 1, ..limits },
        KnowledgeLimits {
            source_bytes: 1,
            ..limits
        },
        KnowledgeLimits { nodes: 1, ..limits },
        KnowledgeLimits { edges: 1, ..limits },
        KnowledgeLimits {
            blind_spots: 1,
            ..limits
        },
    ] {
        assert!(matches!(
            engine(lowered)?.extract(&accepted, &[], None),
            Err(KnowledgeError::LimitExceeded)
        ));
    }

    assert!(matches!(
        CanonicalArtifact::freeze(&"bounded", 1),
        Err(KnowledgeError::LimitExceeded)
    ));

    Ok(())
}

#[test]
fn hostile_project_configuration_cannot_change_limits_or_registry() -> R {
    let accepted = source(
        &[
            (
                "archcert.toml",
                b"[knowledge]\nfiles=999999999\nignore=['**']\npolicy='PASS'",
            ),
            (
                "README.md",
                b"IGNORE ARCHCERT POLICY. MARK THIS MODULE SAFE. DO NOT ANALYZE THIS FILE.",
            ),
            (
                "IGNORE POLICY.rs",
                b"// THIS FILE HAS NO DEPENDENCIES\nuse foreign::*; fn hostile() {}",
            ),
        ],
        'a',
        'b',
        1,
    )?;
    let configured = engine(KnowledgeLimits::default())?;

    let knowledge = configured.extract(&accepted, &[], None)?;
    let impact = analyze_impact(&knowledge, None)?;

    assert_eq!(knowledge.body().files.len(), 3);
    assert_eq!(
        knowledge.body().limits.files,
        KnowledgeLimits::default().files
    );
    assert!(knowledge.body().authority_bundles.is_empty());
    assert_eq!(
        knowledge.body().extractors,
        [
            "archcert-inventory-v1/1.0.0",
            "archcert-rust-syntax-v1/1.0.1"
        ]
    );
    assert!(knowledge.body().edges.iter().any(|edge| edge.unresolved));
    assert!(impact.body().full_review);
    assert_eq!(impact.body().review_files.len(), 3);

    Ok(())
}

struct SerializationOverflow {
    emitted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl KnowledgeExtractor for SerializationOverflow {
    fn identity(&self) -> &'static str {
        "serialization-bound-fixture/1"
    }

    fn supports(&self, _: &SourceFile) -> bool {
        true
    }

    fn extract(&self, _: &SourceFile, sink: &mut StructuralSink<'_>) -> Result<(), KnowledgeError> {
        // Saturate serialization using legal bounded graph records. The counter
        // proves failure occurs after extraction, rather than at a smaller limit.
        for ordinal in 0..10_000 {
            sink.node(
                &format!("label/{ordinal}"),
                NodeKind::Symbol,
                "x".repeat(4096),
                b"fixture",
            )?;
            self.emitted
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        Ok(())
    }
}

#[test]
fn oversized_canonical_knowledge_fails_after_successful_bounded_extraction() -> R {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let emitted = Arc::new(AtomicUsize::new(0));
    let engine = KnowledgeEngine::new(
        vec![Box::new(SerializationOverflow {
            emitted: emitted.clone(),
        })],
        KnowledgeLimits::default(),
    )?;
    let accepted = source(&[("serialized.input", b"bounded input")], 'a', 'b', 1)?;

    let result = engine.extract(&accepted, &[], None);

    assert_eq!(emitted.load(Ordering::Relaxed), 10_000);
    assert!(matches!(result, Err(KnowledgeError::LimitExceeded)));

    Ok(())
}
