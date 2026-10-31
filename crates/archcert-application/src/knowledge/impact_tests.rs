//! Graph mechanics independent of the deliberately unresolved Rust adapter.

use super::*;
use archcert_domain::{GitObjectId, source::SourceFile};

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn source() -> R<SourceSnapshot> {
    Ok(SourceSnapshot::seal(
        "a57e0000-0000-4000-8000-000000000007".parse()?,
        RepositoryId::parse("asterwyn/graph")?,
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![SourceFile::new(
            SourcePath::from_bytes(b"graph")?,
            SourceMode::File,
            b"graph fixture".to_vec(),
        )],
        1,
        1,
    )?)
}

// These internal fixtures isolate relation traversal from extraction. They do
// not claim compiler resolution, accepted source provenance or database behavior.
fn graph(
    selected: &SelectedBaseline,
    count: usize,
    relations: &[(usize, usize, RelationKind, bool)],
    changed: bool,
    depth: usize,
) -> R<KnowledgeArtifact> {
    let snapshot = source()?;
    let mut knowledge = KnowledgeEngine::new(vec![], KnowledgeLimits::default())?.extract(
        &snapshot,
        &[],
        Some(selected),
    )?;
    let body = &mut knowledge.body;
    body.files.clear();
    body.nodes = (0..count)
        .map(|index| KnowledgeNode {
            id: format!("node:{index:04}"),
            kind: NodeKind::Symbol,
            path: None,
            label: format!("node {index}"),
            content_sha256: digest_bytes(if changed && index == 0 {
                b"new"
            } else {
                b"old"
            }),
            provenance: Provenance::DirectlyObserved,
        })
        .collect();
    body.edges = relations
        .iter()
        .map(|(from, to, kind, unresolved)| KnowledgeEdge {
            from: format!("node:{from:04}"),
            to: format!("node:{to:04}"),
            kind: *kind,
            unresolved: *unresolved,
            provenance: Provenance::DirectlyObserved,
        })
        .collect();
    body.edges = body
        .edges
        .drain(..)
        .map(|edge| Ok((canonical_bytes(&edge)?, edge)))
        .collect::<Result<BTreeMap<_, _>, KnowledgeError>>()?
        .into_values()
        .collect();
    body.blind_spots.clear();
    body.limits.impact_depth = depth;
    knowledge.artifact = CanonicalArtifact::freeze(body, 32 * 1024 * 1024)?;

    Ok(knowledge)
}

#[test]
fn cycles_close_without_duplicates_and_disconnected_nodes_stay_outside() -> R {
    let selected = SelectedBaseline::accepted(&source()?, "Graph mechanics fixture".into())?;
    let relations = [
        (0, 1, RelationKind::References, false),
        (1, 2, RelationKind::References, false),
        (2, 0, RelationKind::References, false),
    ];
    let before = graph(&selected, 4, &relations, false, 16)?;
    let after = graph(&selected, 4, &relations, true, 16)?;

    let impact = analyze_impact(&after, Some(&before))?;

    assert!(!impact.body.full_review);
    assert_eq!(
        impact.body.dependent_nodes,
        ["node:0000", "node:0001", "node:0002"]
    );
    assert_eq!(impact.body.changed_nodes, ["node:0000"]);

    Ok(())
}

#[test]
fn every_supported_relation_expands_in_both_directions_transitively() -> R {
    let selected = SelectedBaseline::accepted(&source()?, "Relation mechanics fixture".into())?;

    for kind in [
        RelationKind::Defines,
        RelationKind::Imports,
        RelationKind::References,
        RelationKind::Tests,
        RelationKind::Affects,
        RelationKind::Implements,
        RelationKind::GovernedBy,
        RelationKind::RelatedToFinding,
        RelationKind::RelatedToInvariant,
    ] {
        for reversed in [false, true] {
            let relations: Vec<_> = (0..6)
                .map(|index| {
                    if reversed {
                        (index + 1, index, kind, false)
                    } else {
                        (index, index + 1, kind, false)
                    }
                })
                .collect();
            let before = graph(&selected, 8, &relations, false, 16)?;
            let after = graph(&selected, 8, &relations, true, 16)?;

            let impact = analyze_impact(&after, Some(&before))?;

            assert!(!impact.body.full_review);
            assert_eq!(impact.body.dependent_nodes.len(), 7, "{kind:?}");
            assert!(!impact.body.dependent_nodes.contains(&"node:0007".into()));
        }
    }

    Ok(())
}

#[test]
fn deep_exhaustion_is_explicit_and_wide_closure_is_bounded() -> R {
    let selected = SelectedBaseline::accepted(&source()?, "Bounded graph fixture".into())?;
    let deep: Vec<_> = (0..40)
        .map(|index| (index, index + 1, RelationKind::References, false))
        .collect();
    let before = graph(&selected, 42, &deep, false, 4)?;
    let after = graph(&selected, 42, &deep, true, 4)?;

    let impact = analyze_impact(&after, Some(&before))?;

    assert!(impact.body.full_review);
    assert_eq!(impact.body.dependent_nodes.len(), 42);
    assert!(
        impact
            .body
            .blind_spots
            .iter()
            .any(|b| b.code == "IMPACT_DEPTH_EXHAUSTED")
    );

    let wide: Vec<_> = (1..512)
        .map(|index| (0, index, RelationKind::References, false))
        .collect();
    let before = graph(&selected, 513, &wide, false, 1)?;
    let after = graph(&selected, 513, &wide, true, 1)?;

    let impact = analyze_impact(&after, Some(&before))?;

    assert!(!impact.body.full_review);
    assert_eq!(impact.body.dependent_nodes.len(), 512);

    Ok(())
}

#[test]
fn deleted_relationships_and_nodes_still_influence_impact() -> R {
    let selected = SelectedBaseline::accepted(&source()?, "Removed graph fixture".into())?;
    let relations = [
        (0, 1, RelationKind::Implements, false),
        (1, 2, RelationKind::Tests, false),
    ];
    let before = graph(&selected, 3, &relations, false, 16)?;
    let after = graph(&selected, 2, &[], false, 16)?;

    let impact = analyze_impact(&after, Some(&before))?;

    assert_eq!(impact.body.changed_nodes, ["node:0002"]);
    assert_eq!(
        impact.body.dependent_nodes,
        ["node:0000", "node:0001", "node:0002"]
    );

    Ok(())
}

#[test]
fn adding_edges_or_uncertainty_never_reduces_impact() -> R {
    let selected = SelectedBaseline::accepted(&source()?, "Bounded property fixture".into())?;
    let before = graph(&selected, 12, &[], false, 16)?;
    let mut previous = BTreeSet::new();

    for width in 0..12 {
        let relations: Vec<_> = (1..=width)
            .map(|index| (0, index, RelationKind::References, false))
            .collect();
        let after = graph(&selected, 12, &relations, true, 16)?;
        let impact = analyze_impact(&after, Some(&before))?;
        let current: BTreeSet<_> = impact.body.dependent_nodes.iter().cloned().collect();

        assert!(previous.is_subset(&current));
        assert_eq!(current.len(), width + 1);
        previous = current;

        let mut unresolved = relations;
        unresolved.push((0, 11, RelationKind::Imports, true));
        let uncertain = graph(&selected, 12, &unresolved, true, 16)?;
        let impact = analyze_impact(&uncertain, Some(&before))?;

        assert!(impact.body.full_review);
        assert_eq!(impact.body.dependent_nodes.len(), 12);
        assert_eq!(impact.body.unresolved_impact_edges.len(), 1);
    }

    Ok(())
}
