//! Additive deterministic scenario selection. Catalogs are provisioned by authority;
//! selections describe obligations and grant no execution or policy capability.

use super::*;
use std::collections::VecDeque;

/// Whether impact may omit a scenario. Mandatory always means selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScenarioRequirement {
    /// Required independently of every impact result, including an empty delta.
    Mandatory,
    /// Optional targeted work; uncertainty selects it conservatively.
    ImpactSelected,
}

/// Exact authority mapping, never a repository-authored relevance score.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScenarioTrigger {
    /// A file/component, including a path that exists only in the baseline.
    Path {
        /// Exact admitted relative path.
        path: SourcePath,
    },
    /// An approved invariant, policy association or finding in a pinned bundle.
    AuthorityEntry {
        /// Stable authority entry ID; all matching bound bundles are relevant.
        id: String,
    },
}

/// Trusted authoring input. No target deserializer or command field exists.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationScenario {
    /// Stable scenario identity interpreted by a separate authority executor.
    pub id: String,
    /// Explicit mandatory or optional semantics.
    pub requirement: ScenarioRequirement,
    /// Canonical set of affected component/authority mappings.
    pub triggers: Vec<ScenarioTrigger>,
}

/// Immutable catalog. Versions and mapping bytes participate in its identity.
#[derive(Debug)]
pub struct ScenarioCatalog {
    scope: KnowledgeScope,
    scenarios: Vec<ValidationScenario>,
    artifact: CanonicalArtifact,
}

impl ScenarioCatalog {
    /// Authority provisioning only. Fixed ceilings: 128 scenarios, 32 triggers
    /// each and 1 MiB canonical bytes. Empty optional mappings are invalid.
    pub fn approve(
        id: String,
        version: String,
        scope: KnowledgeScope,
        mut scenarios: Vec<ValidationScenario>,
    ) -> Result<Self, KnowledgeError> {
        if !identifier(&id) || !identifier(&version) || scenarios.len() > 128 {
            return Err(KnowledgeError::Invalid);
        }

        scenarios.sort_by(|a, b| a.id.cmp(&b.id));
        let mut ids = BTreeSet::new();

        for scenario in &mut scenarios {
            if !identifier(&scenario.id)
                || !ids.insert(scenario.id.clone())
                || scenario.triggers.len() > 32
                || (scenario.requirement == ScenarioRequirement::ImpactSelected
                    && scenario.triggers.is_empty())
            {
                return Err(KnowledgeError::Invalid);
            }

            let mut triggers = BTreeMap::new();

            for trigger in &scenario.triggers {
                if matches!(trigger, ScenarioTrigger::AuthorityEntry { id } if !identifier(id)) {
                    return Err(KnowledgeError::Invalid);
                }

                triggers.insert(canonical_bytes(trigger)?, trigger.clone());
            }

            scenario.triggers = triggers.into_values().collect();
        }

        let artifact = CanonicalArtifact::freeze(
            &serde_json::json!({
                "schema": 1,
                "kind": "ARCHCERT_ASTERWYN_SCENARIO_CATALOG",
                "algorithm": "asterwyn-scenario-selection-v1/1.0.0",
                "id": id,
                "version": version,
                "scope": scope,
                "scenarios": scenarios,
            }),
            1024 * 1024,
        )?;

        Ok(Self {
            scope,
            scenarios,
            artifact,
        })
    }

    /// Canonical mappings and exact interpretation identity.
    pub fn artifact(&self) -> &CanonicalArtifact {
        &self.artifact
    }
}

/// Machine-readable selection witness. Full review is conservative expansion,
/// never a claim that unresolved relations were resolved.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScenarioReason {
    /// Cannot be removed by impact optimization.
    Mandatory,
    /// The bound impact retains all uncertainty and exact changed source paths.
    ConservativeFullReview,
    /// A changed node reaches an authority-mapped component through actual edges.
    RelationClosure {
        /// Changed file/syntax/authority node in the bound impact.
        changed_node: String,
        /// A component or authority node matched by the catalog trigger.
        affected_node: String,
        /// Accepted edges in traversal order, conservatively bidirectional.
        relations: Vec<KnowledgeEdge>,
    },
}

/// One scenario and its deterministic, auditable reason.
#[derive(Debug, Serialize)]
pub struct SelectedScenario {
    /// Exact catalog scenario ID.
    pub id: String,
    /// Mandatory selection or a conservative/mechanical derivation.
    pub reason: ScenarioReason,
}

/// Immutable evidence with explicit input bindings and retained impact uncertainty.
#[derive(Debug)]
pub struct ScenarioSelection {
    selected: Vec<SelectedScenario>,
    impact: ImpactArtifact,
    artifact: CanonicalArtifact,
}

impl ScenarioSelection {
    /// Canonical scenario ID order. Mandatory scenarios are always present.
    pub fn selected(&self) -> &[SelectedScenario] {
        &self.selected
    }

    /// Complete impact read model, including blind spots and full-review state.
    pub fn impact(&self) -> &ImpactArtifact {
        &self.impact
    }

    /// Exact scope/source/catalog/knowledge/impact and selection evidence.
    pub fn artifact(&self) -> &CanonicalArtifact {
        &self.artifact
    }
}

/// Select additional deterministic validation without changing any execution plan.
/// Recompute impact from private accepted artifacts rather than trusting a caller's
/// list of affected nodes. Unsupported dimensions select every catalog scenario.
pub fn select_validation_scenarios(
    catalog: &ScenarioCatalog,
    target: &KnowledgeArtifact,
    baseline: Option<&KnowledgeArtifact>,
) -> Result<ScenarioSelection, KnowledgeError> {
    if !catalog.scope.permits(target.body().project) {
        return Err(KnowledgeError::BindingMismatch);
    }

    let impact = analyze_impact(target, baseline)?;
    let witnesses = if impact.body().full_review {
        BTreeMap::new()
    } else {
        relation_witnesses(target, baseline, &impact)?
    };
    let nodes: BTreeMap<_, _> = target
        .body()
        .nodes
        .iter()
        .chain(baseline.into_iter().flat_map(|b| &b.body().nodes))
        .map(|node| (node.id.clone(), node))
        .collect();
    let mut selected = Vec::new();

    for scenario in &catalog.scenarios {
        let reason = if scenario.requirement == ScenarioRequirement::Mandatory {
            Some(ScenarioReason::Mandatory)
        } else if impact.body().full_review {
            Some(ScenarioReason::ConservativeFullReview)
        } else {
            nodes.values().find_map(|node| {
                let matches = scenario.triggers.iter().any(|trigger| match trigger {
                    ScenarioTrigger::Path { path } => node.id == file_id(path),
                    ScenarioTrigger::AuthorityEntry { id } => {
                        node.provenance == Provenance::AuthorityAsserted && node.label == *id
                    }
                });

                if !matches {
                    return None;
                }

                witnesses
                    .get(&node.id)
                    .map(|(seed, edges)| ScenarioReason::RelationClosure {
                        changed_node: seed.clone(),
                        affected_node: node.id.clone(),
                        relations: edges.clone(),
                    })
            })
        };

        if let Some(reason) = reason {
            selected.push(SelectedScenario {
                id: scenario.id.clone(),
                reason,
            });
        }
    }

    let artifact = CanonicalArtifact::freeze(
        &serde_json::json!({
            "schema": 1,
            "kind": "ARCHCERT_ASTERWYN_SCENARIO_SELECTION",
            "algorithm": "asterwyn-scenario-selection-v1/1.0.0",
            "project": target.body().project,
            "repository": target.body().repository,
            "source": target.body().source,
            "baseline_source": impact.body().baseline_source,
            "knowledge_sha256": target.artifact().digest(),
            "baseline_knowledge_sha256": impact.body().baseline_knowledge_sha256,
            "catalog_sha256": catalog.artifact().digest(),
            "impact_sha256": impact.artifact().digest(),
            "selected": selected,
        }),
        8 * 1024 * 1024,
    )?;

    Ok(ScenarioSelection {
        selected,
        impact,
        artifact,
    })
}

type Witnesses = BTreeMap<String, (String, Vec<KnowledgeEdge>)>;

fn relation_witnesses(
    target: &KnowledgeArtifact,
    baseline: Option<&KnowledgeArtifact>,
    impact: &ImpactArtifact,
) -> Result<Witnesses, KnowledgeError> {
    let mut edges = BTreeMap::new();

    for edge in target
        .body()
        .edges
        .iter()
        .chain(baseline.into_iter().flat_map(|b| &b.body().edges))
    {
        edges.insert(canonical_bytes(edge)?, edge);
    }

    let mut adjacent = BTreeMap::<String, Vec<&KnowledgeEdge>>::new();

    for edge in edges.into_values() {
        adjacent.entry(edge.from.clone()).or_default().push(edge);
        adjacent.entry(edge.to.clone()).or_default().push(edge);
    }

    let mut witnesses = Witnesses::new();
    let mut pending = VecDeque::new();
    let seeds = impact
        .body()
        .changed_nodes
        .iter()
        .cloned()
        .chain(
            impact
                .body()
                .changed_files
                .iter()
                .chain(&impact.body().added_files)
                .chain(&impact.body().deleted_files)
                .map(file_id),
        )
        .collect::<BTreeSet<_>>();

    for seed in seeds {
        witnesses.insert(seed.clone(), (seed.clone(), Vec::new()));
        pending.push_back(seed);
    }

    while let Some(node) = pending.pop_front() {
        let (seed, path) = witnesses
            .get(&node)
            .cloned()
            .ok_or(KnowledgeError::Invalid)?;

        for edge in adjacent.get(&node).into_iter().flatten() {
            let next = if edge.from == node {
                &edge.to
            } else {
                &edge.from
            };

            if witnesses.contains_key(next) {
                continue;
            }

            if path.len() >= target.body().limits.impact_depth {
                return Err(KnowledgeError::LimitExceeded);
            }

            let mut next_path = path.clone();
            next_path.push((*edge).clone());
            witnesses.insert(next.clone(), (seed.clone(), next_path));
            pending.push_back(next.clone());
        }
    }

    Ok(witnesses)
}
