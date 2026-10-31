//! Explicit Greywatch protocol. Historical request/response interpretation is unchanged.

use super::packaging::stabilize_size;
use super::*;
use archcert_domain::source::SourcePath;
use std::collections::BTreeMap;

/// Authority-owned interpretation identity, included verbatim in each new request.
pub const GREYWATCH_PROTOCOL: &str = "archcert-greywatch-v1/1.0.1";

/// Gate interpretation for typed claims, inherited coverage and provider outcomes.
pub const GREYWATCH_GATE_ALGORITHM: &str = "archcert-greywatch-gate-v1/1.0.0";

/// Separate template and parser identities make re-review requirements explicit.
pub fn greywatch_protocol() -> serde_json::Value {
    serde_json::json!({
        "id": GREYWATCH_PROTOCOL,
        "request_schema": 3,
        "response_schema": 2,
        "normalization_schema": 1,
        "gate_algorithm": GREYWATCH_GATE_ALGORITHM,
        "response_fields": [
            "schema", "request_sha256", "outcome", "complete",
            "items", "proposed_challenges", "claims", "discoveries"
        ],
        "claim_fields": [
            "id", "subject", "proposition", "polarity", "statement",
            "supporting", "contradicting"
        ],
        "discovery_fields": [
            "id", "kind", "statement", "citations"
        ],
        "provider_outcomes": ["COMPLETED", "REFUSED", "CONTEXT_EXHAUSTED"],
        "claim_polarities": ["AFFIRMS", "DENIES"],
        "citation_kinds": ["SOURCE", "KNOWLEDGE", "OBSERVATION", "AUTHORITY"],
        "template": "archcert-greywatch-structured-v1/1.0.0",
        "system_instruction_sha256": digest_bytes(AUTHORITY_REVIEW_CONTRACT.as_bytes()),
        "task": "Report supplemental claims and discoveries. Cite only admitted immutable inputs. Explicit opposite polarities for the same subject and proposition require authority resolution. No semantic statement establishes a deterministic verdict.",
        "unknown_fields": "REJECT",
        "citation_policy": "EXACT_ADMITTED_IDENTITIES",
        "contradiction_policy": "REQUIRE_MORE_EVIDENCE",
        "discovery_policy": "SUPPLEMENTAL_ONLY",
        "expiration": "NONE"
    })
}

pub(super) struct GreywatchRequestContext {
    files: BTreeMap<SourcePath, (Sha256Digest, usize)>,
    nodes: BTreeSet<String>,
    observations: BTreeSet<String>,
    identity: Sha256Digest,
}

// Do not expose the admitted citation index through diagnostics.
impl std::fmt::Debug for GreywatchRequestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GreywatchRequestContext")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl SemanticReviewRequest {
    /// New bounded protocol. The semantic identity excludes the operational job UUID;
    /// the invocation request still binds that UUID to prevent cross-session response replay.
    pub fn prepare_greywatch(
        context: ReviewContext<'_>,
        selection: ReviewerSelection,
        limits: SemanticLimits,
        policy: SemanticPackagingPolicy,
    ) -> Result<Self, KnowledgeError> {
        let files = context
            .source
            .files()
            .iter()
            .map(|file| {
                // A final newline terminates a line; it does not invent another line.
                let lines = file.bytes().split_inclusive(|b| *b == b'\n').count();
                (file.path().clone(), (digest_bytes(file.bytes()), lines))
            })
            .collect();
        let nodes = context
            .knowledge
            .body()
            .nodes
            .iter()
            .map(|n| n.id.clone())
            .collect();
        let observations = context
            .observations
            .iter()
            .map(|o| canonical_bytes(o).map(|bytes| digest_bytes(&bytes).as_str().to_owned()))
            .collect::<Result<_, _>>()?;

        // Reserve both copies of mandatory protocol context before selecting optional
        // repository data. Final serialization still checks the original exact ceiling.
        let reserved_envelope_bytes = 2 * canonical_bytes(&greywatch_protocol())?.len() + 512;
        let job = context.job;
        let stable_context = ReviewContext {
            job: JobId::parse("00000000-0000-4000-8000-000000000000")
                .map_err(|_| KnowledgeError::Invalid)?,
            ..context
        };
        let mut request = Self::prepare_impl(
            stable_context,
            selection,
            limits,
            Some(policy),
            reserved_envelope_bytes,
        )?;
        request.binding.job = job;
        let package = request.package.as_mut().ok_or(KnowledgeError::Invalid)?;
        let mut body: serde_json::Value = serde_json::from_slice(package.artifact.bytes())
            .map_err(|_| KnowledgeError::Invalid)?;

        body["schema"] = serde_json::json!(2);
        body["binding"]
            .as_object_mut()
            .ok_or(KnowledgeError::Invalid)?
            .remove("job");
        body["protocol"] = greywatch_protocol();
        stabilize_size(&mut body, "actual_package_bytes")?;
        package.artifact = CanonicalArtifact::freeze(&body, limits.request_bytes)?;

        let identity = digest_bytes(&canonical_bytes(&serde_json::json!({
            "protocol": greywatch_protocol(),
            "package_sha256": package.artifact.digest(),
            "reviewer": request.selection,
            "limits": limits
        }))?);
        let mut envelope: serde_json::Value = serde_json::from_slice(request.artifact.bytes())
            .map_err(|_| KnowledgeError::Invalid)?;
        envelope["schema"] = serde_json::json!(3);
        envelope["binding"] =
            serde_json::to_value(&request.binding).map_err(|_| KnowledgeError::Invalid)?;
        envelope["protocol"] = greywatch_protocol();
        envelope["semantic_identity"] = serde_json::json!(identity);
        envelope["package_sha256"] = serde_json::json!(package.artifact.digest());
        envelope["package"] = body;
        stabilize_size(&mut envelope, "actual_request_bytes")?;
        request.artifact = CanonicalArtifact::freeze(&envelope, limits.request_bytes)?;
        request.greywatch = Some(GreywatchRequestContext {
            files,
            nodes,
            observations,
            identity,
        });

        Ok(request)
    }

    /// Stable semantic identity, separate from an invocation's request digest.
    pub fn semantic_identity(&self) -> Option<&Sha256Digest> {
        self.greywatch.as_ref().map(|g| &g.identity)
    }
}

/// Provider completion state is infrastructure/semantic provenance, never policy truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GreywatchProviderOutcome {
    /// The provider reports processing the bounded request.
    Completed,
    /// The provider refused the request; no repository analysis is inferred.
    Refused,
    /// The provider could not finish within its context.
    ContextExhausted,
}

/// Strict citations identify admitted bytes; their interpretation remains a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SemanticCitation {
    /// Exact file bytes and an actual inclusive source line range.
    Source {
        /// Immutable snapshot digest, not a branch or mutable checkout.
        snapshot_sha256: Sha256Digest,
        /// Admitted relative source path.
        path: SourcePath,
        /// Exact admitted file digest.
        content_sha256: Sha256Digest,
        /// First line, starting at one.
        first_line: usize,
        /// Last line, inclusive.
        last_line: usize,
    },
    /// A real node in the accepted deterministic knowledge artifact.
    Knowledge {
        /// Exact knowledge artifact.
        knowledge_sha256: Sha256Digest,
        /// Exact observed node ID; no symbol resolution is inferred.
        node: String,
    },
    /// A controller observation actually included in this request.
    Observation {
        /// Exact canonical observation bytes.
        sha256: Sha256Digest,
    },
    /// A separately approved invariant/finding/policy identity in this request.
    Authority {
        /// Exact selected policy/bundle-entry spelling.
        id: String,
    },
}

/// Opposite explicit polarities can be compared without interpreting prose as truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimPolarity {
    /// The provider asserts the named proposition.
    Affirms,
    /// The provider denies the same proposition.
    Denies,
}

/// A provider assertion. The containing accepted artifact supplies exact provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticClaim {
    /// Stable local identity within the immutable artifact.
    pub id: String,
    /// Bounded subject key, not an inferred source location.
    pub subject: String,
    /// Exact normalized proposition key shared by explicitly opposite claims.
    pub proposition: String,
    /// Assertion/denial, never a deterministic verdict.
    pub polarity: ClaimPolarity,
    /// Supplemental explanation.
    pub statement: String,
    /// Cited immutable objects claimed to support this assertion.
    pub supporting: Vec<SemanticCitation>,
    /// Cited immutable objects reported to contradict this assertion.
    pub contradicting: Vec<SemanticCitation>,
}

/// Discoveries are supplemental observations, separately typed from assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryKind {
    /// Suspicious code pattern.
    SuspiciousPattern,
    /// Possible defect, not a proven deterministic failure.
    PotentialBug,
    /// Possible hidden relationship.
    HiddenDependency,
    /// Missing validation concern.
    MissingValidation,
    /// Possible architecture mismatch.
    ArchitecturalInconsistency,
    /// Supplemental security concern.
    SecurityConcern,
    /// Unexpected behavior alleged by a reviewer.
    UnexpectedBehavior,
    /// Scope the provider did not establish.
    UnreviewedArea,
}

/// Non-authoritative discovery with exact source-session provenance through its artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDiscovery {
    /// Stable artifact-local identity.
    pub id: String,
    /// Explicit concern category.
    pub kind: DiscoveryKind,
    /// Bounded untrusted explanation.
    pub statement: String,
    /// Validated immutable citations; they do not validate the explanation.
    pub citations: Vec<SemanticCitation>,
}

/// Closed provider response. Deserialization alone never accepts supplemental evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GreywatchProviderResponse {
    /// Exactly 2; unknown schemas reject.
    pub schema: u32,
    /// Exact invocation request digest, including the operational session binding.
    pub request_sha256: Sha256Digest,
    /// Provider outcome, separate from deterministic policy verdicts.
    pub outcome: GreywatchProviderOutcome,
    /// Provider processing completeness cannot promote package coverage.
    pub complete: bool,
    /// Historical bounded concern/veto/blind-spot vocabulary.
    pub items: Vec<SemanticItem>,
    /// Registered-template proposals requiring authority mediation.
    pub proposed_challenges: Vec<ChallengeProposal>,
    /// Explicit assertions with citation links.
    pub claims: Vec<SemanticClaim>,
    /// Supplemental discoveries with citation links.
    pub discoveries: Vec<SemanticDiscovery>,
}

/// Authority evaluation of a semantic assertion, separate from deterministic verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SemanticClaimDisposition {
    /// No truth is inferred from a provider assertion or its citation.
    Unverified,
    /// Explicit conflicting polarities or contradictory evidence require resolution.
    RequiresAuthorityResolution,
}

/// Normalized immutable assertion and its conservative authority disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessedSemanticClaim {
    /// Untrusted provider claim, with validated citation identities only.
    pub claim: SemanticClaim,
    /// Authority-owned assessment; never PROVEN or FAILED.
    pub disposition: SemanticClaimDisposition,
}

/// Canonical contradiction record; both artifact-local identities remain inspectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticContradiction {
    /// Explicit proposition subject key.
    pub subject: String,
    /// Exact proposition key; no general NLP consistency claim is made.
    pub proposition: String,
    /// Sorted IDs for all assertions/denials in this group.
    pub claim_ids: Vec<String>,
}

/// Recomputed from retained raw response bytes during recovery. Never target-authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GreywatchSupplement {
    /// Explicit normalized interpretation version.
    pub protocol: String,
    /// Stable semantic input identity.
    pub semantic_identity: Sha256Digest,
    /// Provider completion state.
    pub outcome: GreywatchProviderOutcome,
    /// Assessed supplemental claims, sorted by local ID.
    pub claims: Vec<AssessedSemanticClaim>,
    /// Supplemental discoveries, sorted by local ID.
    pub discoveries: Vec<SemanticDiscovery>,
    /// Explicit conflicts requiring more evidence.
    pub contradictions: Vec<SemanticContradiction>,
}

fn bounded_text(text: &str, maximum: usize) -> bool {
    !text.is_empty()
        && text.len() <= maximum
        && text.trim() == text
        && !text.chars().any(char::is_control)
}

fn citations_valid(request: &SemanticReviewRequest, citations: &[SemanticCitation]) -> bool {
    let Some(context) = &request.greywatch else {
        return false;
    };

    citations.len() <= 32
        && citations.iter().all(|citation| match citation {
            SemanticCitation::Source {
                snapshot_sha256,
                path,
                content_sha256,
                first_line,
                last_line,
            } => {
                snapshot_sha256 == &request.binding.source.snapshot_sha256
                    && context.files.get(path).is_some_and(|(digest, lines)| {
                        digest == content_sha256
                            && *first_line > 0
                            && first_line <= last_line
                            && last_line <= lines
                    })
            }
            SemanticCitation::Knowledge {
                knowledge_sha256,
                node,
            } => {
                knowledge_sha256 == &request.binding.knowledge_sha256
                    && context.nodes.contains(node)
            }
            SemanticCitation::Observation { sha256 } => {
                context.observations.contains(sha256.as_str())
            }
            SemanticCitation::Authority { id } => request.authority_ids.contains(id),
        })
}

pub(super) fn validated_supplement(
    request: &SemanticReviewRequest,
    output: &ReviewerOutput,
) -> Result<(SemanticReviewResponse, Option<GreywatchSupplement>), SemanticReviewError> {
    let Some(context) = &request.greywatch else {
        return validate_response(request, output).map(|r| (r, None));
    };

    validate_output(request, output)?;
    let provider: GreywatchProviderResponse =
        serde_json::from_slice(&output.bytes).map_err(|_| SemanticReviewError::Malformed)?;

    if provider.schema != 2
        || provider.items.len() + provider.claims.len() + provider.discoveries.len()
            > request.limits.items
        || (provider.outcome != GreywatchProviderOutcome::Completed
            && (provider.complete
                || !provider.items.is_empty()
                || !provider.claims.is_empty()
                || !provider.discoveries.is_empty()
                || !provider.proposed_challenges.is_empty()))
    {
        return Err(SemanticReviewError::Malformed);
    }

    let response = SemanticReviewResponse {
        schema: 1,
        request_sha256: provider.request_sha256,
        complete: provider.complete && provider.outcome == GreywatchProviderOutcome::Completed,
        items: provider.items,
        proposed_challenges: provider.proposed_challenges,
    };
    validate_items(request, &response)?;

    let mut ids: BTreeSet<_> = response
        .items
        .iter()
        .map(|i| i.id.clone())
        .chain(response.proposed_challenges.iter().map(|p| p.id.clone()))
        .collect();
    let mut groups = BTreeMap::<(String, String), Vec<&SemanticClaim>>::new();

    for claim in &provider.claims {
        if !local_id(&claim.id)
            || !ids.insert(claim.id.clone())
            || !bounded_text(&claim.subject, 128)
            || !bounded_text(&claim.proposition, 256)
            || !bounded_text(&claim.statement, 2048)
            || !citations_valid(request, &claim.supporting)
            || !citations_valid(request, &claim.contradicting)
        {
            return Err(SemanticReviewError::Malformed);
        }

        groups
            .entry((claim.subject.clone(), claim.proposition.clone()))
            .or_default()
            .push(claim);
    }

    let mut contradictions = Vec::new();
    let mut conflicting = BTreeSet::new();

    for ((subject, proposition), claims) in groups {
        if claims.iter().any(|c| c.polarity == ClaimPolarity::Affirms)
            && claims.iter().any(|c| c.polarity == ClaimPolarity::Denies)
        {
            let mut claim_ids: Vec<_> = claims.iter().map(|c| c.id.clone()).collect();
            claim_ids.sort();
            conflicting.extend(claim_ids.iter().cloned());
            contradictions.push(SemanticContradiction {
                subject,
                proposition,
                claim_ids,
            });
        }
    }

    for discovery in &provider.discoveries {
        if !local_id(&discovery.id)
            || !ids.insert(discovery.id.clone())
            || !bounded_text(&discovery.statement, 2048)
            || !citations_valid(request, &discovery.citations)
        {
            return Err(SemanticReviewError::Malformed);
        }
    }

    let mut claims: Vec<_> = provider
        .claims
        .into_iter()
        .map(|claim| {
            let disposition = if conflicting.contains(&claim.id) || !claim.contradicting.is_empty()
            {
                SemanticClaimDisposition::RequiresAuthorityResolution
            } else {
                SemanticClaimDisposition::Unverified
            };
            AssessedSemanticClaim { claim, disposition }
        })
        .collect();

    claims.sort_by(|a, b| a.claim.id.cmp(&b.claim.id));
    let mut discoveries = provider.discoveries;
    discoveries.sort_by(|a, b| a.id.cmp(&b.id));

    Ok((
        response,
        Some(GreywatchSupplement {
            protocol: GREYWATCH_PROTOCOL.into(),
            semantic_identity: context.identity.clone(),
            outcome: provider.outcome,
            claims,
            discoveries,
            contradictions,
        }),
    ))
}
