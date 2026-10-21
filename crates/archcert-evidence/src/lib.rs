//! Deterministic evidence manifest; detailed payloads remain in the evidence bundle.
use archcert_application::validation::ValidationObservation;
use archcert_domain::{Sha256Digest, execution::ExecutionEvidence, source::digest_bytes};
use archcert_policy::{EvidenceRef, PolicyEvaluation};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

/// Evidence or canonicalization failure, without target payload diagnostics.
#[derive(Debug, Error)]
pub enum EvidenceError {
    /// A finding or observation reference did not resolve to its exact payload.
    #[error("evidence binding mismatch")]
    EvidenceBindingMismatch,
    /// The restricted canonical format could not represent this value.
    #[error("canonicalization failed")]
    CanonicalizationFailed,
}
/// Restricted canonical JSON, documented in ADR-0025. All keys must be ASCII;
/// numbers must be integers in the interoperable range. Sort every object key
/// recursively, compact UTF-8 JSON, no BOM/newline, preserve strings and arrays.
/// This is deliberately not a general RFC 8785 implementation.
pub fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, EvidenceError> {
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
    let mut v = serde_json::to_value(value).map_err(|_| EvidenceError::CanonicalizationFailed)?;
    if !valid(&v) {
        return Err(EvidenceError::CanonicalizationFailed);
    }
    v.sort_all_objects();
    serde_json::to_vec(&v).map_err(|_| EvidenceError::CanonicalizationFailed)
}
/// Semantic evaluation identity excludes only the explicitly non-decisional audit
/// timestamp. Schema and evaluator version are included; issuance time is separate.
pub fn evaluation_digest(evaluation: &PolicyEvaluation) -> Result<Sha256Digest, EvidenceError> {
    let mut value =
        serde_json::to_value(evaluation).map_err(|_| EvidenceError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(EvidenceError::CanonicalizationFailed)?
        .remove("evaluated_at");
    Ok(digest_bytes(&canonical_bytes(&serde_json::json!({
        "schema":1,"kind":"ARCHCERT_POLICY_EVALUATION","evaluation":value
    }))?))
}
/// Canonical detailed evidence bundle, stored separately from the small certificate.
#[derive(Debug)]
pub struct EvidenceBundle {
    bytes: Vec<u8>,
    digest: Sha256Digest,
}
impl EvidenceBundle {
    /// Builds a deterministic retained bundle from exact consumed observations,
    /// findings and detailed controller execution records, including log prefixes.
    /// Record/observation order is normalized by digest; audit evaluated_at is
    /// excluded from semantic evaluation identity, while execution audit data stays.
    pub fn build(
        e: &PolicyEvaluation,
        observations: &[ValidationObservation],
        records: &[ExecutionEvidence],
    ) -> Result<Self, EvidenceError> {
        if records.len() > 160 || observations.len() > 4096 || e.findings.len() > 32 {
            return Err(EvidenceError::EvidenceBindingMismatch);
        }
        let mut sorted_observations = BTreeMap::new();
        for o in observations {
            sorted_observations.insert(digest_bytes(&canonical_bytes(o)?).as_str().to_owned(), o);
        }
        let mut sorted_records = BTreeMap::new();
        for r in records {
            // Bound even a mutated trusted caller's prefixes before JSON expansion.
            if r.source != e.source
                || r.stdout.excerpt.len() > 65536
                || r.stderr.excerpt.len() > 65536
            {
                return Err(EvidenceError::EvidenceBindingMismatch);
            }
            sorted_records.insert(digest_bytes(&canonical_bytes(r)?).as_str().to_owned(), r);
        }
        let mut findings: BTreeMap<_, _> = BTreeMap::new();
        for f in &e.findings {
            findings.insert(f.id.as_str(), f);
        }
        let bytes = canonical_bytes(&serde_json::json!({
            "schema":1,"kind":"ARCHCERT_EVIDENCE_BUNDLE","source":e.source,"policy":e.policy,
            "plan_sha256":e.plan_sha256,"evaluation_sha256":evaluation_digest(e)?,
            "observations":sorted_observations.into_values().collect::<Vec<_>>(),
            "findings":findings.into_values().collect::<Vec<_>>(),
            "execution_records":sorted_records.into_values().collect::<Vec<_>>(),
        }))?;
        Ok(Self {
            digest: digest_bytes(&bytes),
            bytes,
        })
    }
    /// Exact bundle bytes; no private key or certificate signature is present.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// SHA-256 identity bound by the evidence manifest.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}
/// Immutable canonical manifest. Construction validates every actual reference.
/// No raw logs, source bytes or private keys are stored in it.
#[derive(Debug)]
pub struct EvidenceManifest {
    bytes: Vec<u8>,
    digest: Sha256Digest,
}
impl EvidenceManifest {
    /// Binds a checked evaluation to exact sorted/deduplicated observation payloads
    /// and full finding digests. The issuer separately re-evaluates policy inputs.
    pub fn build(
        e: &PolicyEvaluation,
        observations: &[ValidationObservation],
    ) -> Result<Self, EvidenceError> {
        Self::build_with_bundle(e, observations, None)
    }
    /// Builds a manifest that also binds a detailed canonical evidence bundle.
    pub fn build_with_bundle(
        e: &PolicyEvaluation,
        observations: &[ValidationObservation],
        bundle: Option<&EvidenceBundle>,
    ) -> Result<Self, EvidenceError> {
        if observations.len() > 4096 || e.findings.len() > 32 || e.properties.len() > 32 {
            return Err(EvidenceError::EvidenceBindingMismatch);
        }
        if e.properties.iter().any(|p| {
            p.description.len() > 2048
                || p.required_evidence.len() > 160
                || p.actual_evidence.len() > 4096
        }) || e.findings.iter().any(|f| f.observations.len() > 4096)
        {
            return Err(EvidenceError::EvidenceBindingMismatch);
        }
        let mut payloads = BTreeMap::new();
        for o in observations {
            if o.schema != 1
                || o.source != e.source
                || o.plan_sha256 != e.plan_sha256
                || o.id.step.len() > 128
                || o.producer.len() > 128
                || o.profile.len() > 128
            {
                return Err(EvidenceError::EvidenceBindingMismatch);
            }
            payloads.insert(digest_bytes(&canonical_bytes(o)?).as_str().to_owned(), o);
        }
        for r in e
            .properties
            .iter()
            .flat_map(|p| &p.actual_evidence)
            .chain(e.findings.iter().flat_map(|f| &f.observations))
        {
            match r {
                EvidenceRef::SourceSnapshot { sha256 } if sha256 == &e.source.snapshot_sha256 => {}
                EvidenceRef::Observation { id, sha256 } => {
                    let o = payloads
                        .get(sha256.as_str())
                        .ok_or(EvidenceError::EvidenceBindingMismatch)?;
                    if canonical_bytes(id)? != canonical_bytes(&o.id)? {
                        return Err(EvidenceError::EvidenceBindingMismatch);
                    }
                }
                _ => return Err(EvidenceError::EvidenceBindingMismatch),
            }
        }
        let mut findings = BTreeMap::new();
        for f in &e.findings {
            if findings
                .insert(f.id.as_str(), digest_bytes(&canonical_bytes(f)?))
                .is_some()
            {
                return Err(EvidenceError::EvidenceBindingMismatch);
            }
        }
        let observations: Vec<_> = payloads
            .into_iter()
            .map(|(sha256, o)| serde_json::json!({"id":o.id,"sha256":sha256}))
            .collect();
        let findings: Vec<_> = findings
            .into_iter()
            .map(|(id, sha256)| serde_json::json!({"id":id,"sha256":sha256}))
            .collect();
        let bytes = canonical_bytes(&serde_json::json!({
            "schema":1,"kind":"ARCHCERT_EVIDENCE_MANIFEST", "source":e.source,
            "policy":e.policy,"plan_sha256":e.plan_sha256,"evaluation_sha256":evaluation_digest(e)?,
            "observations":observations,"findings":findings,"evidence_bundle_sha256":bundle.map(EvidenceBundle::digest),
        }))?;
        Ok(Self {
            digest: digest_bytes(&bytes),
            bytes,
        })
    }
    /// Explicit schema-2 extension: preserve the complete historical schema-1
    /// manifest and bind exact typed Ironcrest artifacts. This validates identity
    /// grammar, not semantic/provider honesty or issuance authorization.
    pub fn with_ironcrest(
        &self,
        binding: &archcert_application::ironcrest::IroncrestEvidenceBinding,
    ) -> Result<Self, EvidenceError> {
        use archcert_application::ironcrest::IroncrestEvidenceRole as R;
        let original: Value = serde_json::from_slice(&self.bytes)
            .map_err(|_| EvidenceError::CanonicalizationFailed)?;
        if original["schema"] != 1
            || original["kind"] != "ARCHCERT_EVIDENCE_MANIFEST"
            || original["source"]
                != serde_json::to_value(&binding.pin.source)
                    .map_err(|_| EvidenceError::CanonicalizationFailed)?
            || original["policy"]
                != serde_json::to_value(&binding.pin.policy)
                    .map_err(|_| EvidenceError::CanonicalizationFailed)?
            || original["plan_sha256"] != binding.plan_sha256.as_str()
            || binding.roles.len() != 8
        {
            return Err(EvidenceError::EvidenceBindingMismatch);
        }
        let expected = [
            R::AuthorityProfile,
            R::Knowledge,
            R::Impact,
            R::Request,
            R::Review,
            R::Gate,
            R::ChallengePlan,
            R::ChallengeResult,
        ];
        for ((role, reference), expected) in binding.roles.iter().zip(expected) {
            let schema = if matches!(role, R::Gate | R::ChallengePlan) {
                2
            } else {
                1
            };
            if *role != expected
                || reference.schema != schema
                || reference.size == 0
                || reference.size > 32 * 1024 * 1024
                || reference.producer != "archcert-ironcrest-v1/0.1.0"
                || (*role == R::AuthorityProfile
                    && reference.sha256 != binding.pin.authority_profile_sha256)
            {
                return Err(EvidenceError::EvidenceBindingMismatch);
            }
        }
        let bytes = canonical_bytes(&serde_json::json!({
            "schema":2,"kind":"ARCHCERT_EVIDENCE_MANIFEST",
            "deterministic_manifest_sha256":self.digest,
            "deterministic_manifest":original,"ironcrest":binding
        }))?;
        Ok(Self {
            digest: digest_bytes(&bytes),
            bytes,
        })
    }
    /// Exact deterministic manifest preimage.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// SHA-256 of the canonical manifest, not a signature.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}
