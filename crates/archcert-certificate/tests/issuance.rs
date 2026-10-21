//! Adversarial issuance, parser, canonical identity and offline verification tests.

use archcert_application::{configuration::ProjectConfiguration, validation::*};
use archcert_certificate::*;
use archcert_crypto::{
    CertificateSigner, DetachedSignature, PublicKey, SigningFailure, SigningKeyId,
};
use archcert_domain::{GitObjectId, ProjectId, execution::ExecutionOutcome, source::*};
use archcert_evidence::{EvidenceManifest, canonical_bytes, evaluation_digest};
use archcert_policy::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::cell::Cell;
type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    source: SourceSnapshot,
    plan: ValidationPlan,
    executions: Vec<ExpectedExecution>,
    observations: Vec<ValidationObservation>,
    bundle: PolicyBundle,
    records: Vec<archcert_domain::execution::ExecutionEvidence>,
}

fn fixture() -> R<Fixture> {
    let source = SourceSnapshot::seal(
        serde_json::from_str::<ProjectId>("\"00000000-0000-4000-8000-000000000004\"")?,
        RepositoryId::parse("fixture/eldermark")?,
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![],
        1,
        1,
    )?;
    let authority = AuthorityConfiguration::development(vec![(
        "python".into(),
        format!("approved@sha256:{}", "a".repeat(64)),
    )])?;
    let required = [
        ("typecheck", EvidenceCategory::Typecheck),
        ("test", EvidenceCategory::Test),
        ("build", EvidenceCategory::Build),
    ]
    .into_iter()
    .map(|(id, evidence)| {
        Ok(AuthorityRequiredStep {
            id: id.into(),
            profile: "python".into(),
            command: ExecutionCommand::new(
                "python3".into(),
                vec!["-c".into(), "pass".into()],
                "/source".into(),
            )?,
            evidence,
        })
    })
    .collect::<R<Vec<_>>>()?;

    let plan = authority.with_required_steps(required)?.resolve(None)?;
    let executions: Vec<_> = plan
        .steps()
        .iter()
        .map(|s| ExpectedExecution {
            step: s.id().into(),
            execution: ExecutionId::new(),
        })
        .collect();
    let mut observations = vec![];

    for (s, e) in plan.steps().iter().zip(&executions) {
        for (kind, fact) in [
            (
                ObservationKind::SourceIdentityMatched,
                ObservationFact::SourceIdentityMatched,
            ),
            (
                ObservationKind::NetworkDenied,
                ObservationFact::NetworkDenied,
            ),
            (
                ObservationKind::EnvironmentEstablished,
                ObservationFact::EnvironmentEstablished {
                    toolchain: ToolchainObservation::NotObserved,
                },
            ),
            (
                ObservationKind::ExecutionFinished,
                ObservationFact::ExecutionFinished {
                    outcome: ExecutionOutcome::Completed,
                    exit_code: Some(0),
                    category: s.evidence_category(),
                },
            ),
        ] {
            observations.push(ValidationObservation {
                schema: 1,
                id: ObservationId {
                    execution: e.execution,
                    step: s.id().into(),
                    kind,
                },
                source: source.identity().clone(),
                plan_sha256: plan.digest()?,
                profile: "python".into(),
                producer: "archcert-docker-cli-v1/0.1.0".into(),
                fact,
            });
        }
    }

    use archcert_domain::{execution::*, materialization::WorkspaceId};
    let mut records = Vec::new();

    for (step, execution) in plan.steps().iter().zip(&executions) {
        let empty = CapturedStream {
            sha256: digest_bytes(b""),
            observed_bytes: 0,
            excerpt: vec![],
            truncated: false,
            complete: true,
        };
        records.push(ExecutionEvidence {
            execution: execution.execution,
            source: source.identity().clone(),
            workspace: WorkspaceId::new(),
            backend: "test-controller".into(),
            backend_version: "archcert-docker-cli-v1".into(),
            producer_version: "0.1.0".into(),
            observed_runtime: ObservedRuntimeIdentity {
                client_path: "/trusted/runtime".into(),
                client_version: "test-client".into(),
                server_version: "test-server".into(),
                runtime_information: Default::default(),
            },
            toolchain: ToolchainObservation::NotObserved,
            image_digest: step.profile().image().into(),
            base_image_id: format!("sha256:{}", "c".repeat(64)),
            execution_image_id: format!("sha256:{}", "d".repeat(64)),
            profile: "python".into(),
            command: step.command().clone(),
            network: NetworkPolicy::Denied,
            limits: step.profile().limits(),
            environment_keys: sandbox_environment().into_keys().collect(),
            container_user: "10001:10001".into(),
            started_at_ms: 1,
            ended_at_ms: 2,
            duration_ms: 1,
            exit_code: Some(0),
            termination: TerminationReason::Exit,
            stdout: empty.clone(),
            stderr: empty,
            outcome: ExecutionOutcome::Completed,
        });
    }

    Ok(Fixture {
        source,
        plan,
        executions,
        observations,
        bundle: development_bundle()?,
        records,
    })
}

impl Fixture {
    fn evaluation(&self) -> R<PolicyEvaluation> {
        Ok(evaluate(
            &self.bundle,
            self.bundle.identity(),
            EvaluationInput {
                source: &self.source,
                plan: &self.plan,
                executions: &self.executions,
                observations: &self.observations,
                evaluated_at: 1,
            },
        )?)
    }

    fn context(&self) -> IssuanceContext<'_> {
        IssuanceContext {
            source: &self.source,
            plan: &self.plan,
            executions: &self.executions,
            observations: &self.observations,
            execution_records: &self.records,
            bundle: &self.bundle,
            selected: self.bundle.identity(),
        }
    }

    fn draft(
        &self,
        e: Option<PolicyEvaluation>,
        key: PublicKey,
    ) -> Result<CertificateDraft, CertificateError> {
        CertificateDraft::prepare(
            self.context(),
            e,
            IssuanceMetadata {
                issued_at: 1_700_000_000,
                certifier: "fixture-authority".into(),
            },
            key,
        )
    }
}

struct CountingSigner {
    key: SigningKey,
    count: Cell<usize>,
    mode: u8,
}

impl CountingSigner {
    fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
            count: Cell::new(0),
            mode: 0,
        }
    }

    fn public(&self) -> R<PublicKey> {
        Ok(PublicKey::from_bytes(self.key.verifying_key().to_bytes())?)
    }
}

impl CertificateSigner for CountingSigner {
    fn key_id(&self) -> SigningKeyId {
        PublicKey::from_bytes(self.key.verifying_key().to_bytes())
            .unwrap_or_else(|_| unreachable!("fixture key valid"))
            .key_id()
    }

    fn sign(&self, m: &[u8]) -> Result<DetachedSignature, SigningFailure> {
        self.count.set(self.count.get() + 1);

        match self.mode {
            1 => Err(SigningFailure::SigningFailed),
            2 => Ok(DetachedSignature::from_bytes([0; 64])),
            _ => Ok(DetachedSignature::from_bytes(self.key.sign(m).to_bytes())),
        }
    }
}

fn issued(f: &Fixture, s: &CountingSigner) -> R<Value> {
    Ok(serde_json::from_slice(
        &f.draft(Some(f.evaluation()?), s.public()?)?
            .issue(s)?
            .envelope()
            .to_json()?,
    )?)
}

fn verified(v: &Value, key: &PublicKey) -> bool {
    CertificateEnvelope::read(serde_json::to_vec(v).unwrap_or_default().as_slice())
        .and_then(|c| c.verify(key))
        .is_ok()
}

fn refresh_digest(v: &mut Value) -> R {
    v["certificate_sha256"] = json!(digest_bytes(&canonical_bytes(&v["payload"])?).as_str());

    Ok(())
}

#[test]
fn eligible_issues_only_after_signing_and_offline_verification() -> R {
    let f = fixture()?;
    let s = CountingSigner::new(7);
    let draft = f.draft(Some(f.evaluation()?), s.public()?)?;

    assert_eq!(s.count.get(), 0);

    let issued = draft.issue(&s)?;

    assert_eq!(s.count.get(), 1);

    let parsed = CertificateEnvelope::read(issued.envelope().to_json()?.as_slice())?;

    assert_eq!(parsed.verify(&s.public()?)?.report()["status"], "CERTIFIED");
    assert_eq!(issued.verification().report()["scope"], "EXACT_SOURCE");

    Ok(())
}

#[test]
fn missing_ineligible_inconclusive_unknown_evaluations_never_invoke_signer() -> R {
    let f = fixture()?;
    let s = CountingSigner::new(7);

    assert!(matches!(
        f.draft(None, s.public()?),
        Err(CertificateError::MissingEvaluation)
    ));

    for disposition in [
        CertificationEligibility::NotEligible,
        CertificationEligibility::Inconclusive,
    ] {
        let mut e = f.evaluation()?;
        e.eligibility = disposition;
        let attempt = f.draft(Some(e), s.public()?).and_then(|d| d.issue(&s));

        assert!(matches!(
            attempt,
            Err(CertificateError::EvaluationNotEligible)
        ));
    }

    let mut e = f.evaluation()?;
    e.schema = 2;

    assert!(matches!(
        f.draft(Some(e), s.public()?),
        Err(CertificateError::UnsupportedEvaluationSchema)
    ));
    assert_eq!(s.count.get(), 0);

    Ok(())
}

#[test]
fn bottle_not_proven_cannot_invoke_signer() -> R {
    let mut f = fixture()?;
    let s = CountingSigner::new(7);
    let config = ProjectConfiguration::read(
        include_bytes!("../../../docs/runner/BOTTLE_REQUEST.toml").as_slice(),
    )?;
    f.plan = AuthorityConfiguration::development(vec![(
        "python".into(),
        format!("approved@sha256:{}", "a".repeat(64)),
    )])?
    .resolve(config.execution_request())?;
    f.executions.clear();
    f.observations.clear();
    let e = f.evaluation()?;

    assert_eq!(e.eligibility, CertificationEligibility::NotEligible);
    assert_eq!(
        e.properties
            .iter()
            .filter(|p| [
                PropertyId::TestSuiteCompletes,
                PropertyId::TypecheckCompletes,
                PropertyId::BuildCompletes
            ]
            .contains(&p.property)
                && p.verdict == archcert_domain::PropertyVerdict::NotProven)
            .count(),
        3
    );
    assert!(
        f.draft(Some(e), s.public()?)
            .and_then(|d| d.issue(&s))
            .is_err()
    );
    assert_eq!(s.count.get(), 0);

    Ok(())
}

#[test]
fn original_identity_and_recomputed_findings_gate_reject_post_evaluation_mutation() -> R {
    let f = fixture()?;
    let s = CountingSigner::new(7);

    for attack in 0..9 {
        let mut e = f.evaluation()?;

        match attack {
            0 => e.source.snapshot_sha256 = digest_bytes(b"substituted source"),
            1 => e.source.commit = GitObjectId::parse("c".repeat(40))?,
            2 => e.source.tree = GitObjectId::parse("c".repeat(40))?,
            3 => e.plan_sha256 = digest_bytes(b"substituted plan"),
            4 => e.policy.sha256 = digest_bytes(b"substituted policy"),
            5 => e.policy.version = "0.0.0".into(),
            6 => e.properties[0]
                .actual_evidence
                .push(EvidenceRef::SourceSnapshot {
                    sha256: digest_bytes(b"foreign ref"),
                }),
            7 => e.blocking_findings.push(digest_bytes(b"invalid finding")),
            _ => e.properties.clear(),
        }

        assert!(
            f.draft(Some(e), s.public()?)
                .and_then(|d| d.issue(&s))
                .is_err(),
            "attack {attack}"
        );
    }

    assert_eq!(s.count.get(), 0);

    Ok(())
}

#[test]
fn signing_failure_invalid_signature_and_wrong_signer_never_produce_certified() -> R {
    let f = fixture()?;
    let mut s = CountingSigner::new(7);
    s.mode = 1;

    assert!(matches!(
        f.draft(Some(f.evaluation()?), s.public()?)?.issue(&s),
        Err(CertificateError::Signing(SigningFailure::SigningFailed))
    ));

    s.mode = 2;

    assert!(matches!(
        f.draft(Some(f.evaluation()?), s.public()?)?.issue(&s),
        Err(CertificateError::VerificationFailed)
    ));

    let other = CountingSigner::new(8);

    assert!(matches!(
        f.draft(Some(f.evaluation()?), s.public()?)?.issue(&other),
        Err(CertificateError::SigningKeyMismatch)
    ));
    assert_eq!(other.count.get(), 0);

    Ok(())
}

#[test]
fn every_signed_field_tamper_rejects_even_after_recomputing_digest() -> R {
    let f = fixture()?;
    let s = CountingSigner::new(7);
    let original = issued(&f, &s)?;
    let key = s.public()?;
    let paths = [
        "source.snapshot_sha256",
        "source.commit",
        "source.tree",
        "policy.sha256",
        "policy.version",
        "policy.id",
        "plan_sha256",
        "evaluation_sha256",
        "evidence_manifest_sha256",
        "findings",
        "signing_key_id",
        "schema",
        "kind",
        "scope",
        "project",
        "repository",
        "authority",
        "archcert_version",
        "evaluator_version",
        "certifier",
        "runner",
        "isolation_level",
        "issued_at",
        "expiration",
        "revocation",
        "signature_algorithm",
    ];

    for path in paths {
        let mut changed = original.clone();
        let mut field = &mut changed["payload"];

        for component in path.split('.') {
            field = &mut field[component];
        }

        *field = match field {
            Value::Number(n) => json!(n.as_u64().ok_or("number")? + 1),
            Value::Array(_) => json!(["c".repeat(64)]),
            Value::String(s) => {
                if s.bytes().all(|b| b.is_ascii_hexdigit()) && [40, 64].contains(&s.len()) {
                    json!("c".repeat(s.len()))
                } else {
                    json!("substituted")
                }
            }
            _ => return Err("unexpected field type".into()),
        };

        assert!(!verified(&changed, &key), "accepted tampering: {path}");

        refresh_digest(&mut changed)?;

        assert!(
            !verified(&changed, &key),
            "accepted tampering with rehashed digest: {path}"
        );
    }

    Ok(())
}

#[test]
fn wrong_key_signature_digest_and_cross_certificate_substitutions_reject() -> R {
    let f = fixture()?;
    let a = CountingSigner::new(7);
    let b = CountingSigner::new(8);
    let va = issued(&f, &a)?;
    let vb = issued(&f, &b)?;

    assert!(!verified(&va, &b.public()?));

    for field in ["signature", "public_key", "certificate_sha256"] {
        let mut changed = va.clone();
        changed[field] = vb[field].clone();

        assert!(!verified(&changed, &a.public()?), "{field}");
    }

    let mut bad = va.clone();
    bad["signature"] = json!("00".repeat(64));

    assert!(!verified(&bad, &a.public()?));

    let mut bad = vb.clone();
    bad["signature"] = va["signature"].clone();

    assert!(!verified(&bad, &b.public()?));

    // Two meaningful source/evidence/evaluation instances under the SAME key.
    let mut other = fixture()?;
    other.source = SourceSnapshot::seal(
        f.source.project(),
        f.source.repository().clone(),
        GitObjectId::parse("d".repeat(40))?,
        GitObjectId::parse("e".repeat(40))?,
        vec![],
        1,
        1,
    )?;

    for o in &mut other.observations {
        o.source = other.source.identity().clone();
    }

    for record in &mut other.records {
        record.source = other.source.identity().clone();
    }

    let second = issued(&other, &a)?;

    for path in [
        "source",
        "evaluation_sha256",
        "evidence_manifest_sha256",
        "signing_key_id",
    ] {
        let mut changed = second.clone();
        changed["payload"][path] = va["payload"][path].clone();

        if changed != second {
            refresh_digest(&mut changed)?;

            assert!(!verified(&changed, &a.public()?));
        }
    }

    Ok(())
}

#[test]
fn strict_bounded_parser_rejects_unknown_duplicate_schema_algorithm_and_encodings() -> R {
    let f = fixture()?;
    let s = CountingSigner::new(7);
    let value = issued(&f, &s)?;

    for path in ["", "payload", "payload.source", "payload.policy"] {
        let mut changed = value.clone();
        let mut node = &mut changed;

        for key in path.split('.').filter(|s| !s.is_empty()) {
            node = &mut node[key];
        }

        node["unknown"] = json!(true);

        assert!(CertificateEnvelope::read(serde_json::to_vec(&changed)?.as_slice()).is_err());
    }

    let compact = serde_json::to_string(&value)?;

    for (key, literal) in [
        ("schema", "1"),
        ("commit", &format!("\"{}\"", "a".repeat(40))),
        (
            "signature",
            &format!("\"{}\"", value["signature"].as_str().ok_or("signature")?),
        ),
    ] {
        let duplicate = compact.replacen(
            &format!("\"{key}\":"),
            &format!("\"{key}\":{literal},\"{key}\":"),
            1,
        );

        assert!(
            CertificateEnvelope::read(duplicate.as_bytes()).is_err(),
            "duplicate {key}"
        );
    }

    for (path, replacement) in [
        ("schema", json!(2)),
        ("signature_algorithm", json!("Ed25519ph")),
        ("certifier", json!("x".repeat(129))),
        ("issued_at", json!(0)),
        ("issued_at", json!(9_007_199_254_740_992u64)),
        ("repository", json!("main\n")),
        ("findings", json!(["a".repeat(64), "a".repeat(64)])),
    ] {
        let mut changed = value.clone();
        changed["payload"][path] = replacement;

        assert!(
            CertificateEnvelope::read(serde_json::to_vec(&changed)?.as_slice()).is_err(),
            "{path}"
        );
    }

    for (field, encoding) in [
        ("signature", "0".repeat(127)),
        ("signature", "GG".repeat(64)),
        ("public_key", "00".repeat(31)),
        ("public_key", "00".repeat(32)),
        ("certificate_sha256", "A".repeat(64)),
    ] {
        let mut changed = value.clone();
        changed[field] = json!(encoding);

        assert!(
            CertificateEnvelope::read(serde_json::to_vec(&changed)?.as_slice()).is_err(),
            "{field}"
        );
    }

    assert!(CertificateEnvelope::read(vec![b' '; MAX_CERTIFICATE_BYTES + 1].as_slice()).is_err());
    assert!(
        CertificateEnvelope::read(format!("{}{}", "[".repeat(200), "]".repeat(200)).as_bytes())
            .is_err()
    );

    Ok(())
}

#[test]
fn draft_owns_all_signing_input_after_gate() -> R {
    let mut f = fixture()?;
    let s = CountingSigner::new(7);
    let draft = f.draft(Some(f.evaluation()?), s.public()?)?;
    let bytes = draft.certificate().bytes().to_vec();
    let digest = draft.certificate().digest().clone();
    f.observations.clear();
    f.executions.clear();
    f.bundle = PolicyBundle::read(
        DEVELOPMENT_POLICY
            .replace("version = \"1.0.0\"", "version = \"9.0.0\"")
            .as_bytes(),
    )?;

    assert_eq!(draft.certificate().bytes(), bytes);
    assert_eq!(draft.certificate().digest(), &digest);
    assert_eq!(
        draft.issue(&s)?.verification().report()["status"],
        "CERTIFIED"
    );

    Ok(())
}

#[test]
fn observations_permutations_duplicates_and_audit_time_leave_identity_deterministic() -> R {
    let mut f = fixture()?;
    let s = CountingSigner::new(7);
    let baseline = f.draft(Some(f.evaluation()?), s.public()?)?;
    let expected = baseline.certificate().bytes().to_vec();
    let manifest = baseline.manifest().canonical_bytes().to_vec();

    for rotation in 0..f.observations.len() {
        f.observations.rotate_left(rotation);
        let mut e = f.evaluation()?;
        e.evaluated_at = 10000;
        let other = f.draft(Some(e), s.public()?)?;

        assert_eq!(other.certificate().bytes(), expected);
        assert_eq!(other.manifest().canonical_bytes(), manifest);
    }

    f.observations.push(f.observations[0].clone());
    let other = f.draft(Some(f.evaluation()?), s.public()?)?;

    assert_eq!(other.certificate().bytes(), expected);
    assert_eq!(
        other.certificate().digest(),
        baseline.certificate().digest()
    );

    // JSON presentation and insertion order never enter the signing preimage.
    let issued = baseline.issue(&s)?;
    let v: Value = serde_json::from_slice(&issued.envelope().to_json()?)?;

    assert!(verified(&v, &s.public()?));

    let compact = serde_json::to_vec(&v)?;

    assert!(
        CertificateEnvelope::read(compact.as_slice())?
            .verify(&s.public()?)
            .is_ok()
    );

    Ok(())
}

#[test]
fn manifest_rejects_unresolvable_observation_id_digest_or_finding_reference() -> R {
    let f = fixture()?;

    for attack in 0..3 {
        let mut e = f.evaluation()?;

        match attack {
            0 => e.properties[0]
                .actual_evidence
                .push(EvidenceRef::Observation {
                    id: f.observations[0].id.clone(),
                    sha256: digest_bytes(b"missing"),
                }),
            1 => {
                let mut id = f.observations[0].id.clone();
                id.step = "wrong-step".into();
                e.properties[0]
                    .actual_evidence
                    .push(EvidenceRef::Observation {
                        id,
                        sha256: digest_bytes(&canonical_bytes(&f.observations[0])?),
                    });
            }
            _ => e.findings.push(Finding {
                id: digest_bytes(b"finding"),
                property: PropertyId::BuildCompletes,
                severity: Severity::P2,
                status: archcert_domain::PropertyVerdict::NotProven,
                blocking: false,
                reason: ReasonCode::RequiredEvidenceMissing,
                observations: vec![EvidenceRef::SourceSnapshot {
                    sha256: digest_bytes(b"other source"),
                }],
            }),
        }

        assert!(EvidenceManifest::build(&e, &f.observations).is_err());
    }

    Ok(())
}

#[test]
fn issuance_timestamp_changes_instance_identity_but_not_evaluation_or_evidence() -> R {
    let f = fixture()?;
    let s = CountingSigner::new(7);
    let e = f.evaluation()?;
    let a = f.draft(Some(e.clone()), s.public()?)?;

    let b = CertificateDraft::prepare(
        f.context(),
        Some(e.clone()),
        IssuanceMetadata {
            issued_at: 1_700_000_001,
            certifier: "fixture-authority".into(),
        },
        s.public()?,
    )?;

    assert_ne!(a.certificate().digest(), b.certificate().digest());
    assert_eq!(a.manifest().digest(), b.manifest().digest());

    let mut other = e.clone();
    other.evaluated_at += 100;

    assert_eq!(evaluation_digest(&e)?, evaluation_digest(&other)?);

    Ok(())
}

#[test]
fn target_config_cannot_select_signer_key_algorithm_or_authority() -> R {
    for field in [
        "key='x'",
        "key_path='x'",
        "signer='x'",
        "algorithm='Ed25519'",
        "certificate_authority='x'",
        "kms='x'",
        "signing_key_id='x'",
        "development_key='x'",
    ] {
        for text in [
            format!("schema=1\n{field}\n[project]\nname='hostile'"),
            format!("schema=1\n[project]\nname='hostile'\n{field}"),
            format!("schema=1\n[project]\nname='hostile'\n[execution]\nprofile='python'\n{field}"),
        ] {
            assert!(
                ProjectConfiguration::read(text.as_bytes()).is_err(),
                "{field}"
            );
        }
    }

    Ok(())
}

#[test]
fn fixed_openssl_python_vector_matches_bytes_digest_key_identity_and_signature() -> R {
    let value: Value = serde_json::from_slice(include_bytes!("fixtures/openssl-vector.json"))?;
    let canonical = canonical_bytes(&value["payload"])?;

    assert_eq!(
        canonical,
        include_bytes!("fixtures/openssl-vector.canonical.json")
    );
    assert_eq!(
        digest_bytes(&canonical).as_str(),
        include_str!("fixtures/openssl-vector.sha256").trim()
    );

    let key = PublicKey::from_hex(value["public_key"].as_str().ok_or("public key")?)?;
    let parsed =
        CertificateEnvelope::read(include_bytes!("fixtures/openssl-vector.json").as_slice())?;

    assert_eq!(parsed.verify(&key)?.report()["status"], "CERTIFIED");

    // Reject all 64 individual signature-byte flips against this independent vector.
    let original = value["signature"].as_str().ok_or("signature")?;

    for byte in 0..64 {
        let mut mutated = original.as_bytes().to_vec();
        mutated[byte * 2] = if mutated[byte * 2] == b'0' {
            b'1'
        } else {
            b'0'
        };
        let mut altered = value.clone();
        altered["signature"] = json!(String::from_utf8(mutated)?);

        assert!(!verified(&altered, &key));
    }

    Ok(())
}

#[test]
fn advisory_findings_are_signed_and_cannot_be_transplanted_between_certificates() -> R {
    fn advisory() -> R<Fixture> {
        let mut f = fixture()?;
        let mut text = String::new();

        for block in DEVELOPMENT_POLICY.split("[[properties]]") {
            let block = if block.contains("id = \"TEST_SUITE_COMPLETES\"") {
                block
                    .replace("mandatory = true", "mandatory = false")
                    .replace("severity = \"P1\"", "severity = \"P2\"")
            } else {
                block.into()
            };

            if !text.is_empty() {
                text.push_str("[[properties]]");
            }

            text.push_str(&block);
        }

        f.bundle = PolicyBundle::read(text.as_bytes())?;

        for o in &mut f.observations {
            if o.id.step == "test" && o.id.kind == ObservationKind::ExecutionFinished {
                o.fact = ObservationFact::ExecutionFinished {
                    outcome: ExecutionOutcome::Completed,
                    exit_code: Some(1),
                    category: EvidenceCategory::Test,
                };
            }
        }

        for record in &mut f.records {
            if record.command == f.plan.steps()[1].command().clone()
                && record.execution == f.executions[1].execution
            {
                record.exit_code = Some(1);
            }
        }

        Ok(f)
    }

    let f = advisory()?;
    let s = CountingSigner::new(7);
    let first = issued(&f, &s)?;

    assert_eq!(
        first["payload"]["findings"]
            .as_array()
            .ok_or("findings")?
            .len(),
        1
    );

    let mut other = advisory()?;
    other.source = SourceSnapshot::seal(
        f.source.project(),
        f.source.repository().clone(),
        GitObjectId::parse("d".repeat(40))?,
        GitObjectId::parse("e".repeat(40))?,
        vec![],
        1,
        1,
    )?;

    for o in &mut other.observations {
        o.source = other.source.identity().clone();
    }

    for record in &mut other.records {
        record.source = other.source.identity().clone();
    }

    let second = issued(&other, &s)?;

    for field in ["findings", "evidence_manifest_sha256", "evaluation_sha256"] {
        assert_ne!(first["payload"][field], second["payload"][field]);

        let mut changed = second.clone();
        changed["payload"][field] = first["payload"][field].clone();
        refresh_digest(&mut changed)?;

        assert!(!verified(&changed, &s.public()?));
    }

    // A validly referenced finding whose meaning/ID was edited fails re-evaluation.
    let mut evaluation = f.evaluation()?;
    evaluation.findings[0].id = digest_bytes(b"transplanted finding");

    assert!(matches!(
        f.draft(Some(evaluation), s.public()?),
        Err(CertificateError::InternalIntegrityFailure)
    ));

    Ok(())
}

#[test]
fn restricted_canonical_strings_sorting_and_numeric_bounds_are_explicit() -> R {
    let value = json!({
        "z": "é \"\\\n\t\u{0001}",
        "a": {
            "b": true,
            "a": null
        }
    });

    assert_eq!(
        canonical_bytes(&value)?,
        "{\"a\":{\"a\":null,\"b\":true},\"z\":\"é \\\"\\\\\\n\\t\\u0001\"}".as_bytes()
    );
    assert!(canonical_bytes(&json!({"é":1})).is_err());
    assert!(canonical_bytes(&json!(1.5)).is_err());
    assert!(canonical_bytes(&json!(9_007_199_254_740_992u64)).is_err());

    Ok(())
}

#[test]
fn reversed_json_object_order_and_whitespace_reconstruct_exact_signing_bytes() -> R {
    fn reversed(v: &Value) -> R<String> {
        Ok(match v {
            Value::Object(m) => format!(
                "{{ {} }}",
                m.iter()
                    .rev()
                    .map(|(k, v)| Ok(format!("{} : {}", serde_json::to_string(k)?, reversed(v)?)))
                    .collect::<R<Vec<_>>>()?
                    .join(", ")
            ),
            Value::Array(a) => format!(
                "[ {} ]",
                a.iter().map(reversed).collect::<R<Vec<_>>>()?.join(", ")
            ),
            _ => serde_json::to_string(v)?,
        })
    }

    let v: Value = serde_json::from_slice(include_bytes!("fixtures/openssl-vector.json"))?;
    let key = PublicKey::from_hex(v["public_key"].as_str().ok_or("key")?)?;
    let presentation = reversed(&v)?;

    assert_ne!(presentation, serde_json::to_string(&v)?);

    let verified = CertificateEnvelope::read(presentation.as_bytes())?.verify(&key)?;

    assert_eq!(
        verified.report()["certificate_sha256"],
        v["certificate_sha256"]
    );

    Ok(())
}

#[test]
fn signing_does_not_claim_an_unobserved_isolation_level_under_minimal_policy() -> R {
    let mut f = fixture()?;
    let s = CountingSigner::new(7);
    let header = DEVELOPMENT_POLICY
        .split("[[properties]]")
        .next()
        .ok_or("header")?;
    let source = DEVELOPMENT_POLICY
        .split("[[properties]]")
        .find(|p| p.contains("id = \"SOURCE_COMPLETE\""))
        .ok_or("source property")?;
    f.bundle = PolicyBundle::read(format!("{header}[[properties]]{source}").as_bytes())?;
    f.observations
        .retain(|o| o.id.kind != ObservationKind::EnvironmentEstablished);
    let e = f.evaluation()?;

    assert_eq!(
        e.eligibility,
        CertificationEligibility::EligibleForCertification
    );
    assert!(matches!(
        f.draft(Some(e), s.public()?),
        Err(CertificateError::EvidenceBindingMismatch)
    ));
    assert_eq!(s.count.get(), 0);

    Ok(())
}

#[test]
fn detailed_log_mutation_changes_bundle_manifest_and_certificate_identity() -> R {
    let mut f = fixture()?;
    let s = CountingSigner::new(7);
    let evaluation_before = evaluation_digest(&f.evaluation()?)?;
    let original = f.draft(Some(f.evaluation()?), s.public()?)?;
    f.records[0].stdout.excerpt = b"hostile target output is evidence, never authority".to_vec();
    f.records[0].stdout.observed_bytes = f.records[0].stdout.excerpt.len() as u64;
    f.records[0].stdout.sha256 = digest_bytes(&f.records[0].stdout.excerpt);
    let changed = f.draft(Some(f.evaluation()?), s.public()?)?;

    assert_ne!(
        original.evidence_bundle().digest(),
        changed.evidence_bundle().digest()
    );
    assert_ne!(original.manifest().digest(), changed.manifest().digest());
    assert_ne!(
        original.certificate().digest(),
        changed.certificate().digest()
    );
    assert_eq!(evaluation_before, evaluation_digest(&f.evaluation()?)?);

    let baseline = changed.certificate().bytes().to_vec();
    f.records.reverse();
    let permuted = f.draft(Some(f.evaluation()?), s.public()?)?;

    assert_eq!(permuted.certificate().bytes(), baseline);

    Ok(())
}

#[test]
fn detailed_records_must_reproduce_consumed_observations_before_signing() -> R {
    let s = CountingSigner::new(7);

    for attack in 0..4 {
        let mut f = fixture()?;
        let e = f.evaluation()?;

        match attack {
            0 => f.records.clear(),
            1 => f.records[0].exit_code = Some(1),
            2 => f.records[0].source.snapshot_sha256 = digest_bytes(b"wrong record source"),
            _ => f.records[0].command = f.records[1].command.clone(),
        }

        if attack == 3 {
            f.records[0].profile = "foreign-profile".into();
        }

        assert!(
            f.draft(Some(e), s.public()?)
                .and_then(|d| d.issue(&s))
                .is_err()
        );
    }

    assert_eq!(s.count.get(), 0);

    Ok(())
}

#[test]
fn issued_certificate_resolves_the_exact_manifest_and_detailed_bundle() -> R {
    // A clean checkout must not depend on untracked local milestone output.
    // Fixed independent signature bytes are covered by openssl-vector.* separately.
    let f = fixture()?;
    let signer = CountingSigner::new(7);
    let draft = f.draft(Some(f.evaluation()?), signer.public()?)?;
    let manifest_bytes = draft.manifest().canonical_bytes().to_vec();
    let bundle_bytes = draft.evidence_bundle().canonical_bytes().to_vec();
    let issued = draft.issue(&signer)?;
    let certificate: Value = serde_json::from_slice(&issued.envelope().to_json()?)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    let bundle: Value = serde_json::from_slice(&bundle_bytes)?;

    assert_eq!(canonical_bytes(&manifest)?, manifest_bytes);
    assert_eq!(canonical_bytes(&bundle)?, bundle_bytes);
    assert_eq!(
        certificate["payload"]["evidence_manifest_sha256"],
        digest_bytes(&manifest_bytes).as_str()
    );
    assert_eq!(
        manifest["evidence_bundle_sha256"],
        digest_bytes(&bundle_bytes).as_str()
    );

    for identity in ["source", "policy", "plan_sha256", "evaluation_sha256"] {
        assert_eq!(certificate["payload"][identity], manifest[identity]);
        assert_eq!(manifest[identity], bundle[identity]);
    }

    let mut observations = std::collections::BTreeMap::new();

    for o in bundle["observations"].as_array().ok_or("observations")? {
        observations.insert(digest_bytes(&canonical_bytes(o)?).as_str().to_owned(), o);
    }

    for reference in manifest["observations"].as_array().ok_or("references")? {
        let payload = observations
            .get(reference["sha256"].as_str().ok_or("digest")?)
            .ok_or("unresolved payload")?;

        assert_eq!(payload["id"], reference["id"]);
    }

    assert_eq!(
        bundle["execution_records"]
            .as_array()
            .ok_or("records")?
            .len(),
        3
    );
    assert!(verified(&certificate, &signer.public()?));

    Ok(())
}

#[test]
fn forged_eligibility_cannot_issue_for_incomplete_external_source() -> R {
    let mut f = fixture()?;
    let e = f.evaluation()?;
    f.source = SourceSnapshot::seal(
        f.source.project(),
        f.source.repository().clone(),
        f.source.identity().commit.clone(),
        f.source.identity().tree.clone(),
        vec![SourceFile::new(
            SourcePath::from_bytes(b"module")?,
            SourceMode::Submodule,
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
        )],
        1,
        1,
    )?;
    let key = PublicKey::from_bytes(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes())?;

    assert!(matches!(
        f.draft(Some(e), key),
        Err(CertificateError::IncompleteSource)
    ));

    Ok(())
}

#[test]
fn ironcrest_manifest_extension_preserves_schema_one_and_binds_exact_roles() -> R {
    use archcert_application::{ironcrest::*, jobs::ArtifactReference};
    use archcert_domain::{
        ingress::{GitActorId, SourceSubmissionId},
        jobs::{JobId, PolicyPin},
    };

    let f = fixture()?;
    let evaluation = f.evaluation()?;
    let legacy = EvidenceManifest::build(&evaluation, &f.observations)?;
    let retained = legacy.canonical_bytes().to_vec();
    let roles = [
        IroncrestEvidenceRole::AuthorityProfile,
        IroncrestEvidenceRole::Knowledge,
        IroncrestEvidenceRole::Impact,
        IroncrestEvidenceRole::Request,
        IroncrestEvidenceRole::Review,
        IroncrestEvidenceRole::Gate,
        IroncrestEvidenceRole::ChallengePlan,
        IroncrestEvidenceRole::ChallengeResult,
    ];
    let references: Vec<_> = roles
        .into_iter()
        .map(|role| {
            (
                role,
                ArtifactReference {
                    sha256: digest_bytes(role.as_str().as_bytes()),
                    size: role.as_str().len() as u64,
                    schema: if matches!(
                        role,
                        IroncrestEvidenceRole::Gate | IroncrestEvidenceRole::ChallengePlan
                    ) {
                        2
                    } else {
                        1
                    },
                    producer: "archcert-ironcrest-v1/0.1.0".into(),
                },
            )
        })
        .collect();
    // Synthetic manifest conformance identities, not accepted execution/issuance.
    let binding = IroncrestEvidenceBinding {
        session: JobId::new(),
        plan_sha256: evaluation.plan_sha256.clone(),
        roles: references,
        pin: IroncrestSessionPin {
            project: f.source.project(),
            repository: f.source.repository().clone(),
            actor: GitActorId::parse(JobId::new().to_string())?,
            submission: SourceSubmissionId::new(),
            source: f.source.identity().clone(),
            baseline: None,
            policy: PolicyPin {
                id: evaluation.policy.id.clone(),
                version: evaluation.policy.version.clone(),
                sha256: evaluation.policy.sha256.clone(),
            },
            base_plan_sha256: digest_bytes(b"base"),
            authority_profile_sha256: digest_bytes(b"AUTHORITY_PROFILE"),
            extractor_registry_sha256: digest_bytes(b"extractors"),
            challenge_registry_sha256: digest_bytes(b"registry"),
            authority_bundles: vec![],
        },
    };
    let extended = legacy.with_ironcrest(&binding)?;
    let parsed: Value = serde_json::from_slice(extended.canonical_bytes())?;

    assert_eq!(parsed["schema"], 2);
    assert_eq!(
        parsed["deterministic_manifest_sha256"],
        legacy.digest().as_str()
    );
    assert_eq!(
        canonical_bytes(&parsed["deterministic_manifest"])?,
        retained
    );
    assert_eq!(legacy.canonical_bytes(), retained);
    assert_ne!(legacy.digest(), extended.digest());

    for role in 0..8 {
        let mut changed = binding.clone();
        changed.roles[role].1.sha256 = digest_bytes(b"substitution");

        if role == 0 {
            assert!(legacy.with_ironcrest(&changed).is_err());
        } else {
            assert_ne!(legacy.with_ironcrest(&changed)?.digest(), extended.digest());
        }
    }

    for field in 0..5 {
        let mut changed = binding.clone();

        match field {
            0 => changed.roles.pop().map(|_| ()).ok_or("role")?,
            1 => changed.roles.swap(1, 2),
            2 => changed.pin.source.snapshot_sha256 = digest_bytes(b"other-source"),
            3 => changed.pin.policy.sha256 = digest_bytes(b"other-policy"),
            _ => changed.plan_sha256 = digest_bytes(b"other-plan"),
        }

        assert!(legacy.with_ironcrest(&changed).is_err());
    }

    assert!(extended.with_ironcrest(&binding).is_err());

    Ok(())
}

#[test]
fn ironcrest_policy_cannot_use_legacy_preparation_without_review_evidence() -> R {
    let mut f = fixture()?;
    f.bundle = ironcrest_controlled_bundle()?;
    let mut forged = f.evaluation()?;

    assert_ne!(
        forged.eligibility,
        CertificationEligibility::EligibleForCertification
    );

    forged.eligibility = CertificationEligibility::EligibleForCertification;
    let signer = CountingSigner::new(47);

    assert!(matches!(
        f.draft(Some(forged), signer.public()?),
        Err(CertificateError::EvidenceBindingMismatch)
    ));
    assert_eq!(signer.count.get(), 0);

    Ok(())
}
