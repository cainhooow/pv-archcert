//! Direct forged HTTP requests exercise server-side authorization independently of UI.

#[path = "http/readiness.rs"]
mod readiness;

#[path = "http/build.rs"]
mod build;

#[path = "http/platform.rs"]
mod platform;

use archcert_application::glassmere::commands::*;
use archcert_application::{glassmere::*, jobs::JobStoreError};
use archcert_domain::{ProjectId, source::digest_bytes};
use archcert_domain::{
    ingress::SourceSubmissionId,
    jobs::{ControlCommandId, IdempotencyKey},
};
use archcert_glassmere::{auth::*, router, router_with_commands};
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, Response, StatusCode, header},
};
use http_body_util::BodyExt;
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tower::ServiceExt;

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ORIGIN: &str = "http://127.0.0.1:8090";
const HOSTILE: &str = "<script>alert(1)</script><img src=x onerror=alert(1)>";
const DEEP_JOB: &str = "10000000-0000-4000-8000-000000000099";
const WORKFLOW_SOURCE: &str = "10000000-0000-4000-8000-000000000001";
const WORKFLOW_SESSION: &str = "10000000-0000-4000-8000-000000000002";
const WORKFLOW_RUNNING: &str = "10000000-0000-4000-8000-000000000003";
const WORKFLOW_ATTEMPT: &str = "10000000-0000-4000-8000-000000000004";
const WORKFLOW_RECEIPT: &str = "10000000-0000-4000-8000-000000000005";
const WORKFLOW_COMPLETED: &str = "10000000-0000-4000-8000-000000000006";
const WORKFLOW_INVOCATION: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// Renderer/authorization metadata only. The actual M6 verifier is qualified separately.
fn workflow_readiness(
    project: ProjectId,
    allowed: bool,
) -> Result<ReleaseReadiness, JobStoreError> {
    use archcert_domain::{
        GitObjectId,
        source::{RepositoryId, SourceSnapshot},
    };

    let source = SourceSnapshot::seal(
        project,
        RepositoryId::parse("workflow/fixture").map_err(|_| JobStoreError::Invalid)?,
        GitObjectId::parse("a".repeat(40)).map_err(|_| JobStoreError::Invalid)?,
        GitObjectId::parse("b".repeat(40)).map_err(|_| JobStoreError::Invalid)?,
        vec![],
        1,
        1_700_000_000,
    )
    .map_err(|_| JobStoreError::Invalid)?;
    let checks = ReadinessChecks {
        subject: ReleaseSubject {
            project,
            repository: "workflow/fixture".into(),
            source: source.identity().clone(),
            certificate: Some(digest_bytes(b"metadata certificate").as_str().into()),
            invocation: WORKFLOW_INVOCATION.into(),
            artifact: Some(digest_bytes(b"metadata artifact").as_str().into()),
            permit: Some(digest_bytes(b"metadata permit").as_str().into()),
        },
        certificate: if allowed {
            Ok(())
        } else {
            Err(BlockerCode::NoSourceCertificate)
        },
        reproducibility: Ok(()),
        artifact: Ok(()),
        permit: Ok(()),
        policy: Ok(()),
        review: Ok(()),
        environment: Ok(()),
        freshness: Ok(()),
    };
    let mut result = checks.evaluate(
        digest_bytes(b"metadata revision").as_str().into(),
        1_700_000_000,
    );
    result.provenance = "METADATA RENDER FIXTURE / NO EXECUTION OR SIGNATURE QUALIFICATION".into();

    Ok(result)
}

struct QueryFixture {
    project: ProjectId,
    workflow: bool,
    revoke_on_entity: Option<PathBuf>,
}

impl QueryFixture {
    fn revoke_during_lookup(&self) -> Result<(), JobStoreError> {
        if let Some(path) = &self.revoke_on_entity {
            let mut configuration: PanelConfiguration = serde_json::from_slice(
                &std::fs::read(path).map_err(|_| JobStoreError::Unavailable)?,
            )
            .map_err(|_| JobStoreError::Unavailable)?;
            configuration.principals[0].grant_generation = Some(
                digest_bytes(b"new grant during passive lookup")
                    .as_str()
                    .into(),
            );
            std::fs::write(
                path,
                serde_json::to_vec(&configuration).map_err(|_| JobStoreError::Unavailable)?,
            )
            .map_err(|_| JobStoreError::Unavailable)?;
        }

        Ok(())
    }
}

#[async_trait]
impl GlassmereQuery for QueryFixture {
    async fn search(
        &self,
        project: ProjectId,
        query: &search::SearchQuery,
    ) -> Result<search::SearchPage, JobStoreError> {
        query.after_key(project)?;
        if project != self.project {
            return Err(JobStoreError::Precondition);
        }
        Ok(search::SearchPage {
            schema: 1,
            project,
            query: query.clone(),
            hits: vec![search::SearchHit {
                key: format!("JOB/{DEEP_JOB}"),
                entity: DEEP_JOB.into(),
                kind: "JOB".into(),
                state: HOSTILE.into(),
                digest: None,
            }],
            next: None,
        })
    }

    async fn projects(
        &self,
        allowed: &[ProjectId],
        _: Option<ProjectId>,
    ) -> Result<Vec<ProjectObservation>, JobStoreError> {
        Ok(allowed
            .iter()
            .filter(|id| **id == self.project)
            .map(|id| ProjectObservation {
                project: *id,
                repository: HOSTILE.into(),
            })
            .collect())
    }

    async fn snapshot(
        &self,
        project: ProjectId,
        offset: u32,
    ) -> Result<ProjectSnapshot, JobStoreError> {
        if project != self.project {
            return Err(JobStoreError::Precondition);
        }
        if offset > 100_000 {
            return Err(JobStoreError::Invalid);
        }
        let mut snapshot = ProjectSnapshot {
            schema: 1,
            project: ProjectObservation {
                project,
                repository: HOSTILE.into(),
            },
            revision: "fixture".into(),
            database_snapshot: "1:2:".into(),
            evaluated_at: 1700000000,
            offset,
            page_size: 50,
            has_more: false,
            sources: vec![],
            jobs: vec![],
            sessions: vec![],
            releases: vec![],
            evidence: vec![],
            timeline: vec![],
            limitations: vec![HOSTILE.into()],
        };
        if self.workflow {
            let repository = ObservationField {
                label: "Repository".into(),
                value: "workflow/fixture".into(),
                provenance: "Scoped fixture".into(),
            };
            snapshot.sources.push(EntityObservation {
                id: WORKFLOW_SOURCE.into(),
                kind: "SOURCE".into(),
                state: "ACCEPTED IMMUTABLE SOURCE".into(),
                fields: vec![repository.clone()],
            });
            snapshot.jobs.push(EntityObservation {
                id: DEEP_JOB.into(),
                kind: "CERTIFICATION".into(),
                state: "QUEUED".into(),
                fields: vec![repository.clone()],
            });
            snapshot.jobs.push(EntityObservation {
                id: WORKFLOW_COMPLETED.into(),
                kind: "CERTIFICATION".into(),
                state: "COMPLETED".into(),
                fields: vec![repository.clone()],
            });
            snapshot.jobs.push(EntityObservation {
                id: WORKFLOW_RUNNING.into(),
                kind: "CERTIFICATION".into(),
                state: "RUNNING".into(),
                fields: vec![
                    repository.clone(),
                    ObservationField {
                        label: "Attempt 1: identity".into(),
                        value: WORKFLOW_ATTEMPT.into(),
                        provenance: "Scoped fixture".into(),
                    },
                ],
            });
            snapshot.sessions.push(EntityObservation {
                id: WORKFLOW_SESSION.into(),
                kind: "SEMANTIC_SESSION".into(),
                state: HOSTILE.into(),
                fields: vec![
                    repository,
                    ObservationField {
                        label: "Source submission".into(),
                        value: WORKFLOW_SOURCE.into(),
                        provenance: "Frozen source binding fixture".into(),
                    },
                ],
            });
        }

        Ok(snapshot)
    }

    async fn readiness(
        &self,
        project: ProjectId,
        invocation: &str,
    ) -> Result<ReleaseReadiness, JobStoreError> {
        if !self.workflow || project != self.project || invocation != WORKFLOW_INVOCATION {
            return Err(JobStoreError::Precondition);
        }
        self.revoke_during_lookup()?;

        workflow_readiness(project, false)
    }

    async fn entity(
        &self,
        project: ProjectId,
        entity: &str,
        offset: u32,
    ) -> Result<ProjectSnapshot, JobStoreError> {
        if self.workflow {
            let mut snapshot = self.snapshot(project, offset).await?;
            snapshot.sources.retain(|item| item.id == entity);
            snapshot.jobs.retain(|item| item.id == entity);
            snapshot.sessions.retain(|item| item.id == entity);
            if snapshot.sources.is_empty()
                && snapshot.jobs.is_empty()
                && snapshot.sessions.is_empty()
            {
                return Err(JobStoreError::Precondition);
            }
            self.revoke_during_lookup()?;

            return Ok(snapshot);
        }
        if entity != DEEP_JOB {
            return Err(JobStoreError::Precondition);
        }
        let mut snapshot = self.snapshot(project, offset).await?;
        snapshot.jobs.push(EntityObservation {
            id: DEEP_JOB.into(),
            kind: "CERTIFICATION".into(),
            state: "QUEUED".into(),
            fields: Vec::new(),
        });
        snapshot.has_more = offset == 0;

        Ok(snapshot)
    }

    async fn evidence(
        &self,
        project: ProjectId,
        entity: &str,
        digest: &str,
    ) -> Result<(EvidenceObservation, Vec<u8>), JobStoreError> {
        if project != self.project
            || entity != "owned"
            || digest != digest_bytes(HOSTILE.as_bytes()).as_str()
        {
            return Err(JobStoreError::Precondition);
        }
        Ok((
            EvidenceObservation {
                entity: entity.into(),
                role: "REVIEW".into(),
                sha256: digest.into(),
                size: HOSTILE.len() as u64,
                schema: 2,
                producer: "fixture".into(),
                state: "AVAILABLE".into(),
                verification: Vec::new(),
            },
            HOSTILE.as_bytes().to_vec(),
        ))
    }

    async fn healthy(&self) -> bool {
        true
    }
}

struct Fixture {
    root: tempfile::TempDir,
    configuration: PanelConfiguration,
    credential: String,
    app: axum::Router,
    project: ProjectId,
}

impl Fixture {
    fn new(role: Role) -> R<Self> {
        Self::configured(role, None, false)
    }

    fn configured(
        role: Role,
        commands: Option<Arc<dyn GlassmereCommandBroker>>,
        revoke_on_entity: bool,
    ) -> R<Self> {
        let root = tempfile::tempdir()?;
        let project = ProjectId::new();
        let credential = random_credential().map_err(|_| "entropy unavailable")?;
        let configuration = PanelConfiguration {
            schema: 1,
            origin: ORIGIN.into(),
            development_http: true,
            demonstration_data: true,
            principals: vec![Principal {
                id: "test-operator".into(),
                token_sha256: digest_bytes(credential.as_bytes()).as_str().into(),
                role,
                projects: vec![project],
                grant_generation: commands.as_ref().map(|_| {
                    digest_bytes(b"initial fixture grant generation")
                        .as_str()
                        .into()
                }),
            }],
            audit_path: root.path().join("audit.jsonl"),
        };
        let path = root.path().join("panel.json");
        std::fs::write(&path, serde_json::to_vec(&configuration)?)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let query = Arc::new(QueryFixture {
            project,
            workflow: commands.is_some(),
            revoke_on_entity: revoke_on_entity.then(|| path.clone()),
        });
        let app = if let Some(commands) = commands {
            router_with_commands(query, path, commands)
        } else {
            router(query, path)
        }
        .map_err(|_| "router configuration")?;

        Ok(Self {
            root,
            configuration,
            credential,
            app,
            project,
        })
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        origin: Option<&str>,
        body: String,
    ) -> R<Response<Body>> {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if method == "POST" {
            request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        }

        Ok(self
            .app
            .clone()
            .oneshot(request.body(Body::from(body))?)
            .await?)
    }

    async fn login(&self) -> R<String> {
        let response = self
            .request(
                "POST",
                "/login",
                None,
                Some(ORIGIN),
                format!("credential={}", self.credential),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .ok_or("cookie missing")?
            .to_str()?;
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Max-Age=1800"));

        Ok(cookie
            .split(';')
            .next()
            .ok_or("cookie value missing")?
            .into())
    }
}

async fn body(response: Response<Body>) -> R<String> {
    Ok(String::from_utf8(
        response.into_body().collect().await?.to_bytes().to_vec(),
    )?)
}

// This broker records presentation calls only. PostgreSQL/daemon suites establish
// durable deduplication and domain mediation independently of this HTTP fixture.
#[derive(Default)]
struct RecordingBroker {
    submissions: Mutex<Vec<(String, RequestedJobCommand, String)>>,
    context_reads: AtomicUsize,
    receipt_reads: AtomicUsize,
    requires_review: AtomicBool,
}

fn command_context_digest() -> archcert_domain::Sha256Digest {
    digest_bytes(b"explicit workflow fixture authority")
}

#[async_trait]
impl GlassmereCommandBroker for RecordingBroker {
    async fn context(
        &self,
        _: &str,
        project: ProjectId,
        repository: &archcert_domain::source::RepositoryId,
        operation: ControlOperation,
    ) -> Result<CommandContextObservation, JobStoreError> {
        self.context_reads.fetch_add(1, Ordering::Relaxed);
        Ok(CommandContextObservation {
            project,
            repository: repository.clone(),
            operation,
            authority_context: command_context_digest(),
            requires_reviewed_session: self.requires_review.load(Ordering::Relaxed),
        })
    }

    async fn submit(
        &self,
        principal: &str,
        request: &RequestedJobCommand,
        key: &IdempotencyKey,
    ) -> Result<CommandReceiptObservation, JobStoreError> {
        self.submissions
            .lock()
            .map_err(|_| JobStoreError::Unavailable)?
            .push((principal.into(), request.clone(), key.as_str().into()));
        Ok(CommandReceiptObservation {
            id: ControlCommandId::parse(WORKFLOW_RECEIPT)?,
            project: request.project,
            repository: request.repository.clone(),
            operation: request.action.operation(),
            authority_context: request.authority_context.clone(),
            request_sha256: digest_bytes(b"recorded fixture request"),
            state: ControlCommandState::Requested,
            created_at: 1_700_000_000,
            outcome: None,
        })
    }

    async fn receipt(
        &self,
        _: &str,
        selection: &CommandReceiptSelection,
    ) -> Result<CommandReceiptObservation, JobStoreError> {
        self.receipt_reads.fetch_add(1, Ordering::Relaxed);
        let readiness = selection.operation == ControlOperation::RequestReleaseReadinessEvaluation;
        let build = selection.operation == ControlOperation::RequestReleaseBuild;
        Ok(CommandReceiptObservation {
            id: selection.id,
            project: selection.project,
            repository: selection.repository.clone(),
            operation: selection.operation,
            authority_context: selection.authority_context.clone(),
            request_sha256: digest_bytes(b"recorded fixture request"),
            state: if readiness || build {
                ControlCommandState::Applied
            } else {
                ControlCommandState::Requested
            },
            created_at: 1_700_000_000,
            outcome: if build {
                Some(ControlCommandOutcome::Applied {
                    effect: Box::new(CommandEffect::ReleaseBuildRequested {
                        invocation: archcert_domain::release::BuildInvocationIdentity(
                            digest_bytes(b"metadata build invocation"),
                        ),
                    }),
                })
            } else if readiness {
                Some(ControlCommandOutcome::Applied {
                    effect: Box::new(CommandEffect::ReadinessEvaluated {
                        observation: Box::new(workflow_readiness(selection.project, true)?),
                    }),
                })
            } else {
                None
            },
        })
    }
}

async fn csrf(fixture: &Fixture, cookie: &str) -> R<String> {
    let response = fixture
        .request(
            "GET",
            &format!("/projects/{}", fixture.project),
            Some(cookie),
            None,
            String::new(),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body(response).await?;

    Ok(html
        .split("name=csrf value=\"")
        .nth(1)
        .ok_or("CSRF field")?
        .split('"')
        .next()
        .ok_or("CSRF value")?
        .into())
}

fn command_form(operation: ControlOperation, csrf: &str) -> String {
    let (kind, entity, attempt) = match operation {
        ControlOperation::RequestCertification => ("SOURCE", WORKFLOW_SOURCE, String::new()),
        ControlOperation::RequestReleaseBuild => ("JOB", WORKFLOW_COMPLETED, String::new()),
        ControlOperation::RequestReleaseReadinessEvaluation => {
            ("RELEASE", WORKFLOW_INVOCATION, String::new())
        }
        ControlOperation::CancelEligibleJob => ("JOB", DEEP_JOB, String::new()),
        ControlOperation::RetryEligibleJob => (
            "JOB",
            WORKFLOW_RUNNING,
            format!("&attempt={WORKFLOW_ATTEMPT}"),
        ),
    };

    format!(
        "csrf={csrf}&idempotency=retained-user-action&operation={}&target={kind}&entity={entity}&repository=workflow/fixture&authority_context={}{}",
        operation.name(),
        command_context_digest().as_str(),
        attempt
    )
}

#[tokio::test]
async fn command_permission_matrix_is_enforced_for_every_role_and_supported_operation() -> R {
    for role in [
        Role::Viewer,
        Role::Operator,
        Role::Reviewer,
        Role::Administrator,
    ] {
        let broker = Arc::new(RecordingBroker::default());
        let fixture = Fixture::configured(role, Some(broker.clone()), false)?;
        let cookie = fixture.login().await?;
        let csrf = csrf(&fixture, &cookie).await?;
        let path = format!("/projects/{}/commands", fixture.project);

        for operation in [
            ControlOperation::RequestCertification,
            ControlOperation::RequestReleaseBuild,
            ControlOperation::RequestReleaseReadinessEvaluation,
            ControlOperation::CancelEligibleJob,
            ControlOperation::RetryEligibleJob,
        ] {
            let response = fixture
                .request(
                    "POST",
                    &path,
                    Some(&cookie),
                    Some(ORIGIN),
                    command_form(operation, &csrf),
                )
                .await?;
            let expected = if matches!(role, Role::Operator | Role::Administrator) {
                StatusCode::SEE_OTHER
            } else {
                StatusCode::FORBIDDEN
            };
            assert_eq!(response.status(), expected, "{role:?} {operation:?}");
        }
        {
            let submissions = broker.submissions.lock().map_err(|_| "broker lock")?;
            assert_eq!(
                submissions.len(),
                if matches!(role, Role::Operator | Role::Administrator) {
                    5
                } else {
                    0
                }
            );
            for (principal, command, key) in submissions.iter() {
                assert_eq!(principal, "test-operator");
                assert_eq!(command.project, fixture.project);
                assert_eq!(command.repository.as_str(), "workflow/fixture");
                assert_eq!(key, "retained-user-action");
            }
        }

        for path in [
            "/sign-certificate",
            "/sign-release-permit",
            "/admin/users",
            "/review-disposition",
        ] {
            assert_eq!(
                fixture
                    .request("POST", path, Some(&cookie), Some(ORIGIN), String::new())
                    .await?
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn command_csrf_scope_object_and_role_escalation_fail_before_broker_submission() -> R {
    let broker = Arc::new(RecordingBroker::default());
    let fixture = Fixture::configured(Role::Operator, Some(broker.clone()), false)?;
    let cookie = fixture.login().await?;
    let csrf = csrf(&fixture, &cookie).await?;
    let path = format!("/projects/{}/commands", fixture.project);
    let valid = command_form(ControlOperation::CancelEligibleJob, &csrf);

    for origin in [None, Some("https://attacker.invalid")] {
        assert_eq!(
            fixture
                .request("POST", &path, Some(&cookie), origin, valid.clone())
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        fixture
            .request(
                "POST",
                &path,
                Some(&cookie),
                Some(ORIGIN),
                command_form(ControlOperation::CancelEligibleJob, "wrong-csrf")
            )
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture
            .request("POST", &path, None, Some(ORIGIN), valid.clone())
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                &format!("/projects/{}/commands", ProjectId::new()),
                Some(&cookie),
                Some(ORIGIN),
                valid.clone()
            )
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    let foreign_object = valid.replace(DEEP_JOB, "20000000-0000-4000-8000-000000000099");
    assert_eq!(
        fixture
            .request("POST", &path, Some(&cookie), Some(ORIGIN), foreign_object)
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                &path,
                Some(&cookie),
                Some(ORIGIN),
                valid.replace("workflow/fixture", "other/repository")
            )
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                &path,
                Some(&cookie),
                Some(ORIGIN),
                format!("{valid}&role=ADMINISTRATOR")
            )
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(
        broker
            .submissions
            .lock()
            .map_err(|_| "broker lock")?
            .is_empty()
    );

    Ok(())
}

#[tokio::test]
async fn command_submission_rechecks_grant_after_passive_object_lookup() -> R {
    let broker = Arc::new(RecordingBroker::default());
    let fixture = Fixture::configured(Role::Operator, Some(broker.clone()), true)?;
    let cookie = fixture.login().await?;
    let csrf = csrf(&fixture, &cookie).await?;

    let response = fixture
        .request(
            "POST",
            &format!("/projects/{}/commands", fixture.project),
            Some(&cookie),
            Some(ORIGIN),
            command_form(ControlOperation::CancelEligibleJob, &csrf),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        broker
            .submissions
            .lock()
            .map_err(|_| "broker lock")?
            .is_empty()
    );

    Ok(())
}

#[tokio::test]
async fn command_forms_bind_reviewed_source_and_receipt_refresh_is_nonmutating() -> R {
    let broker = Arc::new(RecordingBroker::default());
    broker.requires_review.store(true, Ordering::Relaxed);
    let fixture = Fixture::configured(Role::Operator, Some(broker.clone()), false)?;
    let cookie = fixture.login().await?;
    let base = format!(
        "/projects/{}/commands/new?operation=REQUEST_CERTIFICATION",
        fixture.project
    );
    let source = fixture
        .request(
            "GET",
            &format!("{base}&target=SOURCE&entity={WORKFLOW_SOURCE}"),
            Some(&cookie),
            None,
            String::new(),
        )
        .await?;
    assert_eq!(source.status(), StatusCode::OK);
    let source = body(source).await?;
    assert!(source.contains("requires an existing reviewed session"));
    assert!(!source.contains("data-command-form"));
    let session = fixture
        .request(
            "GET",
            &format!("{base}&target=SESSION&entity={WORKFLOW_SESSION}"),
            Some(&cookie),
            None,
            String::new(),
        )
        .await?;
    assert_eq!(session.status(), StatusCode::OK);
    let session = body(session).await?;
    assert!(session.contains("data-command-form"));
    assert!(session.contains("name=\"idempotency\""));
    assert!(!session.contains(HOSTILE));
    let csrf = csrf(&fixture, &cookie).await?;
    let payload = command_form(ControlOperation::RequestCertification, &csrf)
        .replace("target=SOURCE", "target=SESSION")
        .replace(WORKFLOW_SOURCE, WORKFLOW_SESSION);
    let response = fixture
        .request(
            "POST",
            &format!("/projects/{}/commands", fixture.project),
            Some(&cookie),
            Some(ORIGIN),
            payload,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()[header::LOCATION].to_str()?.to_owned();

    for _ in 0..2 {
        let response = fixture
            .request("GET", &location, Some(&cookie), None, String::new())
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body(response).await?.contains("not a certificate"));
    }
    let submissions = broker.submissions.lock().map_err(|_| "broker lock")?;
    assert_eq!(submissions.len(), 1);
    assert!(matches!(
        &submissions[0].1.action,
        RequestedJobAction::RequestCertification {
            submission,
            reviewed_session: Some(session),
        } if submission == &SourceSubmissionId::parse(WORKFLOW_SOURCE)?
            && session.to_string() == WORKFLOW_SESSION
    ));
    assert_eq!(broker.receipt_reads.load(Ordering::Relaxed), 2);

    Ok(())
}

#[tokio::test]
async fn unauthenticated_denial_login_headers_and_exact_origin_csrf() -> R {
    let f = Fixture::new(Role::Viewer)?;
    let response = f
        .request("GET", "/projects", None, None, String::new())
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(body(response).await?.contains("UNAUTHENTICATED"));

    let response = f
        .request("GET", "/login", None, None, String::new())
        .await?;
    let csp = response
        .headers()
        .get("content-security-policy")
        .ok_or("CSP missing")?
        .to_str()?;
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(!csp.contains("unsafe-inline"));
    assert!(!csp.contains("https:"));
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .ok_or("cache header")?,
        "private, no-store, max-age=0"
    );

    for origin in [None, Some("https://attacker.invalid")] {
        let response = f
            .request(
                "POST",
                "/login",
                None,
                origin,
                format!("credential={}", f.credential),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    f.login().await?;

    Ok(())
}

#[tokio::test]
async fn viewer_direct_mutations_admin_audit_and_cross_project_idor_are_denied() -> R {
    let f = Fixture::new(Role::Viewer)?;
    let cookie = f.login().await?;
    let other = ProjectId::new();

    for suffix in [
        "",
        "/jobs",
        "/certifications/foreign",
        "/semantic/foreign",
        "/readiness/foreign",
        "/evidence/foreign/foreign",
        "/download/foreign/foreign",
    ] {
        let response = f
            .request(
                "GET",
                &format!("/projects/{other}{suffix}"),
                Some(&cookie),
                None,
                String::new(),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{suffix}");
    }
    for path in [
        "/api/v1/commands/cancel",
        "/api/v1/commands/retry",
        "/api/v1/commands/review",
        "/admin/users",
        "/run-command",
    ] {
        let response = f
            .request("POST", path, Some(&cookie), Some(ORIGIN), String::new())
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let response = f
        .request("GET", "/audit", Some(&cookie), None, String::new())
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let digest_value = digest_bytes(HOSTILE.as_bytes());
    let digest = digest_value.as_str();
    let response = f
        .request(
            "GET",
            &format!("/projects/{}/download/foreign/{digest}", f.project),
            Some(&cookie),
            None,
            String::new(),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[tokio::test]
async fn logout_tampering_revocation_and_role_change_invalidate_access() -> R {
    let mut f = Fixture::new(Role::Viewer)?;
    let cookie = f.login().await?;
    let response = f
        .request(
            "POST",
            "/logout",
            Some(&cookie),
            Some(ORIGIN),
            "csrf=forged".into(),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let page = body(
        f.request("GET", "/projects", Some(&cookie), None, String::new())
            .await?,
    )
    .await?;
    let csrf = page
        .split("name=csrf value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .ok_or("CSRF missing")?;
    let response = f
        .request(
            "POST",
            "/logout",
            Some(&cookie),
            Some(ORIGIN),
            format!("csrf={csrf}"),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        f.request("GET", "/projects", Some(&cookie), None, String::new())
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.request(
            "GET",
            "/projects",
            Some("archcert_session=invalid"),
            None,
            String::new()
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );

    let cookie = f.login().await?;
    f.configuration.principals[0].role = Role::Administrator;
    std::fs::write(
        f.root.path().join("panel.json"),
        serde_json::to_vec(&f.configuration)?,
    )?;
    assert_eq!(
        f.request("GET", "/projects", Some(&cookie), None, String::new())
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let cookie = f.login().await?;
    assert_eq!(
        f.request("GET", "/audit", Some(&cookie), None, String::new())
            .await?
            .status(),
        StatusCode::OK
    );
    f.configuration.principals[0].projects.clear();
    std::fs::write(
        f.root.path().join("panel.json"),
        serde_json::to_vec(&f.configuration)?,
    )?;
    assert_eq!(
        f.request("GET", "/projects", Some(&cookie), None, String::new())
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    Ok(())
}

#[tokio::test]
async fn hostile_metadata_preview_and_download_are_inert_and_original_bytes_are_preserved() -> R {
    let f = Fixture::new(Role::Viewer)?;
    let cookie = f.login().await?;
    let page = body(
        f.request("GET", "/projects", Some(&cookie), None, String::new())
            .await?,
    )
    .await?;
    assert!(!page.contains(HOSTILE));
    assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!page.contains(&f.credential));
    assert!(!page.contains(&f.configuration.principals[0].token_sha256));

    let digest_value = digest_bytes(HOSTILE.as_bytes());
    let digest = digest_value.as_str();
    let path = format!("/projects/{}/evidence/owned/{digest}", f.project);
    let page = body(
        f.request("GET", &path, Some(&cookie), None, String::new())
            .await?,
    )
    .await?;
    assert!(!page.contains(HOSTILE));
    assert!(page.contains("SUPPLEMENTAL / NON-AUTHORITATIVE"));
    assert!(page.contains("UNSUPPORTED structured inspection"));
    assert!(page.contains("<details><summary>Raw data:"));

    for query in [
        "item_offset=100001",
        "item_offset=-1",
        "collection=a..b",
        "collection=%3Cscript%3E",
        "collection=claims&collection=claims",
        "unknown=value",
    ] {
        let response = f
            .request(
                "GET",
                &format!("{path}?{query}"),
                Some(&cookie),
                None,
                String::new(),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
    }

    let path = format!("/projects/{}/download/owned/{digest}", f.project);
    let response = f
        .request("GET", &path, Some(&cookie), None, String::new())
        .await?;
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .ok_or("content type")?,
        "application/octet-stream"
    );
    assert!(
        response
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .ok_or("attachment")?
            .to_str()?
            .starts_with("attachment; filename=\"")
    );
    assert_eq!(body(response).await?, HOSTILE);

    Ok(())
}

#[tokio::test]
async fn server_bounds_configuration_and_browser_body_inputs() -> R {
    let f = Fixture::new(Role::Operator)?;
    let cookie = f.login().await?;
    let response = f
        .request(
            "GET",
            &format!("/api/v1/projects/{}?offset=100001", f.project),
            Some(&cookie),
            None,
            String::new(),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = f
        .request(
            "POST",
            "/login",
            None,
            Some(ORIGIN),
            format!("credential={}", "x".repeat(8192)),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    std::fs::set_permissions(
        f.root.path().join("panel.json"),
        std::fs::Permissions::from_mode(0o644),
    )?;
    assert_eq!(
        f.request("GET", "/projects", Some(&cookie), None, String::new())
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    Ok(())
}

#[tokio::test]
async fn exact_job_links_retain_the_parent_across_child_pages_and_authorize_before_lookup() -> R {
    let f = Fixture::new(Role::Viewer)?;
    let cookie = f.login().await?;
    let path = format!("/projects/{}/jobs/{DEEP_JOB}", f.project);

    for offset in [0, 50, 100_000] {
        let response = f
            .request(
                "GET",
                &format!("{path}?offset={offset}"),
                Some(&cookie),
                None,
                String::new(),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let html = body(response).await?;
        assert!(html.contains(DEEP_JOB));
        assert!(html.contains("Bound immutable evidence"));
        assert!(html.contains("Forensic timeline"));
        if offset == 0 {
            assert!(html.contains(&format!("href=\"{path}?offset=50\"")));
        } else {
            assert!(html.contains(&format!("href=\"{path}?offset={}\"", offset - 50)));
        }
    }
    assert_eq!(
        f.request(
            "GET",
            &format!("{path}?offset=100001"),
            Some(&cookie),
            None,
            String::new()
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        f.request("GET", &path, None, None, String::new())
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let foreign = format!("/projects/{}/jobs/{DEEP_JOB}", ProjectId::new());
    assert_eq!(
        f.request("GET", &foreign, Some(&cookie), None, String::new())
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );

    Ok(())
}

#[tokio::test]
async fn search_is_private_project_scoped_bounded_and_inert_for_every_role() -> R {
    for role in [
        Role::Viewer,
        Role::Operator,
        Role::Reviewer,
        Role::Administrator,
    ] {
        let f = Fixture::new(role)?;
        let cookie = f.login().await?;
        let path = format!("/projects/{}/search", f.project);
        let exact = format!("{path}?kind=JOB&value={DEEP_JOB}");
        let response = f
            .request("GET", &exact, Some(&cookie), None, String::new())
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let html = body(response).await?;
        assert!(html.contains(&format!("/projects/{}/jobs/{DEEP_JOB}", f.project)));
        assert!(!html.contains(HOSTILE));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("data-readiness"));

        let api = format!(
            "/api/v1/projects/{}/search?kind=JOB&value={DEEP_JOB}",
            f.project
        );
        let response = f
            .request("GET", &api, Some(&cookie), None, String::new())
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let page: search::SearchPage = serde_json::from_str(&body(response).await?)?;
        assert_eq!(page.project, f.project);
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].entity, DEEP_JOB);

        for query in [
            "kind=JOB&value=*".into(),
            "kind=JOB&value=x&value=y".into(),
            format!("kind=COMMIT&value={}", "a".repeat(65)),
            "kind=STATUS&value=RUNNING%25".into(),
            "kind=VERDICT&value=PROVEN".into(),
            "kind=SQL&value=SELECT".into(),
            format!("kind=JOB&value={DEEP_JOB}&after=forged"),
            format!("kind=JOB&value={DEEP_JOB}&limit=10000"),
        ] {
            let response = f
                .request(
                    "GET",
                    &format!("{path}?{query}"),
                    Some(&cookie),
                    None,
                    String::new(),
                )
                .await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        }
        assert_eq!(
            f.request("GET", &exact, None, None, String::new())
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let foreign = format!(
            "/api/v1/projects/{}/search?kind=JOB&value={DEEP_JOB}",
            ProjectId::new()
        );
        assert_eq!(
            f.request("GET", &foreign, Some(&cookie), None, String::new())
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    Ok(())
}
