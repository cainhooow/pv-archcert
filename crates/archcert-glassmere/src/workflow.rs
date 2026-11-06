//! Session/role/project/CSRF mediation over a separately authenticated command broker.

use super::*;
use archcert_application::glassmere::commands::*;
use archcert_domain::{
    Sha256Digest,
    ingress::SourceSubmissionId,
    jobs::{AttemptId, ControlCommandId, IdempotencyKey, JobId},
    source::RepositoryId,
};
use auth::Role;
use serde::Deserialize;
use std::fmt::Write;

pub(super) fn routes(router: Router<Arc<Panel>>) -> Router<Arc<Panel>> {
    router
        .route("/projects/{project}/commands/new", get(form))
        .route("/projects/{project}/commands", post(submit))
        .route("/projects/{project}/commands/{id}", get(receipt_page))
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TargetKind {
    Source,
    Session,
    Job,
    Release,
}

impl TargetKind {
    fn name(self) -> &'static str {
        match self {
            Self::Source => "SOURCE",
            Self::Session => "SESSION",
            Self::Job => "JOB",
            Self::Release => "RELEASE",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewRequest {
    operation: ControlOperation,
    target: TargetKind,
    entity: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Submission {
    csrf: String,
    idempotency: String,
    operation: ControlOperation,
    target: TargetKind,
    entity: String,
    repository: RepositoryId,
    authority_context: Sha256Digest,
    attempt: Option<AttemptId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptQuery {
    repository: RepositoryId,
    operation: ControlOperation,
    authority_context: Sha256Digest,
}

struct Target {
    repository: RepositoryId,
    submission: Option<SourceSubmissionId>,
    session: Option<JobId>,
    job: Option<JobId>,
    invocation: Option<archcert_domain::release::BuildInvocationIdentity>,
    attempts: Vec<AttemptId>,
    state: String,
}

fn label(operation: ControlOperation) -> &'static str {
    match operation {
        ControlOperation::RequestCertification => "Request certification",
        ControlOperation::RequestReleaseBuild => "Request release build",
        ControlOperation::RequestReleaseReadinessEvaluation => "Request readiness observation",
        ControlOperation::CancelEligibleJob => "Request eligible cancellation",
        ControlOperation::RetryEligibleJob => "Request infrastructure recovery",
    }
}

fn scoped_identity(
    panel: &Panel,
    headers: &HeaderMap,
    project: &str,
    operation: ControlOperation,
) -> Result<(Identity, ProjectId), AccessError> {
    let id = identity(panel, headers)?;
    let project = project_scope(panel, &id, project)?;
    panel
        .authentication
        .check_operation(&id, operation)
        .map_err(AccessError::Authentication)?;

    Ok((id, project))
}

async fn target(
    panel: &Panel,
    project: ProjectId,
    kind: TargetKind,
    entity: &str,
    operation: ControlOperation,
) -> Result<Target, JobStoreError> {
    if matches!(kind, TargetKind::Release) {
        if operation != ControlOperation::RequestReleaseReadinessEvaluation {
            return Err(JobStoreError::Invalid);
        }

        let digest = Sha256Digest::parse(entity).map_err(|_| JobStoreError::Invalid)?;
        let invocation = archcert_domain::release::BuildInvocationIdentity(digest);

        let observation = panel.query.readiness(project, entity).await?;

        if observation.schema != PROJECTION_SCHEMA
            || observation.subject.project != project
            || observation.subject.invocation != entity
        {
            return Err(JobStoreError::Unavailable);
        }

        let repository = RepositoryId::parse(observation.subject.repository)
            .map_err(|_| JobStoreError::Unavailable)?;

        return Ok(Target {
            repository,
            submission: None,
            session: None,
            job: None,
            invocation: Some(invocation),
            attempts: Vec::new(),
            state: render::enum_text(&observation.state),
        });
    }

    JobId::parse(entity)?;
    if !matches!(
        (operation, kind),
        (
            ControlOperation::RequestCertification,
            TargetKind::Source | TargetKind::Session
        ) | (
            ControlOperation::RequestReleaseBuild
                | ControlOperation::CancelEligibleJob
                | ControlOperation::RetryEligibleJob,
            TargetKind::Job
        )
    ) {
        return Err(JobStoreError::Invalid);
    }

    let snapshot = panel.query.entity(project, entity, 0).await?;
    if snapshot.schema != PROJECTION_SCHEMA || snapshot.project.project != project {
        return Err(JobStoreError::Unavailable);
    }
    let collection = match kind {
        TargetKind::Source => &snapshot.sources,
        TargetKind::Session => &snapshot.sessions,
        TargetKind::Job => &snapshot.jobs,
        TargetKind::Release => return Err(JobStoreError::Invalid),
    };
    let selected = collection
        .iter()
        .find(|item| item.id == entity)
        .ok_or(JobStoreError::Precondition)?;
    let repository = selected
        .fields
        .iter()
        .find(|field| field.label == "Repository")
        .ok_or(JobStoreError::Unavailable)?;
    let repository =
        RepositoryId::parse(repository.value.clone()).map_err(|_| JobStoreError::Unavailable)?;
    let submission = match kind {
        TargetKind::Source => {
            Some(SourceSubmissionId::parse(entity).map_err(|_| JobStoreError::Invalid)?)
        }
        TargetKind::Session => {
            let value = selected
                .fields
                .iter()
                .find(|field| field.label == "Source submission")
                .ok_or(JobStoreError::Unavailable)?;
            Some(SourceSubmissionId::parse(&value.value).map_err(|_| JobStoreError::Unavailable)?)
        }
        TargetKind::Job => None,
        TargetKind::Release => return Err(JobStoreError::Invalid),
    };
    let attempts = selected
        .fields
        .iter()
        .filter(|field| field.label.starts_with("Attempt ") && field.label.ends_with(": identity"))
        .map(|field| AttemptId::parse(&field.value).map_err(|_| JobStoreError::Unavailable))
        .collect::<Result<Vec<_>, _>>()?;
    if attempts.len() > 3 {
        return Err(JobStoreError::Unavailable);
    }

    Ok(Target {
        repository,
        submission,
        session: matches!(kind, TargetKind::Session)
            .then(|| JobId::parse(entity))
            .transpose()?,
        job: matches!(kind, TargetKind::Job)
            .then(|| JobId::parse(entity))
            .transpose()?,
        invocation: None,
        attempts,
        state: selected.state.clone(),
    })
}

fn hidden(name: &str, value: &str) -> String {
    format!(
        "<input type=hidden name=\"{}\" value=\"{}\">",
        render::escape(name),
        render::escape(value)
    )
}

fn form_body(
    project: ProjectId,
    request: &NewRequest,
    target: &Target,
    context: &CommandContextObservation,
    id: &Identity,
    key: &str,
) -> String {
    let mut body = format!(
        "<section class=panel><h2>{}</h2><p>Repository: <span class=mono>{}</span></p><p>Selected record: <span class=mono>{}</span></p><p>Recorded state: {}</p>",
        label(request.operation),
        render::escape(target.repository.as_str()),
        render::escape(&request.entity),
        render::escape(&target.state)
    );
    if request.operation == ControlOperation::RequestCertification
        && context.requires_reviewed_session
        && target.session.is_none()
    {
        let _ = write!(
            body,
            "<div class=callout>Certification requires an existing reviewed session. <a href=/projects/{project}/semantic>Open Semantic review</a> and select its certification request.</div></section>"
        );
        return body;
    }
    if (request.operation == ControlOperation::CancelEligibleJob && target.state != "QUEUED")
        || (request.operation == ControlOperation::RequestReleaseBuild
            && target.state != "COMPLETED")
        || (request.operation == ControlOperation::RetryEligibleJob
            && (target.state != "RUNNING" || target.attempts.is_empty()))
    {
        body.push_str("<div class=callout>No request is available for this recorded state. Eligibility is checked again by the authority.</div></section>");
        return body;
    }

    let _ = write!(
        body,
        "<form method=post action=/projects/{project}/commands data-command-form>"
    );
    for (name, value) in [
        ("csrf", id.csrf.as_str()),
        ("idempotency", key),
        ("operation", request.operation.name()),
        ("target", request.target.name()),
        ("entity", request.entity.as_str()),
        ("repository", target.repository.as_str()),
        ("authority_context", context.authority_context.as_str()),
    ] {
        body.push_str(&hidden(name, value));
    }
    if request.operation == ControlOperation::RetryEligibleJob {
        body.push_str("<p>Recovery requires expired ownership, confirmed cleanup and remaining original attempt capacity. Target or policy rejection cannot be retried here.</p><label>Exact attempt<select name=attempt required>");
        for attempt in &target.attempts {
            let _ = write!(body, "<option value=\"{attempt}\">{attempt}</option>");
        }
        body.push_str("</select></label>");
    } else if request.operation == ControlOperation::CancelEligibleJob {
        body.push_str("<p>The authority may cancel eligible queued work only. This request cannot stop a running target or discard evidence.</p>");
    } else if request.operation == ControlOperation::RequestReleaseReadinessEvaluation {
        body.push_str("<p>This records a fresh question about the exact release. Its receipt is a historical observation, including when it records RELEASE_ALLOWED. Current use still requires the live readiness query. This form requests no build, signing or deployment.</p>");
    } else if request.operation == ControlOperation::RequestReleaseBuild {
        body.push_str("<p>This requests build workflow admission from the selected source certification. The authority verifies the original certificate and selects the fixed build recipe. Admission does not mean builds succeeded, reproducibility was proven or a Release Permit was issued.</p>");
    } else {
        body.push_str("<p>This requests the existing exact-source workflow. Mandatory validation and review remain required. No certificate is issued by this form.</p>");
    }
    let _ = write!(
        body,
        "<p><button type=submit>{}</button></p></form><p>Duplicate submissions resolve to the retained request. Refreshing its receipt does not submit again.</p></section>",
        label(request.operation)
    );

    body
}

async fn form(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(request): Query<NewRequest>,
) -> Response {
    let (id, project) = match scoped_identity(&panel, &headers, &project, request.operation) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let result = async {
        let target = target(
            &panel,
            project,
            request.target,
            &request.entity,
            request.operation,
        )
        .await?;
        let broker = panel.commands.as_ref().ok_or(JobStoreError::Unavailable)?;
        let context = broker
            .context(&id.id, project, &target.repository, request.operation)
            .await?;
        if context.project != project
            || context.repository != target.repository
            || context.operation != request.operation
        {
            return Err(JobStoreError::Unavailable);
        }

        Ok((target, context))
    }
    .await;
    let (target, context) = match result {
        Ok(value) => value,
        Err(error) => return query_error(error),
    };
    let key = match auth::random_credential() {
        Ok(key) => key,
        Err(error) => return auth_error(error),
    };

    html(
        &panel,
        label(request.operation),
        &form_body(project, &request, &target, &context, &id, &key),
        Some(&id),
    )
}

async fn submit(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Path(project_text): Path<String>,
    Form(request): Form<Submission>,
) -> Response {
    let (id, project) = match scoped_identity(&panel, &headers, &project_text, request.operation) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = panel.authentication.check_csrf(&id, &request.csrf) {
        return auth_error(error);
    }
    let result = async {
        let key = IdempotencyKey::parse(request.idempotency.clone())?;
        let target = target(
            &panel,
            project,
            request.target,
            &request.entity,
            request.operation,
        )
        .await?;
        if target.repository != request.repository {
            return Err(JobStoreError::Precondition);
        }
        let action = match request.operation {
            ControlOperation::RequestReleaseBuild if request.attempt.is_none() => {
                RequestedJobAction::RequestReleaseBuild {
                    job: target.job.ok_or(JobStoreError::Invalid)?,
                }
            }
            ControlOperation::RequestReleaseReadinessEvaluation if request.attempt.is_none() => {
                RequestedJobAction::RequestReleaseReadinessEvaluation {
                    invocation: target.invocation.ok_or(JobStoreError::Invalid)?,
                }
            }
            ControlOperation::RequestCertification if request.attempt.is_none() => {
                RequestedJobAction::RequestCertification {
                    submission: target.submission.ok_or(JobStoreError::Invalid)?,
                    reviewed_session: target.session,
                }
            }
            ControlOperation::CancelEligibleJob if request.attempt.is_none() => {
                RequestedJobAction::CancelEligibleJob {
                    job: target.job.ok_or(JobStoreError::Invalid)?,
                }
            }
            ControlOperation::RetryEligibleJob => {
                let attempt = request.attempt.ok_or(JobStoreError::Invalid)?;
                if !target.attempts.contains(&attempt) {
                    return Err(JobStoreError::Precondition);
                }
                RequestedJobAction::RetryEligibleJob {
                    job: target.job.ok_or(JobStoreError::Invalid)?,
                    attempt,
                }
            }
            _ => return Err(JobStoreError::Invalid),
        };

        Ok((
            key,
            RequestedJobCommand {
                project,
                repository: target.repository,
                authority_context: request.authority_context,
                action,
            },
        ))
    }
    .await;
    let (key, command) = match result {
        Ok(value) => value,
        Err(error) => return query_error(error),
    };
    // Recheck revocation after passive object lookup, before any broker call.
    let (current, _) = match scoped_identity(&panel, &headers, &project_text, request.operation) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = panel.authentication.check_csrf(&current, &request.csrf) {
        return auth_error(error);
    }
    if let Err(error) = panel
        .authentication
        .audit(&current.id, "COMMAND_SUBMISSION_REQUESTED")
    {
        return auth_error(error);
    }
    let Some(broker) = &panel.commands else {
        return query_error(JobStoreError::Unavailable);
    };
    let receipt = match broker.submit(&current.id, &command, &key).await {
        Ok(receipt) => receipt,
        Err(error) => return query_error(error),
    };
    if receipt.project != project
        || receipt.repository != command.repository
        || receipt.operation != command.action.operation()
        || receipt.authority_context != command.authority_context
    {
        return query_error(JobStoreError::Unavailable);
    }
    if let Err(error) = panel
        .authentication
        .audit(&current.id, "COMMAND_SUBMISSION_ACCEPTED")
    {
        return auth_error(error);
    }

    Redirect::to(&receipt_url(&receipt)).into_response()
}

fn receipt_url(receipt: &CommandReceiptObservation) -> String {
    format!(
        "/projects/{}/commands/{}?repository={}&operation={}&authority_context={}",
        receipt.project,
        receipt.id,
        receipt.repository.as_str(),
        receipt.operation.name(),
        receipt.authority_context.as_str()
    )
}

fn historical_readiness(observation: &ReleaseReadiness) -> String {
    let subject = &observation.subject;
    let mut body = format!(
        "<section class=panel data-historical-readiness><h3>Historical readiness observation: {}</h3><p><strong>HISTORICAL_OBSERVATION</strong> — this recorded result does not establish current readiness. Check the live query before making a current decision.</p><dl class=facts>",
        render::enum_text(&observation.state),
    );
    for (label, value) in [
        ("Project", subject.project.to_string()),
        ("Repository", subject.repository.clone()),
        ("Invocation", subject.invocation.clone()),
        ("Source commit", subject.source.commit.as_str().into()),
        ("Source tree", subject.source.tree.as_str().into()),
        (
            "Source snapshot",
            subject.source.snapshot_sha256.as_str().into(),
        ),
        (
            "Certificate",
            subject
                .certificate
                .clone()
                .unwrap_or_else(|| "MISSING".into()),
        ),
        (
            "Artifact",
            subject.artifact.clone().unwrap_or_else(|| "MISSING".into()),
        ),
        (
            "Release Permit",
            subject.permit.clone().unwrap_or_else(|| "MISSING".into()),
        ),
        ("Recorded revision", observation.revision.clone()),
        (
            "Evaluated UTC Unix seconds",
            observation.evaluated_at.to_string(),
        ),
        ("Observation scope", observation.provenance.clone()),
    ] {
        let _ = write!(
            body,
            "<div><dt>{label}</dt><dd class=mono>{}</dd></div>",
            render::escape(&value),
        );
    }
    body.push_str("</dl>");

    for blocker in &observation.blockers {
        let _ = write!(
            body,
            "<p><strong>{}</strong>: {}<small class=mono>{}</small></p>",
            render::enum_text(&blocker.code),
            render::escape(&blocker.summary),
            render::escape(&blocker.affected_identity),
        );
    }

    let _ = write!(
        body,
        "<p><a href=/projects/{}/readiness/{}>Check current readiness</a></p><p><a href=/projects/{}/commands/new?operation=REQUEST_RELEASE_READINESS_EVALUATION&amp;target=RELEASE&amp;entity={}>Request another explicit observation</a></p></section>",
        subject.project,
        render::escape(&subject.invocation),
        subject.project,
        render::escape(&subject.invocation),
    );

    body
}

fn receipt_body(receipt: &CommandReceiptObservation) -> String {
    let state = match receipt.state {
        ControlCommandState::Requested => "REQUESTED",
        ControlCommandState::Processing => "PROCESSING",
        ControlCommandState::Applied => "APPLIED",
        ControlCommandState::Rejected => "REJECTED",
        ControlCommandState::Inconclusive => "INCONCLUSIVE",
    };
    let mut body = format!(
        "<section class=panel><h2>{}</h2><p><span class=tag>{state}</span></p><p class=mono>{}</p><p>Repository: <span class=mono>{}</span></p><p>A request receipt is not a certificate, Release Permit or target verdict.</p>",
        label(receipt.operation),
        receipt.id,
        render::escape(receipt.repository.as_str())
    );
    if receipt.operation == ControlOperation::RequestReleaseReadinessEvaluation {
        body.push_str("<p><strong>HISTORICAL_OBSERVATION</strong>. Refreshing this receipt retains the same question and recorded result. A new explicit action key asks another question; it creates no certification or build workflow.</p>");
    }

    match receipt.outcome.as_ref() {
        Some(ControlCommandOutcome::Applied { effect }) => match effect.as_ref() {
            CommandEffect::ReleaseBuildRequested { invocation }
                if receipt.operation == ControlOperation::RequestReleaseBuild =>
            {
                let _ = write!(
                    body,
                    "<section data-build-admission><h3>Build workflow admitted</h3><p>Invocation: <span class=mono>{}</span></p><p>This receipt establishes admission only. Successful builds, reproducibility and Release Permit issuance remain separate. Check current readiness before making a release decision.</p><p><a href=/projects/{}/readiness/{}>Inspect current release readiness</a></p></section>",
                    invocation.0.as_str(),
                    receipt.project,
                    invocation.0.as_str(),
                );
            }
            CommandEffect::ReadinessEvaluated { observation }
                if receipt.operation == ControlOperation::RequestReleaseReadinessEvaluation =>
            {
                body.push_str(&historical_readiness(observation));
            }
            CommandEffect::CertificationRequested { job, session } => {
                body.push_str("<p>The certification workflow was requested. Mandatory checks and any subsequent signing remain separate.</p>");
                if let Some(job) = job {
                    let _ = write!(
                        body,
                        "<p><a href=/projects/{}/jobs/{job}>Inspect certification job</a></p>",
                        receipt.project
                    );
                }
                if let Some(session) = session {
                    let _ = write!(
                        body,
                        "<p><a href=/projects/{}/semantic/{session}>Inspect reviewed session</a></p>",
                        receipt.project
                    );
                }
            }
            CommandEffect::JobCanceled { job } => {
                let _ = write!(
                    body,
                    "<p>Eligible queued work was canceled without a target verdict.</p><p><a href=/projects/{}/jobs/{job}>Inspect retained job history</a></p>",
                    receipt.project
                );
            }
            CommandEffect::JobRecoveryRequested { job, attempt } => {
                let _ = write!(
                    body,
                    "<p>Infrastructure recovery was recorded for attempt <span class=mono>{attempt}</span>. Current execution state is read separately.</p><p><a href=/projects/{}/jobs/{job}>Inspect job history</a></p>",
                    receipt.project
                );
            }
            _ => body.push_str("<p>Unsupported receipt effect; no positive authority claim is displayed.</p>"),
        },
        Some(ControlCommandOutcome::Rejected { reason })
            if receipt.operation == ControlOperation::RequestReleaseReadinessEvaluation =>
        {
            let _ = write!(body,
                "<p>The authority rejected this question: <strong>{}</strong>. Inspect its original authority context and exact invocation before an explicit new request.</p>",
                render::enum_text(reason),
            );
        }
        Some(ControlCommandOutcome::Rejected { .. }) => body.push_str("<p>The authority rejected this action. No requested job transition was accepted. Review the exact source, mandatory review and current job eligibility before an explicit new action.</p>"),
        Some(ControlCommandOutcome::Inconclusive { reason })
            if receipt.operation == ControlOperation::RequestReleaseReadinessEvaluation =>
        {
            let _ = write!(body,
                "<p>This observation could not be completed: <strong>{}</strong>. The receipt remains historical. Inspect the live readiness query or explicitly request another observation.</p>",
                render::enum_text(reason),
            );
        }
        Some(ControlCommandOutcome::Inconclusive { .. }) => body.push_str("<p>The outcome is uncertain. A different action key cannot authorize repetition. Inspect retained authority state.</p>"),
        None => body.push_str("<p>Waiting for authority mediation. This records no certification result.</p>"),
    }
    let _ = write!(
        body,
        "<details><summary>Request identity</summary><dl class=facts><div><dt>Original authority context</dt><dd class=mono>{}</dd></div><div><dt>Request digest</dt><dd class=mono>{}</dd></div><div><dt>Created UTC Unix seconds</dt><dd>{}</dd></div></dl></details><p><a href=\"{}\">Refresh receipt</a></p></section>",
        receipt.authority_context.as_str(),
        receipt.request_sha256.as_str(),
        receipt.created_at,
        render::escape(&receipt_url(receipt))
    );

    body
}

async fn receipt_page(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Path((project_text, id)): Path<(String, String)>,
    Query(query): Query<ReceiptQuery>,
) -> Response {
    let (identity, project) =
        match scoped_identity(&panel, &headers, &project_text, query.operation) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let id = match ControlCommandId::parse(&id) {
        Ok(id) => id,
        Err(_) => return query_error(JobStoreError::Invalid),
    };
    let selection = CommandReceiptSelection {
        id,
        project,
        repository: query.repository,
        operation: query.operation,
        authority_context: query.authority_context,
    };
    let Some(broker) = &panel.commands else {
        return query_error(JobStoreError::Unavailable);
    };
    match broker.receipt(&identity.id, &selection).await {
        Ok(receipt)
            if receipt.id == selection.id
                && receipt.project == selection.project
                && receipt.repository == selection.repository
                && receipt.operation == selection.operation
                && receipt.authority_context == selection.authority_context =>
        {
            html(
                &panel,
                "Workflow request",
                &receipt_body(&receipt),
                Some(&identity),
            )
        }
        Ok(_) => query_error(JobStoreError::Unavailable),
        Err(error) => query_error(error),
    }
}

pub(super) fn readiness_link(value: &ReleaseReadiness, role: Role) -> String {
    if !role.permits_command(ControlOperation::RequestReleaseReadinessEvaluation) {
        return String::new();
    }

    format!(
        "<section class=panel><h2>Readiness observation request</h2><p>Record a separately audited historical observation of this exact invocation.</p><p><a href=/projects/{}/commands/new?operation=REQUEST_RELEASE_READINESS_EVALUATION&amp;target=RELEASE&amp;entity={}>Request readiness observation</a></p></section>",
        value.subject.project,
        render::escape(&value.subject.invocation),
    )
}

pub(super) fn links(
    snapshot: &ProjectSnapshot,
    section: &str,
    selected: Option<&str>,
    role: Role,
) -> String {
    if !role.permits_command(ControlOperation::RequestCertification) {
        return String::new();
    }
    let project = snapshot.project.project;
    let mut body = String::new();
    if section == "overview" && selected.is_none() {
        for source in &snapshot.sources {
            if SourceSubmissionId::parse(&source.id).is_ok() {
                let _ = write!(
                    body,
                    "<p><a href=/projects/{project}/commands/new?operation=REQUEST_CERTIFICATION&amp;target=SOURCE&amp;entity={}>Request certification for source <span class=mono>{}</span></a></p>",
                    render::escape(&source.id),
                    render::escape(&source.id)
                );
            }
        }
    } else if let Some(selected) = selected {
        if JobId::parse(selected).is_err() {
            return String::new();
        }
        if section == "semantic"
            && snapshot
                .sessions
                .iter()
                .any(|session| session.id == selected)
        {
            let _ = write!(
                body,
                "<p><a href=/projects/{project}/commands/new?operation=REQUEST_CERTIFICATION&amp;target=SESSION&amp;entity={}>Request reviewed certification</a></p>",
                render::escape(selected)
            );
        } else if ["jobs", "certifications"].contains(&section)
            && let Some(job) = snapshot.jobs.iter().find(|job| job.id == selected)
        {
            let operation = match job.state.as_str() {
                "COMPLETED" => Some(ControlOperation::RequestReleaseBuild),
                "QUEUED" => Some(ControlOperation::CancelEligibleJob),
                "RUNNING" => Some(ControlOperation::RetryEligibleJob),
                _ => None,
            };
            if let Some(operation) = operation {
                let _ = write!(
                    body,
                    "<p><a href=/projects/{project}/commands/new?operation={}&amp;target=JOB&amp;entity={}>{}</a></p>",
                    operation.name(),
                    render::escape(selected),
                    label(operation)
                );
            }
        }
    }
    if body.is_empty() {
        body
    } else {
        format!("<section class=panel><h2>Workflow requests</h2>{body}</section>")
    }
}
