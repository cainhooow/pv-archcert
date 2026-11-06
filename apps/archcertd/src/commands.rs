//! Command-only HTTP mediation. No browser session, target execution or signing.

use super::{ApiState, error};
use archcert_application::{glassmere::commands::ControlOperation, jobs::JobStoreError};
use archcert_control_plane::commands::{CommandAuthorization, CommandCredentials};
use archcert_domain::jobs::{ControlCommandId, IdempotencyKey};
use archcert_protocol::commands::{
    ControlActionRequest, ControlCommandContextResponse, ControlCommandQuery,
    ControlCommandResponse, CreateControlCommandRequest,
};
use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{Next, from_fn, map_response},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use std::{future::Future, time::Duration};

#[cfg(test)]
mod tests;

pub(super) fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v2/command-context", get(context))
        .route("/api/v2/commands", post(submit))
        .route("/api/v2/commands/{id}", get(status))
        .layer(from_fn(query_bound))
        .layer(map_response(no_store))
}

async fn query_bound(request: Request, next: Next) -> Response {
    if request
        .uri()
        .path_and_query()
        .is_some_and(|uri| uri.as_str().len() > 768)
    {
        return StatusCode::URI_TOO_LONG.into_response();
    }

    next.run(request).await
}

async fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );

    response
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, JobStoreError> {
    let values = headers.get_all(name);
    let mut values = values.iter();
    let value = values.next().ok_or(JobStoreError::Invalid)?;
    if values.next().is_some() {
        return Err(JobStoreError::Invalid);
    }

    value.to_str().map_err(|_| JobStoreError::Invalid)
}

fn authorize(
    state: &ApiState,
    headers: &HeaderMap,
    query: &ControlCommandQuery,
) -> Result<CommandAuthorization, JobStoreError> {
    let token = single_header(headers, "authorization")
        .map_err(|_| JobStoreError::Unauthorized)?
        .strip_prefix("Bearer ")
        .ok_or(JobStoreError::Unauthorized)?;
    let path = state
        .command_credentials
        .as_ref()
        .ok_or(JobStoreError::Unavailable)?;
    let credentials = CommandCredentials::load(path, &state.control.configuration)
        .map_err(|_| JobStoreError::Unavailable)?;

    if !matches!(
        query.operation,
        ControlOperation::RequestCertification
            | ControlOperation::RequestReleaseBuild
            | ControlOperation::RequestReleaseReadinessEvaluation
            | ControlOperation::CancelEligibleJob
            | ControlOperation::RetryEligibleJob
    ) {
        return Err(JobStoreError::Invalid);
    }

    credentials.authorize(
        &state.control.configuration,
        token,
        query.project,
        &query.repository,
        query.operation,
        query.authority_context.as_ref(),
    )
}

async fn bounded<T>(
    state: &ApiState,
    future: impl Future<Output = Result<T, JobStoreError>>,
) -> Result<T, JobStoreError> {
    let _slot = state
        .command_slots
        .try_acquire()
        .map_err(|_| JobStoreError::Unavailable)?;

    // Coordination only. Timeout does not classify a target result or authorize replay.
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .map_err(|_| JobStoreError::Unavailable)?
}

pub(super) async fn ready(state: &ApiState) -> bool {
    let Some(path) = &state.command_credentials else {
        return true;
    };
    if CommandCredentials::load(path, &state.control.configuration).is_err() {
        return false;
    }

    state
        .control
        .repository
        .check_command_readiness()
        .await
        .is_ok()
}

async fn context(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ControlCommandQuery>,
) -> Response {
    let result = bounded(&state, async {
        let authorization = authorize(&state, &headers, &query)?;
        let authority_context = state.control.command_context(&authorization).await?;
        let scope = authorization.scope();
        let grant = state.control.configuration.grant_for(
            &scope.actor,
            scope.project,
            &scope.repository,
        )?;

        Ok(ControlCommandContextResponse {
            schema: 1,
            project: scope.project,
            repository: scope.repository.clone(),
            operation: authorization.operation(),
            authority_context,
            requires_reviewed_session: grant.ironcrest
                && !matches!(
                    authorization.operation(),
                    ControlOperation::RequestReleaseReadinessEvaluation
                        | ControlOperation::RequestReleaseBuild
                ),
        })
    })
    .await;

    match result {
        Ok(context) => Json(context).into_response(),
        Err(failure) => error(failure),
    }
}

async fn submit(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CreateControlCommandRequest>,
) -> Response {
    let result = bounded(&state, async {
        if request.schema != request.action.schema() {
            return Err(JobStoreError::Invalid);
        }

        let query = ControlCommandQuery {
            project: request.project,
            repository: request.repository,
            operation: request.action.operation(),
            authority_context: Some(request.authority_context),
        };
        let authorization = authorize(&state, &headers, &query)?;
        let key = IdempotencyKey::parse(single_header(&headers, "idempotency-key")?.into())?;

        let record = match request.action {
            ControlActionRequest::RequestReleaseBuild { job } => {
                state
                    .control
                    .request_release_build(&authorization, job, &key)
                    .await?
            }
            ControlActionRequest::RequestReleaseReadinessEvaluation { invocation } => {
                state
                    .control
                    .request_readiness(&authorization, invocation, &key)
                    .await?
            }
            ControlActionRequest::RequestCertification {
                source_submission,
                reviewed_session,
            } => {
                state
                    .control
                    .request_certification(
                        &authorization,
                        source_submission,
                        reviewed_session,
                        &key,
                    )
                    .await?
            }
            ControlActionRequest::CancelEligibleJob { job } => {
                state
                    .control
                    .request_cancellation(&authorization, job, &key)
                    .await?
            }
            ControlActionRequest::RetryEligibleJob { job, attempt } => {
                state
                    .control
                    .request_recovery(&authorization, job, attempt, &key)
                    .await?
            }
        };

        Ok(ControlCommandResponse::from(record))
    })
    .await;

    match result {
        Ok(receipt) => (StatusCode::ACCEPTED, Json(receipt)).into_response(),
        Err(failure) => error(failure),
    }
}

async fn status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ControlCommandQuery>,
) -> Response {
    let result = bounded(&state, async {
        let original_context = query
            .authority_context
            .clone()
            .ok_or(JobStoreError::Invalid)?;
        let mut query = query;
        query.authority_context = None;
        let authorization = authorize(&state, &headers, &query)?;
        let record = state
            .control
            .historical_command_status(
                &authorization,
                ControlCommandId::parse(&id)?,
                &original_context,
            )
            .await?;

        Ok(ControlCommandResponse::from(record))
    })
    .await;

    match result {
        Ok(receipt) => Json(receipt).into_response(),
        Err(failure) => error(failure),
    }
}
