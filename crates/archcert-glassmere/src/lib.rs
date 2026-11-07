//! Private Glassmere HTTP presentation. No signing, runtime or persistence adapter.

pub mod auth;
mod inspection;
mod local;
mod render;
mod search_view;
mod workflow;

use archcert_application::glassmere::commands::GlassmereCommandBroker;
use archcert_application::{glassmere::*, jobs::JobStoreError};
use archcert_domain::ProjectId;
use auth::{AuthError, Authentication, Identity};
use axum::{
    Form, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc, time::Duration};

struct Panel {
    query: Arc<dyn GlassmereQuery>,
    local: Option<Arc<dyn archcert_application::local::LocalPlatform>>,
    commands: Option<Arc<dyn GlassmereCommandBroker>>,
    authentication: Authentication,
    concurrency: tokio::sync::Semaphore,
}

/// Construct a versioned private surface from a query-only application port.
/// Private provisioning and audit must be available before the listener starts.
pub fn router(query: Arc<dyn GlassmereQuery>, configuration: PathBuf) -> Result<Router, AuthError> {
    configured_router(query, configuration, None, None)
}

/// Add an independently provisioned command broker while query storage remains SELECT-only.
pub fn router_with_commands(
    query: Arc<dyn GlassmereQuery>,
    configuration: PathBuf,
    commands: Arc<dyn GlassmereCommandBroker>,
) -> Result<Router, AuthError> {
    configured_router(query, configuration, Some(commands), None)
}

/// Add the separately authenticated local onboarding port without persistence/runtime access.
pub fn router_with_local(
    query: Arc<dyn GlassmereQuery>,
    configuration: PathBuf,
    local: Arc<dyn archcert_application::local::LocalPlatform>,
) -> Result<Router, AuthError> {
    configured_router(query, configuration, None, Some(local))
}

fn configured_router(
    query: Arc<dyn GlassmereQuery>,
    configuration: PathBuf,
    commands: Option<Arc<dyn GlassmereCommandBroker>>,
    local: Option<Arc<dyn archcert_application::local::LocalPlatform>>,
) -> Result<Router, AuthError> {
    let panel = Arc::new(Panel {
        query,
        local,
        commands,
        authentication: Authentication::open(configuration)?,
        concurrency: tokio::sync::Semaphore::new(8),
    });
    if panel.commands.is_some()
        && panel
            .authentication
            .configuration()?
            .principals
            .iter()
            .any(|principal| {
                matches!(
                    principal.role,
                    auth::Role::Operator | auth::Role::Administrator
                ) && principal.grant_generation.is_none()
            })
    {
        return Err(AuthError::Unavailable);
    }
    let router = Router::new()
        .route(
            "/",
            get(|State(panel): State<Arc<Panel>>| async move {
                Redirect::to(if panel.local.is_some() {
                    "/local"
                } else {
                    "/projects"
                })
            }),
        )
        .route("/healthz", get(|| async { "panel process healthy" }))
        .route("/readyz", get(health))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/projects", get(projects))
        .route("/projects/{project}", get(overview))
        .route("/projects/{project}/search", get(search_view::page))
        .route("/projects/{project}/{section}", get(project_view))
        .route("/projects/{project}/{section}/{entity}", get(entity_view))
        .route(
            "/projects/{project}/evidence/{entity}/{digest}",
            get(evidence),
        )
        .route(
            "/projects/{project}/download/{entity}/{digest}",
            get(download),
        )
        .route("/api/v1/projects/{project}", get(snapshot_api))
        .route("/api/v1/projects/{project}/search", get(search_view::api))
        .route(
            "/api/v1/projects/{project}/readiness/{invocation}",
            get(readiness_api),
        )
        .route("/audit", get(audit))
        .route(
            "/assets/panel.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../static/panel.css"),
                )
            }),
        )
        .route(
            "/assets/panel.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../static/panel.js"),
                )
            }),
        );
    let router = if panel.commands.is_some() {
        workflow::routes(router)
    } else {
        router
    };
    let router = if panel.local.is_some() {
        local::routes(router)
    } else {
        router
    };
    let router = router
        .fallback(unsupported)
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn_with_state(panel.clone(), boundary))
        .with_state(panel);

    Ok(router)
}

fn error(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        Json(serde_json::json!({"schema":1,"error":{"code":code}})),
    )
        .into_response()
}

fn auth_error(error_value: AuthError) -> Response {
    match error_value {
        AuthError::Unauthenticated => error(StatusCode::UNAUTHORIZED, "UNAUTHENTICATED"),
        AuthError::Forbidden => error(StatusCode::FORBIDDEN, "FORBIDDEN"),
        AuthError::RateLimited => error(StatusCode::TOO_MANY_REQUESTS, "LIMIT_EXCEEDED"),
        AuthError::Unavailable => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "INFRASTRUCTURE_UNAVAILABLE",
        ),
    }
}

fn query_error(error_value: JobStoreError) -> Response {
    match error_value {
        JobStoreError::Unavailable => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "INFRASTRUCTURE_UNAVAILABLE",
        ),
        JobStoreError::Invalid => error(StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
        JobStoreError::Conflict => error(StatusCode::CONFLICT, "CONFLICT"),
        JobStoreError::SemanticContextLimit => {
            error(StatusCode::PAYLOAD_TOO_LARGE, "LIMIT_EXCEEDED")
        }
        JobStoreError::Precondition | JobStoreError::Unauthorized => {
            error(StatusCode::NOT_FOUND, "NOT_FOUND")
        }
    }
}

fn token(headers: &HeaderMap) -> &str {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(';')
                .find_map(|cookie| cookie.trim().strip_prefix("archcert_session="))
        })
        .unwrap_or("")
}

enum AccessError {
    Authentication(AuthError),
    NotFound,
}

impl IntoResponse for AccessError {
    fn into_response(self) -> Response {
        match self {
            Self::Authentication(auth) => auth_error(auth),
            Self::NotFound => error(StatusCode::NOT_FOUND, "NOT_FOUND"),
        }
    }
}

fn identity(panel: &Panel, headers: &HeaderMap) -> Result<Identity, AccessError> {
    panel
        .authentication
        .authenticate(token(headers))
        .map_err(AccessError::Authentication)
}

fn project_scope(
    panel: &Panel,
    identity: &Identity,
    project: &str,
) -> Result<ProjectId, AccessError> {
    let project: ProjectId = project.parse().map_err(|_| AccessError::NotFound)?;
    if !identity.projects.contains(&project) {
        panel
            .authentication
            .audit(&identity.id, "PROJECT_AUTHORIZATION_DENIED")
            .map_err(AccessError::Authentication)?;
        return Err(AccessError::NotFound);
    }

    Ok(project)
}

async fn boundary(State(panel): State<Arc<Panel>>, request: Request, next: Next) -> Response {
    let config = match panel.authentication.configuration() {
        Ok(config) => config,
        Err(e) => return auth_error(e),
    };
    let method = request.method();
    let mut response = if ![Method::GET, Method::HEAD, Method::OPTIONS].contains(method)
        && request
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            != Some(config.origin.as_str())
    {
        let _ = panel.authentication.audit("UNKNOWN", "ORIGIN_DENIED");
        error(StatusCode::FORBIDDEN, "FORBIDDEN")
    } else if let Err(error) = validate_local_session(&panel, request.headers()).await {
        auth_error(error)
    } else if let Ok(_permit) = panel.concurrency.try_acquire() {
        match tokio::time::timeout(
            Duration::from_secs(if panel.local.is_some() { 45 } else { 15 }),
            next.run(request),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => error(
                StatusCode::SERVICE_UNAVAILABLE,
                "INFRASTRUCTURE_UNAVAILABLE",
            ),
        }
    } else {
        error(StatusCode::TOO_MANY_REQUESTS, "LIMIT_EXCEEDED")
    };

    response = match response.status() {
        StatusCode::BAD_REQUEST
        | StatusCode::UNPROCESSABLE_ENTITY
        | StatusCode::METHOD_NOT_ALLOWED => error(StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
        StatusCode::PAYLOAD_TOO_LARGE => error(StatusCode::PAYLOAD_TOO_LARGE, "LIMIT_EXCEEDED"),
        _ => response,
    };

    // Apply to errors, login, downloads and static resources as well as pages.
    let headers = response.headers_mut();
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'",
        ),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "same-origin"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        ),
        ("cache-control", "private, no-store, max-age=0"),
        ("pragma", "no-cache"),
        ("vary", "Cookie"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    if let Ok(request_id) = auth::random_credential()
        && let Ok(value) = HeaderValue::from_str(&request_id[..16])
    {
        headers.insert("x-request-id", value);
    }

    if !config.development_http {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000"),
        );
    }

    response
}

fn html(panel: &Panel, title: &str, body: &str, identity: Option<&Identity>) -> Response {
    match panel.authentication.configuration() {
        Ok(config) => {
            let local_body;
            let body = if panel.local.is_some() {
                local_body = format!(
                    "<p><a href=/local>Local installation and project onboarding</a> · LOCAL SELF-HOSTED PILOT — DEVELOPMENT CERTIFICATION AUTHORITY</p>{body}"
                );
                local_body.as_str()
            } else {
                body
            };
            let content = render::page(title, body, identity, &config);
            if content.len() > 2 * 1024 * 1024 {
                error(StatusCode::PAYLOAD_TOO_LARGE, "LIMIT_EXCEEDED")
            } else {
                Html(content).into_response()
            }
        }
        Err(e) => auth_error(e),
    }
}

async fn login_page(State(panel): State<Arc<Panel>>) -> Response {
    if panel.local.is_some() {
        return local::login_page(&panel).await;
    }
    html(&panel, "Operator access", &render::login(), None)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    credential: String,
}

async fn login(State(panel): State<Arc<Panel>>, Form(request): Form<Login>) -> Response {
    if panel.local.is_some() {
        return auth_error(AuthError::Forbidden);
    }

    login_session(&panel, &request.credential)
}

fn login_session(panel: &Panel, credential: &str) -> Response {
    match panel.authentication.login(credential) {
        Ok((_, cookie)) => {
            let mut response = Redirect::to(if panel.local.is_some() {
                "/local"
            } else {
                "/projects"
            })
            .into_response();
            match HeaderValue::from_str(&cookie) {
                Ok(cookie) => {
                    response.headers_mut().insert(header::SET_COOKIE, cookie);
                    response
                }
                Err(_) => auth_error(AuthError::Unavailable),
            }
        }
        Err(e) => auth_error(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Logout {
    csrf: String,
}

async fn logout(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Form(request): Form<Logout>,
) -> Response {
    let identity = match identity(&panel, &headers) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match panel
        .authentication
        .logout(token(&headers), &identity, &request.csrf)
    {
        Ok(()) => {
            let mut response = Redirect::to("/login").into_response();
            response.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_static(
                    "archcert_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
                ),
            );
            response
        }
        Err(e) => auth_error(e),
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    #[serde(default)]
    offset: u32,
    after: Option<String>,
}

async fn projects(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Response {
    let id = match identity(&panel, &headers) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let after = match page.after.map(|p| p.parse()).transpose() {
        Ok(after) => after,
        Err(_) => return error(StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
    };
    match panel.query.projects(&id.projects, after).await {
        Ok(projects) => {
            let after = if projects.len() == MAX_PAGE_SIZE {
                projects.last().map(|p| p.project.to_string())
            } else {
                None
            };
            html(
                &panel,
                "Projects",
                &render::projects(&projects, after),
                Some(&id),
            )
        }
        Err(e) => query_error(e),
    }
}

async fn overview(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(page): Query<Page>,
) -> Response {
    show_project(&panel, &headers, &project, "overview", None, page.offset).await
}

async fn project_view(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Path((project, section)): Path<(String, String)>,
    Query(page): Query<Page>,
) -> Response {
    show_project(&panel, &headers, &project, &section, None, page.offset).await
}

async fn entity_view(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Path((project, section, entity)): Path<(String, String, String)>,
    Query(page): Query<Page>,
) -> Response {
    show_project(
        &panel,
        &headers,
        &project,
        &section,
        Some(&entity),
        page.offset,
    )
    .await
}

async fn show_project(
    panel: &Panel,
    headers: &HeaderMap,
    project: &str,
    section: &str,
    entity: Option<&str>,
    offset: u32,
) -> Response {
    let id = match identity(panel, headers) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let project = match project_scope(panel, &id, project) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if section == "readiness"
        && let Some(invocation) = entity
    {
        return match panel.query.readiness(project, invocation).await {
            Ok(value) => {
                let mut body = render::readiness(&value);
                if panel.commands.is_some() {
                    body.push_str(&workflow::readiness_link(&value, id.role));
                }

                html(panel, "Release readiness", &body, Some(&id))
            }
            Err(e) => query_error(e),
        };
    }
    let snapshot = if let Some(entity) = entity {
        panel.query.entity(project, entity, offset).await
    } else {
        panel.query.snapshot(project, offset).await
    };

    match snapshot {
        Ok(snapshot) => match render::project(&snapshot, section, entity) {
            Some(mut body) => {
                if panel.commands.is_some() {
                    body.push_str(&workflow::links(&snapshot, section, entity, id.role));
                }
                html(panel, "Project observation", &body, Some(&id))
            }
            None => error(StatusCode::NOT_FOUND, "NOT_FOUND"),
        },
        Err(e) => query_error(e),
    }
}

async fn snapshot_api(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(page): Query<Page>,
) -> Response {
    let id = match identity(&panel, &headers) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let project = match project_scope(&panel, &id, &project) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    match panel.query.snapshot(project, page.offset).await {
        Ok(snapshot) => match serde_json::to_vec(&snapshot) {
            Ok(bytes) if bytes.len() <= 2 * 1024 * 1024 => {
                ([(header::CONTENT_TYPE, "application/json")], bytes).into_response()
            }
            _ => error(StatusCode::PAYLOAD_TOO_LARGE, "LIMIT_EXCEEDED"),
        },
        Err(e) => query_error(e),
    }
}

async fn readiness_api(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Path((project, invocation)): Path<(String, String)>,
) -> Response {
    let id = match identity(&panel, &headers) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let project = match project_scope(&panel, &id, &project) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    match panel.query.readiness(project, &invocation).await {
        Ok(value) => Json(value).into_response(),
        Err(e) => query_error(e),
    }
}

async fn evidence(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Path((project, entity, digest)): Path<(String, String, String)>,
    Query(page): Query<inspection::Page>,
) -> Response {
    let id = match identity(&panel, &headers) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let project = match project_scope(&panel, &id, &project) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if !page.valid() {
        return error(StatusCode::BAD_REQUEST, "INVALID_REQUEST");
    }

    match panel.query.evidence(project, &entity, &digest).await {
        Ok((item, bytes)) => html(
            &panel,
            "Evidence inspection",
            &render::evidence(&item, &bytes, project, &page),
            Some(&id),
        ),
        Err(e) => query_error(e),
    }
}

async fn download(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Path((project, entity, digest)): Path<(String, String, String)>,
) -> Response {
    let id = match identity(&panel, &headers) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let project = match project_scope(&panel, &id, &project) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    match panel.query.evidence(project, &entity, &digest).await {
        Ok((item, bytes)) => {
            if archcert_domain::Sha256Digest::parse(&item.sha256).is_err() {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "INFRASTRUCTURE_UNAVAILABLE",
                );
            }
            let mut response =
                ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response();
            if let Ok(value) =
                HeaderValue::from_str(&format!("attachment; filename=\"{}.bin\"", item.sha256))
            {
                response
                    .headers_mut()
                    .insert(header::CONTENT_DISPOSITION, value);
            }
            if let Ok(value) = HeaderValue::from_str(&item.sha256) {
                response.headers_mut().insert("x-content-sha256", value);
            }
            response
        }
        Err(e) => query_error(e),
    }
}

async fn audit(State(panel): State<Arc<Panel>>, headers: HeaderMap) -> Response {
    let id = match identity(&panel, &headers) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match panel.authentication.audit_page(&id) {
        Ok(records) => html(
            &panel,
            "Panel audit",
            &format!(
                "<section class=panel><h2>Append-only operational actions</h2><p>Most recent 50 records. Authority forensic events remain in each project timeline.</p><pre>{}</pre></section>",
                render::escape(&records)
            ),
            Some(&id),
        ),
        Err(e) => auth_error(e),
    }
}

async fn unsupported(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    if request.method() == Method::GET || request.method() == Method::HEAD {
        return error(StatusCode::NOT_FOUND, "NOT_FOUND");
    }
    let id = match identity(&panel, &headers) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match panel
        .authentication
        .audit(&id.id, "UNSUPPORTED_MUTATION_DENIED")
    {
        Ok(()) => error(StatusCode::FORBIDDEN, "FORBIDDEN"),
        Err(e) => auth_error(e),
    }
}

async fn health(State(panel): State<Arc<Panel>>) -> Response {
    if panel.query.healthy().await {
        (StatusCode::OK,Json(serde_json::json!({"panel":"HEALTHY","query_dependencies":"REACHABLE","release_authorization":"UNRELATED"}))).into_response()
    } else {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "INFRASTRUCTURE_UNAVAILABLE",
        )
    }
}

/// Outer executable HTTP router type; never enters application/domain.
pub type HttpRouter = Router;

/// Serve the already authenticated router on an externally bound loopback listener.
pub async fn serve(listener: tokio::net::TcpListener, router: HttpRouter) -> std::io::Result<()> {
    axum::serve(listener, router).await
}

fn local_identity(
    panel: &Panel,
    identity: &Identity,
) -> Result<archcert_application::local::LocalIdentity, AuthError> {
    let configuration = panel.authentication.configuration()?;
    let principal = configuration
        .principals
        .iter()
        .find(|p| p.id == identity.id)
        .ok_or(AuthError::Unauthenticated)?;
    Ok(archcert_application::local::LocalIdentity {
        principal: identity.id.clone(),
        generation: principal
            .grant_generation
            .clone()
            .ok_or(AuthError::Unauthenticated)?,
    })
}

async fn validate_local_session(panel: &Panel, headers: &HeaderMap) -> Result<(), AuthError> {
    let Some(local) = &panel.local else {
        return Ok(());
    };
    if token(headers).is_empty() {
        return Ok(());
    }
    let identity = match panel.authentication.authenticate(token(headers)) {
        Ok(identity) => identity,
        Err(AuthError::Unauthenticated) => return Ok(()),
        Err(error) => return Err(error),
    };
    let current = local_identity(panel, &identity)?;

    local
        .call(archcert_application::local::LocalRequest::Validate { identity: current })
        .await
        .map(|_| ())
        .map_err(|error| {
            if matches!(error, JobStoreError::Unauthorized) {
                AuthError::Unauthenticated
            } else {
                AuthError::Unavailable
            }
        })
}
