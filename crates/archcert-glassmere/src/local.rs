//! Local pilot screens through an independent identity/provisioning port.

use super::*;
use archcert_application::local::{LocalIdentity, LocalRequest};
use std::fmt::Write;

pub(super) fn routes(router: Router<Arc<Panel>>) -> Router<Arc<Panel>> {
    router
        .route("/local/login", post(login))
        .route("/setup", get(setup_page).post(setup))
        .route("/local", get(home))
        .route("/local/projects", post(create_project))
        .route("/local/certify", post(certify))
}

pub(super) async fn login_page(panel: &Panel) -> Response {
    let Some(local) = &panel.local else {
        return auth_error(AuthError::Unavailable);
    };
    match local.call(LocalRequest::Status).await {
        Ok(status) if status.state == "SETUP_PENDING" => Redirect::to("/setup").into_response(),
        Ok(status) if status.state == "INITIALIZED" => html(
            panel,
            "Local account",
            "<section class=login><h2>Sign in</h2><form method=post action=/local/login><label>Email<input name=email type=email required maxlength=254 autocomplete=username></label><label>Password<input name=password type=password required maxlength=128 autocomplete=current-password></label><button>Sign in</button></form><p>HttpOnly sessions expire after 30 minutes. Host-side account recovery is documented in the README.</p></section>",
            None,
        ),
        Ok(_) => html(
            panel,
            "RECOVERY_REQUIRED",
            "<p>Initialization is unavailable. Inspect the installation locally; account creation remains closed.</p>",
            None,
        ),
        Err(error) => query_error(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    email: String,
    password: String,
}

async fn login(State(panel): State<Arc<Panel>>, Form(form): Form<Login>) -> Response {
    let Some(local) = &panel.local else {
        return auth_error(AuthError::Unavailable);
    };
    match local
        .call(LocalRequest::Login {
            email: form.email,
            password: form.password,
        })
        .await
    {
        Ok(reply) => match reply.credential {
            Some(credential) => super::login_session(&panel, &credential),
            None => auth_error(AuthError::Unavailable),
        },
        Err(error) => query_error(error),
    }
}

async fn setup_page(State(panel): State<Arc<Panel>>) -> Response {
    let Some(local) = &panel.local else {
        return auth_error(AuthError::Unavailable);
    };
    match local.call(LocalRequest::Status).await {
        Ok(status) if status.state == "SETUP_PENDING" => html(
            &panel,
            "First-run setup",
            "<section class=login><h2>Create the initial administrator</h2><p>LOCAL SELF-HOSTED PILOT — DEVELOPMENT CERTIFICATION AUTHORITY</p><p>Read the single-use secret locally with scripts/archcert-local setup-secret. It expires after 30 minutes. Never put it in the URL.</p><form method=post action=/setup><label>Setup secret<input name=secret type=password required minlength=64 maxlength=64 autocomplete=off></label><label>Display name<input name=display_name required maxlength=100 autocomplete=name></label><label>Email<input name=email type=email required maxlength=254 autocomplete=username></label><label>Password<input name=password type=password required minlength=12 maxlength=128 autocomplete=new-password></label><label>Confirm password<input name=confirmation type=password required minlength=12 maxlength=128 autocomplete=new-password></label><button>Create administrator</button></form><p>At least 12 characters. This account grants local administration only. Signing, policy and runtime remain host-provisioned.</p></section>",
            None,
        ),
        Ok(_) => error(StatusCode::GONE, "SETUP_CLOSED"),
        Err(error) => query_error(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    secret: String,
    display_name: String,
    email: String,
    password: String,
    confirmation: String,
}

async fn setup(State(panel): State<Arc<Panel>>, Form(form): Form<Setup>) -> Response {
    let Some(local) = &panel.local else {
        return auth_error(AuthError::Unavailable);
    };
    match local
        .call(LocalRequest::Setup {
            secret: form.secret,
            display_name: form.display_name,
            email: form.email,
            password: form.password,
            confirmation: form.confirmation,
        })
        .await
    {
        Ok(_) => Redirect::to("/login").into_response(),
        Err(error) => query_error(error),
    }
}

fn authenticated(
    panel: &Panel,
    headers: &HeaderMap,
    csrf: Option<&str>,
) -> Result<(Identity, LocalIdentity), AccessError> {
    let id = identity(panel, headers)?;
    if let Some(csrf) = csrf {
        panel
            .authentication
            .check_csrf(&id, csrf)
            .map_err(AccessError::Authentication)?;
    }
    let local = local_identity(panel, &id).map_err(AccessError::Authentication)?;
    Ok((id, local))
}

async fn home(State(panel): State<Arc<Panel>>, headers: HeaderMap) -> Response {
    let Some(local) = &panel.local else {
        return auth_error(AuthError::Unavailable);
    };
    let status = match local.call(LocalRequest::Status).await {
        Ok(v) => v,
        Err(e) => return query_error(e),
    };
    if status.state == "SETUP_PENDING" {
        return Redirect::to("/setup").into_response();
    }
    if status.state != "INITIALIZED" {
        return error(StatusCode::SERVICE_UNAVAILABLE, "RECOVERY_REQUIRED");
    }
    let (id, current) = match authenticated(&panel, &headers, None) {
        Ok(v) => v,
        Err(_) => return Redirect::to("/login").into_response(),
    };
    let projects = local
        .call(LocalRequest::Projects { identity: current })
        .await;
    let csrf = render::escape(&id.csrf);
    let mut body = format!(
        "<p class=lede>LOCAL SELF-HOSTED PILOT — DEVELOPMENT CERTIFICATION AUTHORITY</p><p><a href=/local>Refresh infrastructure and accepted commits</a> · <a href=/projects>Evidence, jobs and certificates</a> · <a href=/audit>Panel audit</a></p><section class=panel><h2>1. Infrastructure and authority</h2><p>Host provisioning selects the execution profile and signing key. Administrator access does not select authority.</p><pre>{}</pre><p>Health is an observation at the recorded time. M6 local onboarding: UNSUPPORTED. Native qualification is not established by this installation.</p></section>",
        render::escape(&serde_json::to_string_pretty(&status.details).unwrap_or_default())
    );

    let projects = match projects {
        Ok(reply) => reply,
        Err(JobStoreError::Unavailable) => {
            body.push_str("<section class=panel><h2>Project catalog unavailable</h2><p>Project metadata is unavailable. Inspect the infrastructure states and private installation logs before registering or certifying sources.</p></section>");
            return html(&panel, "Local installation", &body, Some(&id));
        }
        Err(error) => return query_error(error),
    };

    if status.details["artifact_store"] == "ERROR" {
        body.push_str("<section class=panel><h2>Artifact store unavailable</h2><p>Certification admission requires the configured artifact store to be READY. Inspect the private storage permissions, availability and capacity before submitting a source.</p></section>");
    }

    if id.role == auth::Role::Administrator && status.details["profile"] != "CONFIGURATION_REQUIRED"
    {
        let key = match auth::random_credential() {
            Ok(value) => value,
            Err(error) => return auth_error(error),
        };
        let request_key = format!(
            "{}-{}-4{}-8{}-{}",
            &key[..8],
            &key[8..12],
            &key[13..16],
            &key[17..20],
            &key[20..32]
        );
        let _ = write!(
            body,
            "<section class=panel><h2>2. Create project and register Git</h2><p>The delegated profile is python-controlled-local-v1: authority-owned typecheck, test and build checks using checks.py. This bounded pilot supports up to 16 projects and 32 retained ingress sessions. Each repository needs its own Ed25519 public key. SHA-1 Git object format only in this local onboarding version. No remote clone, LFS download or submodule acquisition.</p><form method=post action=/local/projects><input type=hidden name=csrf value=\"{csrf}\"><input type=hidden name=request_key value=\"{request_key}\"><label>Project name<input name=name required maxlength=100></label><label>Description<textarea name=description maxlength=2000></textarea></label><label>Repository identifier<input name=repository required maxlength=128 placeholder=team/project></label><label>Ed25519 public key<input name=public_key required maxlength=256 placeholder=ssh-ed25519></label><button>Create project and register repository</button></form><p>After admission, log in again to acquire the new explicit project grant.</p></section>"
        );
    }
    if status.details["profile"] == "CONFIGURATION_REQUIRED" {
        body.push_str("<section class=panel><h2>2. Host authority configuration required</h2><p>Run scripts/archcert-local configure-authority with an explicitly selected digest-pinned image. Development signing and a rootless runtime are separate explicit host operations documented in the README. Restart, then return here to create a project.</p></section>");
    }
    if let Some(projects) = projects.details["projects"].as_array() {
        for project in projects {
            let project_id = match project["id"]
                .as_str()
                .unwrap_or_default()
                .parse::<ProjectId>()
            {
                Ok(value) => value,
                Err(_) => return query_error(JobStoreError::Invalid),
            };
            let _ = write!(
                body,
                "<section class=panel><h2>{}</h2><p>{}</p><p>Repository: {}</p><p><a href=/projects/{project_id}>Open jobs, evidence and verified downloads</a></p><h3>3. Push an actual commit</h3><pre>git remote add archcert {}\ngit push archcert HEAD:refs/heads/candidate</pre><p>Use the host-pinned SSH configuration printed by scripts/archcert-local git-config. Every push creates a new immutable accepted submission; it never updates a certified branch.</p><h3>4. Certify an exact accepted source</h3>",
                render::escape(project["name"].as_str().unwrap_or_default()),
                render::escape(project["description"].as_str().unwrap_or_default()),
                render::escape(project["repository"].as_str().unwrap_or_default()),
                render::escape(project["remote"].as_str().unwrap_or_default())
            );
            if let Some(sources) = project["sources"].as_array() {
                if sources.is_empty() {
                    body.push_str(
                        "<p>No accepted source. Push through Northgate and refresh this page.</p>",
                    );
                }
                for source in sources {
                    let submission =
                        render::escape(source["submission"].as_str().unwrap_or_default());
                    let _ = write!(
                        body,
                        "<pre>{}</pre>",
                        render::escape(&serde_json::to_string_pretty(source).unwrap_or_default())
                    );
                    if matches!(id.role, auth::Role::Administrator | auth::Role::Operator)
                        && source["completeness"] == "COMPLETE"
                        && status.details["artifact_store"] == "READY"
                    {
                        let _ = write!(
                            body,
                            "<form method=post action=/local/certify><input type=hidden name=csrf value=\"{csrf}\"><input type=hidden name=project value=\"{project_id}\"><input type=hidden name=submission value=\"{submission}\"><input type=hidden name=request_key value=\"local-certify-{submission}\"><p>Authority: python-controlled-local-v1 / archcert-development-v1. Exact source above; target configuration cannot weaken checks.</p><button>Request certification of this exact source</button></form>"
                        );
                    }
                }
            }
            body.push_str("</section>");
        }
    }
    html(&panel, "Local installation", &body, Some(&id))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectForm {
    csrf: String,
    request_key: String,
    name: String,
    description: String,
    repository: String,
    public_key: String,
}

async fn create_project(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<ProjectForm>,
) -> Response {
    let (_, current) = match authenticated(&panel, &headers, Some(&form.csrf)) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let Some(local) = &panel.local else {
        return auth_error(AuthError::Unavailable);
    };
    match local
        .call(LocalRequest::CreateProject {
            identity: current,
            name: form.name,
            description: form.description,
            repository: form.repository,
            public_key: form.public_key,
            request_key: form.request_key,
        })
        .await
    {
        Ok(_) => Redirect::to("/login").into_response(),
        Err(e) => query_error(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertifyForm {
    csrf: String,
    request_key: String,
    project: String,
    submission: String,
}

async fn certify(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<CertifyForm>,
) -> Response {
    let (id, current) = match authenticated(&panel, &headers, Some(&form.csrf)) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let Some(local) = &panel.local else {
        return auth_error(AuthError::Unavailable);
    };
    let project = match project_scope(&panel, &id, &form.project) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match local
        .call(LocalRequest::Certify {
            identity: current,
            project: project.to_string(),
            submission: form.submission,
            request_key: form.request_key,
        })
        .await
    {
        Ok(reply) => {
            let job = reply.details["job"].as_str().unwrap_or_default();
            if archcert_domain::jobs::JobId::parse(job).is_err() {
                return auth_error(AuthError::Unavailable);
            }
            html(
                &panel,
                "REQUEST ACCEPTED",
                &format!(
                    "<p>Certification request admitted durably. This is not a passing verdict.</p><p><a href=/projects/{project}/jobs/{job}>Monitor job {job}</a></p><p><a href=/local>Return to local installation</a></p>"
                ),
                Some(&id),
            )
        }
        Err(e) => query_error(e),
    }
}
