//! Direct forged HTTP requests exercise server-side authorization independently of UI.

use archcert_application::{glassmere::*, jobs::JobStoreError};
use archcert_domain::{ProjectId, source::digest_bytes};
use archcert_glassmere::{auth::*, router};
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, Response, StatusCode, header},
};
use http_body_util::BodyExt;
use std::{os::unix::fs::PermissionsExt, sync::Arc};
use tower::ServiceExt;

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ORIGIN: &str = "http://127.0.0.1:8090";
const HOSTILE: &str = "<script>alert(1)</script><img src=x onerror=alert(1)>";
const DEEP_JOB: &str = "10000000-0000-4000-8000-000000000099";

struct QueryFixture {
    project: ProjectId,
}

#[async_trait]
impl GlassmereQuery for QueryFixture {
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
        Ok(ProjectSnapshot {
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
        })
    }

    async fn readiness(&self, _: ProjectId, _: &str) -> Result<ReleaseReadiness, JobStoreError> {
        Err(JobStoreError::Precondition)
    }

    async fn entity(
        &self,
        project: ProjectId,
        entity: &str,
        offset: u32,
    ) -> Result<ProjectSnapshot, JobStoreError> {
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
            }],
            audit_path: root.path().join("audit.jsonl"),
        };
        let path = root.path().join("panel.json");
        std::fs::write(&path, serde_json::to_vec(&configuration)?)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let app =
            router(Arc::new(QueryFixture { project }), path).map_err(|_| "router configuration")?;

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
