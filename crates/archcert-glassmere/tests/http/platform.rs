//! Setup rejection presentation; durable bootstrap is tested against PostgreSQL.

use super::*;
use archcert_application::platform::{Platform, PlatformReply, PlatformRequest};

struct RejectedSetup {
    failure: Mutex<Option<JobStoreError>>,
}

#[async_trait]
impl Platform for RejectedSetup {
    async fn call(&self, request: PlatformRequest) -> Result<PlatformReply, JobStoreError> {
        match request {
            PlatformRequest::Status => Ok(PlatformReply {
                state: "INITIALIZED".into(),
                details: serde_json::json!({}),
                credential: None,
            }),
            PlatformRequest::Setup { .. } => {
                let mut failure = self
                    .failure
                    .lock()
                    .map_err(|_| JobStoreError::Unavailable)?;
                Err(failure.take().unwrap_or(JobStoreError::Unavailable))
            }
            _ => Err(JobStoreError::Unauthorized),
        }
    }
}

#[tokio::test]
async fn setup_rejection_explains_recovery_without_echoing_secrets_or_reopening_setup() -> R {
    let secret = "a".repeat(64);
    let password = "private test password";

    for (failure, expected, guidance) in [
        (
            JobStoreError::Unauthorized,
            StatusCode::UNAUTHORIZED,
            "The setup secret is invalid or expired",
        ),
        (
            JobStoreError::Conflict,
            StatusCode::CONFLICT,
            "Another registration request",
        ),
    ] {
        let mut fixture = Fixture::new(Role::Viewer)?;
        fixture.app = archcert_glassmere::router_with_platform(
            Arc::new(QueryFixture {
                project: fixture.project,
                workflow: false,
                revoke_on_entity: None,
            }),
            fixture.root.path().join("panel.json"),
            Arc::new(RejectedSetup {
                failure: Mutex::new(Some(failure)),
            }),
        )
        .map_err(|_| "router configuration")?;

        let response = fixture
            .request(
                "POST",
                "/setup",
                None,
                Some(ORIGIN),
                format!(
                    "secret={secret}&display_name=Operator&email=operator%40example.com&password={password}&confirmation={password}"
                ),
            )
            .await?;
        assert_eq!(response.status(), expected);
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()?
                .starts_with("text/html")
        );
        assert!(!response.headers().contains_key(header::SET_COOKIE));

        let rendered = body(response).await?;
        assert!(rendered.contains(guidance));
        assert!(rendered.contains("role=alert"));
        assert!(rendered.contains("href=/setup"));
        assert!(rendered.contains("href=/login"));
        assert!(!rendered.contains(&secret));
        assert!(!rendered.contains(password));
        assert!(!rendered.contains("<form"));

        let closed = fixture
            .request("GET", "/setup", None, None, String::new())
            .await?;
        assert_eq!(closed.status(), StatusCode::GONE);
        assert!(!body(closed).await?.contains("name=password"));
    }

    Ok(())
}
