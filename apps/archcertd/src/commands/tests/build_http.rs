//! Build transport accepts only a versioned owned-job request, never build authority.

use super::*;

#[tokio::test]
async fn build_http_rejects_versions_posted_authority_and_ungranted_credentials() -> Result {
    let fixture = fixture(false).await?;
    let app = crate::router(fixture.state.clone());
    let mut build = fixture.body.clone();
    build["schema"] = serde_json::json!(3);
    build["action"] = serde_json::json!({
        "kind": "REQUEST_RELEASE_BUILD",
        "job": fixture.job,
    });

    for schema in [0, 1, 2, 4] {
        let mut body = build.clone();
        body["schema"] = serde_json::json!(schema);
        assert_eq!(
            app.clone()
                .oneshot(post(&body, Some(COMMAND_TOKEN), "wrong-schema")?)
                .await?
                .status(),
            StatusCode::BAD_REQUEST,
        );
    }

    for field in [
        "source",
        "certificate",
        "artifact",
        "permit",
        "recipe",
        "policy",
        "image",
        "limits",
        "signing_key",
        "actor",
        "shell",
        "verified",
        "invocation",
    ] {
        for nested in [false, true] {
            let mut body = build.clone();
            let object = if nested {
                &mut body["action"]
            } else {
                &mut body
            };
            object[field] = serde_json::json!("forged authority");
            assert_eq!(
                app.clone()
                    .oneshot(post(&body, Some(COMMAND_TOKEN), "posted-authority")?)
                    .await?
                    .status(),
                StatusCode::UNPROCESSABLE_ENTITY,
            );
        }
    }

    for token in [None, Some(LEGACY_TOKEN), Some(COMMAND_TOKEN)] {
        // Even the existing valid cancellation credential has no build grant.
        assert_eq!(
            app.clone()
                .oneshot(post(&build, token, "not-granted")?)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED,
        );
    }

    Ok(())
}
