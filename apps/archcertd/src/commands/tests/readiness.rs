//! The HTTP boundary accepts a question, never posted release verification facts.
//! Metadata-only admission here establishes no source proof or build qualification.

use super::*;
use archcert_application::release::*;
use archcert_domain::release::{BuildInvocationIdentity, CertifiedSourceIdentity};

async fn readiness_fixture(real: bool) -> Result<Fixture> {
    let mut fixture = fixture(real).await?;
    let mut credentials: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.credential_path)?)?;
    credentials["principals"][0]["operations"] =
        serde_json::json!(["REQUEST_RELEASE_READINESS_EVALUATION"]);
    std::fs::write(&fixture.credential_path, serde_json::to_vec(&credentials)?)?;

    let invocation = if real {
        let control = &fixture.state.control;
        let credentials =
            CommandCredentials::load(&fixture.credential_path, &control.configuration)?;
        control.provision_commands(&credentials).await?;
        let job = JobRepository::get(&control.repository, fixture.job).await?;
        let recipe = RustReleaseRecipe::new(
            BuildEnvironment {
                image: format!("authority/rust@sha256:{}", "a".repeat(64)),
                dependency_bundle_sha256: digest_bytes(b"HTTP metadata dependencies"),
                toolchain_sha256: digest_bytes(b"HTTP metadata toolchain"),
            },
            "fixture",
        )?;
        let input = BuildInputManifest {
            schema: 1,
            kind: "ARCHCERT_BUILD_INPUT".into(),
            certified_source: CertifiedSourceIdentity {
                project: job.inputs.project,
                repository: job.inputs.repository,
                source: job.inputs.source,
                certificate_sha256: digest_bytes(b"metadata certificate identity"),
            },
            recipe: recipe.description().clone(),
            recipe_identity: recipe.identity()?,
            environment_identity: recipe.environment_identity()?,
            source_policy_sha256: job.inputs.policy.sha256,
            source_authority_key_sha256: digest_bytes(b"metadata source key"),
            release_authority_key_sha256: digest_bytes(b"metadata release key"),
            release_policy: RELEASE_POLICY.into(),
            release_policy_sha256: release_policy_digest(),
        };
        let invocation = input.identity()?;
        ReleaseRepository::open(
            &control.repository,
            &ReleaseAdmission {
                input_reference: release_reference(&release_bytes(&input)?),
                input,
                submission: job.inputs.submission,
                actor: job.inputs.actor,
            },
        )
        .await?;

        invocation
    } else {
        BuildInvocationIdentity(digest_bytes(b"unregistered metadata invocation"))
    };
    fixture.body["schema"] = serde_json::json!(2);
    fixture.body["action"] = serde_json::json!({
        "kind": "REQUEST_RELEASE_READINESS_EVALUATION",
        "invocation": invocation,
    });

    Ok(fixture)
}

#[tokio::test]
async fn readiness_http_rejects_versions_facts_and_credentials_before_storage() -> Result {
    let fixture = readiness_fixture(false).await?;
    let app = crate::router(fixture.state.clone());

    for schema in [0, 1, 3] {
        let mut body = fixture.body.clone();
        body["schema"] = serde_json::json!(schema);
        assert_eq!(
            app.clone()
                .oneshot(post(&body, Some(COMMAND_TOKEN), "schema")?)
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
    }

    for token in [
        None,
        Some(LEGACY_TOKEN),
        Some("unknown-public-regression-token-00000001"),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(post(&fixture.body, token, "authentication")?)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    for field in [
        "source",
        "certificate",
        "artifact",
        "permit",
        "readiness",
        "policy",
        "recipe",
        "actor",
        "shell",
    ] {
        let mut body = fixture.body.clone();
        body["action"][field] = serde_json::json!("forged authority");
        assert_eq!(
            app.clone()
                .oneshot(post(&body, Some(COMMAND_TOKEN), "posted-fact")?)
                .await?
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    let mut body = fixture.body.clone();
    body["schema"] = serde_json::json!(1);
    body["action"] = serde_json::json!({
        "kind": "CANCEL_ELIGIBLE_JOB",
        "job": fixture.job,
    });
    assert_eq!(
        app.clone()
            .oneshot(post(&body, Some(COMMAND_TOKEN), "other-operation")?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    body["schema"] = serde_json::json!(2);
    assert_eq!(
        app.oneshot(post(&body, Some(COMMAND_TOKEN), "version-substitution")?)
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn readiness_http_retries_fresh_questions_and_historical_receipts_are_scoped() -> Result {
    let fixture = readiness_fixture(true).await?;
    let app = crate::router(fixture.state.clone());
    let query = format!(
        "project={}&repository=fixture/commands&operation=REQUEST_RELEASE_READINESS_EVALUATION&authority_context={}",
        fixture.body["project"].as_str().ok_or("project")?,
        fixture.body["authority_context"]
            .as_str()
            .ok_or("context")?,
    );
    let context = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .uri(format!("/api/v2/command-context?{query}"))
                .header("authorization", format!("Bearer {COMMAND_TOKEN}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(context.status(), StatusCode::OK);
    let context = json(context).await?;
    assert_eq!(context["schema"], 1);
    assert_eq!(context["requires_reviewed_session"], false);
    assert_eq!(
        context["authority_context"],
        fixture.body["authority_context"]
    );

    let (first, retry, fresh) = tokio::join!(
        app.clone().oneshot(post(
            &fixture.body,
            Some(COMMAND_TOKEN),
            "original-question"
        )?),
        app.clone().oneshot(post(
            &fixture.body,
            Some(COMMAND_TOKEN),
            "original-question"
        )?),
        app.clone()
            .oneshot(post(&fixture.body, Some(COMMAND_TOKEN), "fresh-question")?),
    );
    let mut receipts = Vec::new();
    for response in [first?, retry?, fresh?] {
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let receipt = json(response).await?;
        assert_eq!(receipt["schema"], 2);
        assert_eq!(receipt["observation_freshness"], "HISTORICAL_OBSERVATION");
        assert_eq!(receipt["state"], "REQUESTED");
        receipts.push(receipt);
    }
    assert_eq!(receipts[0]["command_id"], receipts[1]["command_id"]);
    assert_ne!(receipts[0]["command_id"], receipts[2]["command_id"]);

    let evaluator = ReadinessRequestEvaluator {
        commands: &fixture.state.control.repository,
        observer: None,
    };
    for _ in 0..2 {
        let assignment = ControlCommandRepository::claim(
            &fixture.state.control.repository,
            "readiness-http-dispatcher",
            30,
        )
        .await?
        .ok_or("readiness assignment")?;
        evaluator
            .evaluate(&assignment, &assignment.record.command.authority_context)
            .await?;
    }

    for index in [0, 2] {
        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(format!(
                        "/api/v2/commands/{}?{query}",
                        receipts[index]["command_id"].as_str().ok_or("id")?,
                    ))
                    .header("authorization", format!("Bearer {COMMAND_TOKEN}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let receipt = json(response).await?;
        assert_eq!(receipt["schema"], 2);
        assert_eq!(receipt["observation_freshness"], "HISTORICAL_OBSERVATION");
        assert_eq!(receipt["state"], "INCONCLUSIVE");
        assert_eq!(receipt["outcome"]["reason"], "INFRASTRUCTURE_UNAVAILABLE");
        let key = if index == 0 {
            "original-question"
        } else {
            "fresh-question"
        };
        let replay = app
            .clone()
            .oneshot(post(&fixture.body, Some(COMMAND_TOKEN), key)?)
            .await?;
        assert_eq!(replay.status(), StatusCode::ACCEPTED);
        assert_eq!(json(replay).await?, receipt);
    }

    let mut foreign = fixture.body.clone();
    foreign["action"]["invocation"] = serde_json::json!(digest_bytes(b"foreign invocation"));
    assert_eq!(
        app.clone()
            .oneshot(post(&foreign, Some(COMMAND_TOKEN), "foreign-invocation")?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    foreign["project"] = serde_json::to_value(ProjectId::new())?;
    assert_eq!(
        app.clone()
            .oneshot(post(&foreign, Some(COMMAND_TOKEN), "foreign-project")?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut credentials: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.credential_path)?)?;
    credentials["principals"][0]["operations"] = serde_json::json!(["CANCEL_ELIGIBLE_JOB"]);
    std::fs::write(&fixture.credential_path, serde_json::to_vec(&credentials)?)?;
    assert_eq!(
        app.oneshot(post(
            &fixture.body,
            Some(COMMAND_TOKEN),
            "revoked-operation"
        )?)
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );

    let counts: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM control_commands),
                (SELECT count(*) FROM control_command_keys),
                (SELECT count(*) FROM control_command_audit WHERE event='CommandInconclusive'),
                (SELECT count(*) FROM release_invocations WHERE claim_a IS NOT NULL OR claim_b IS NOT NULL),
                (SELECT count(*) FROM certification_jobs WHERE certificate IS NOT NULL)",
    )
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(counts, (2, 2, 2, 0, 0));
    assert_eq!(
        JobRepository::get(&fixture.state.control.repository, fixture.job)
            .await?
            .state,
        JobState::Queued
    );

    Ok(())
}
