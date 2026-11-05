//! HTTP role/object/CSRF boundaries and historical rendering, without a crypto claim.

use super::*;

#[tokio::test]
async fn readiness_question_and_historical_receipt_keep_live_confirmation_separate() -> R {
    let broker = Arc::new(RecordingBroker::default());
    let fixture = Fixture::configured(Role::Operator, Some(broker.clone()), false)?;
    let cookie = fixture.login().await?;
    let csrf = csrf(&fixture, &cookie).await?;
    let live = format!(
        "/projects/{}/readiness/{WORKFLOW_INVOCATION}",
        fixture.project
    );
    let form = format!(
        "/projects/{}/commands/new?operation=REQUEST_RELEASE_READINESS_EVALUATION&target=RELEASE&entity={WORKFLOW_INVOCATION}",
        fixture.project,
    );

    let response = fixture
        .request("GET", &live, Some(&cookie), None, String::new())
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let live_body = body(response).await?;
    assert!(live_body.contains("data-readiness"));
    assert!(live_body.contains("Request readiness observation"));
    let response = fixture
        .request("GET", &form, Some(&cookie), None, String::new())
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let form_body = body(response).await?;
    assert!(form_body.contains("historical observation"));
    assert!(form_body.contains(WORKFLOW_INVOCATION));
    assert!(form_body.contains("name=\"idempotency\""));
    assert!(!form_body.contains("name=\"artifact\""));
    assert!(!form_body.contains("name=\"readiness\""));

    let response = fixture
        .request(
            "POST",
            &format!("/projects/{}/commands", fixture.project),
            Some(&cookie),
            Some(ORIGIN),
            command_form(ControlOperation::RequestReleaseReadinessEvaluation, &csrf),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let receipt_url = response.headers()[header::LOCATION].to_str()?.to_owned();
    for _ in 0..2 {
        let response = fixture
            .request("GET", &receipt_url, Some(&cookie), None, String::new())
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let receipt = body(response).await?;
        assert!(receipt.contains("HISTORICAL_OBSERVATION"));
        assert!(receipt.contains("Historical readiness observation: RELEASE_ALLOWED"));
        assert!(receipt.contains("data-historical-readiness"));
        assert!(!receipt.contains("data-readiness"));
        assert!(!receipt.contains("data-check-url"));
        assert!(receipt.contains(&live));
        assert!(receipt.contains(digest_bytes(b"metadata artifact").as_str()));
        assert!(receipt.contains(digest_bytes(b"metadata permit").as_str()));
    }
    assert_eq!(broker.receipt_reads.load(Ordering::Relaxed), 2);
    let submissions = broker.submissions.lock().map_err(|_| "broker lock")?;
    assert_eq!(submissions.len(), 1);
    assert!(matches!(
        &submissions[0].1.action,
        RequestedJobAction::RequestReleaseReadinessEvaluation { invocation }
            if invocation.0.as_str() == WORKFLOW_INVOCATION
    ));

    Ok(())
}

#[tokio::test]
async fn readiness_csrf_posted_facts_and_scope_fail_before_broker_submission() -> R {
    let broker = Arc::new(RecordingBroker::default());
    let fixture = Fixture::configured(Role::Operator, Some(broker.clone()), false)?;
    let cookie = fixture.login().await?;
    let csrf = csrf(&fixture, &cookie).await?;
    let path = format!("/projects/{}/commands", fixture.project);
    let valid = command_form(ControlOperation::RequestReleaseReadinessEvaluation, &csrf);

    for origin in [None, Some("https://attacker.invalid")] {
        assert_eq!(
            fixture
                .request("POST", &path, Some(&cookie), origin, valid.clone())
                .await?
                .status(),
            StatusCode::FORBIDDEN,
        );
    }
    for (forged, expected) in [
        (valid.replace(&csrf, "wrong-csrf"), StatusCode::FORBIDDEN),
        (
            valid.replace("workflow/fixture", "other/repository"),
            StatusCode::NOT_FOUND,
        ),
        (
            valid.replace(WORKFLOW_INVOCATION, &"b".repeat(64)),
            StatusCode::NOT_FOUND,
        ),
        (
            valid.replace("target=RELEASE", "target=JOB"),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("{valid}&readiness=RELEASE_ALLOWED"),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("{valid}&artifact={}", "c".repeat(64)),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("{valid}&attempt={WORKFLOW_ATTEMPT}"),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            fixture
                .request("POST", &path, Some(&cookie), Some(ORIGIN), forged)
                .await?
                .status(),
            expected,
        );
    }
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
async fn readiness_role_revocation_during_passive_lookup_denies_publication() -> R {
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
            command_form(ControlOperation::RequestReleaseReadinessEvaluation, &csrf),
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
