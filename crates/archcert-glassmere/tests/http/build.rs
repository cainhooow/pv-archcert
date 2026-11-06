//! Presentation-only fixtures: no signature, execution or build proof is produced.

use super::*;

#[tokio::test]
async fn build_form_and_retained_receipt_distinguish_admission_from_release_readiness() -> R {
    let broker = Arc::new(RecordingBroker::default());
    let fixture = Fixture::configured(Role::Operator, Some(broker.clone()), false)?;
    let cookie = fixture.login().await?;
    let csrf = csrf(&fixture, &cookie).await?;
    let form = format!(
        "/projects/{}/commands/new?operation=REQUEST_RELEASE_BUILD&target=JOB&entity={WORKFLOW_COMPLETED}",
        fixture.project,
    );

    let response = fixture
        .request("GET", &form, Some(&cookie), None, String::new())
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body(response).await?;
    assert!(html.contains("name=\"entity\" value=\"10000000-0000-4000-8000-000000000006\""));
    assert!(html.contains("Admission does not mean builds succeeded"));
    for field in [
        "certificate",
        "recipe",
        "image",
        "signing_key",
        "source",
        "invocation",
    ] {
        assert!(!html.contains(&format!("name=\"{field}\"")));
    }

    let response = fixture
        .request(
            "POST",
            &format!("/projects/{}/commands", fixture.project),
            Some(&cookie),
            Some(ORIGIN),
            command_form(ControlOperation::RequestReleaseBuild, &csrf),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()[header::LOCATION].to_str()?.to_owned();
    for _ in 0..2 {
        let response = fixture
            .request("GET", &location, Some(&cookie), None, String::new())
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let html = body(response).await?;
        assert!(html.contains("Build workflow admitted"));
        assert!(html.contains("This receipt establishes admission only"));
        assert!(html.contains(digest_bytes(b"metadata build invocation").as_str()));
        assert!(!html.contains("data-readiness"));
        assert!(!html.contains("data-check-url"));
        assert!(!html.contains("RELEASE_ALLOWED"));
    }
    assert_eq!(broker.receipt_reads.load(Ordering::Relaxed), 2);
    let submissions = broker.submissions.lock().map_err(|_| "broker lock")?;
    assert_eq!(submissions.len(), 1);
    assert!(matches!(
        &submissions[0].1.action,
        RequestedJobAction::RequestReleaseBuild { job } if job.to_string() == WORKFLOW_COMPLETED
    ));

    Ok(())
}

#[tokio::test]
async fn build_csrf_target_scope_and_authority_overrides_fail_before_broker_submission() -> R {
    let broker = Arc::new(RecordingBroker::default());
    let fixture = Fixture::configured(Role::Operator, Some(broker.clone()), false)?;
    let cookie = fixture.login().await?;
    let csrf = csrf(&fixture, &cookie).await?;
    let path = format!("/projects/{}/commands", fixture.project);
    let valid = command_form(ControlOperation::RequestReleaseBuild, &csrf);

    for origin in [None, Some("https://attacker.invalid")] {
        assert_eq!(
            fixture
                .request("POST", &path, Some(&cookie), origin, valid.clone())
                .await?
                .status(),
            StatusCode::FORBIDDEN,
        );
    }
    for (body, expected) in [
        (valid.replace(&csrf, "wrong-csrf"), StatusCode::FORBIDDEN),
        (
            valid.replace("workflow/fixture", "other/repository"),
            StatusCode::NOT_FOUND,
        ),
        (
            valid.replace(WORKFLOW_COMPLETED, WORKFLOW_SOURCE),
            StatusCode::NOT_FOUND,
        ),
        (
            valid.replace("target=JOB", "target=SOURCE"),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("{valid}&attempt={WORKFLOW_ATTEMPT}"),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            fixture
                .request("POST", &path, Some(&cookie), Some(ORIGIN), body)
                .await?
                .status(),
            expected,
        );
    }
    for field in [
        "source",
        "certificate",
        "recipe",
        "image",
        "limits",
        "signing_key",
        "actor",
        "role",
        "shell",
        "invocation",
    ] {
        assert_eq!(
            fixture
                .request(
                    "POST",
                    &path,
                    Some(&cookie),
                    Some(ORIGIN),
                    format!("{valid}&{field}=forged")
                )
                .await?
                .status(),
            StatusCode::BAD_REQUEST,
        );
    }
    let other = format!("/projects/{}/commands", ProjectId::new());
    assert_eq!(
        fixture
            .request("POST", &other, Some(&cookie), Some(ORIGIN), valid)
            .await?
            .status(),
        StatusCode::NOT_FOUND,
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
async fn build_submission_rechecks_role_revocation_after_passive_lookup() -> R {
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
            command_form(ControlOperation::RequestReleaseBuild, &csrf),
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
