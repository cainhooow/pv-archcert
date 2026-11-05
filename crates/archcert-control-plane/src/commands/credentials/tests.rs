use super::*;
use std::os::unix::fs::PermissionsExt;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const LEGACY_TOKEN: &str = "public-regression-legacy-credential-00000001";
const COMMAND_TOKEN: &str = "public-regression-command-credential-0000001";

fn fixture() -> Result<(ControlPlaneConfiguration, serde_json::Value)> {
    let grant = AuthorityGrant {
        project: ProjectId::new(),
        repository: RepositoryId::parse("fixture/commands")?,
        actor: GitActorId::parse(JobId::new().to_string())?,
        token_sha256: digest_bytes(LEGACY_TOKEN.as_bytes()),
        profile: "python".into(),
        image: format!("python@sha256:{}", "a".repeat(64)),
        authority_toml: include_str!("../../../../../docs/policy/CONTROLLED_AUTHORITY.toml").into(),
        maximum_attempts: 2,
        ironcrest: false,
        greywatch: false,
        semantic_request_bytes: None,
        ironcrest_baseline: None,
    };
    let credentials = serde_json::json!({
        "schema": 1,
        "principals": [{
            "scope": {
                "project": grant.project,
                "repository": grant.repository,
                "actor": grant.actor,
            },
            "token_sha256": digest_bytes(COMMAND_TOKEN.as_bytes()),
            "operations": ["REQUEST_CERTIFICATION", "CANCEL_ELIGIBLE_JOB"],
        }],
    });

    Ok((
        ControlPlaneConfiguration {
            source_store: "/unused".into(),
            artifact_root: "/unused".into(),
            grants: vec![grant],
        },
        credentials,
    ))
}

#[test]
fn command_credentials_cannot_authenticate_legacy_submission() -> Result {
    let (authority, value) = fixture()?;
    let credentials: CommandCredentials = serde_json::from_value(value.clone())?;
    let grant = &authority.grants[0];
    let authorization = credentials.authorize(
        &authority,
        COMMAND_TOKEN,
        grant.project,
        &grant.repository,
        ControlOperation::RequestCertification,
        None,
    )?;

    assert_eq!(authorization.scope().actor, grant.actor);
    assert!(matches!(
        authority.authenticate(COMMAND_TOKEN),
        Err(JobStoreError::Unauthorized)
    ));
    assert_eq!(authority.authenticate(LEGACY_TOKEN)?, grant.actor);
    assert!(matches!(
        credentials.authorize(
            &authority,
            LEGACY_TOKEN,
            grant.project,
            &grant.repository,
            ControlOperation::RequestCertification,
            None,
        ),
        Err(JobStoreError::Unauthorized)
    ));

    let mut substituted = value;
    substituted["principals"][0]["token_sha256"] = serde_json::to_value(&grant.token_sha256)?;
    let substituted: CommandCredentials = serde_json::from_value(substituted)?;
    assert!(matches!(
        substituted.validate(&authority),
        Err(JobStoreError::Invalid)
    ));

    Ok(())
}

#[test]
fn commands_authenticate_scope_operation_and_context_independently() -> Result {
    let (authority, value) = fixture()?;
    let credentials: CommandCredentials = serde_json::from_value(value)?;
    let grant = &authority.grants[0];
    let context = grant.command_context()?;
    let authorization = credentials.authorize(
        &authority,
        COMMAND_TOKEN,
        grant.project,
        &grant.repository,
        ControlOperation::CancelEligibleJob,
        Some(&context),
    )?;
    authorization.require(ControlOperation::CancelEligibleJob)?;
    assert!(matches!(
        authorization.require(ControlOperation::RequestCertification),
        Err(JobStoreError::Unauthorized)
    ));

    for token in [
        "",
        "short",
        "unknown-command-credential-value-000001",
        &"a".repeat(257),
    ] {
        assert!(matches!(
            credentials.authorize(
                &authority,
                token,
                grant.project,
                &grant.repository,
                ControlOperation::RequestCertification,
                None,
            ),
            Err(JobStoreError::Unauthorized)
        ));
    }
    for operation in [
        ControlOperation::RequestReleaseBuild,
        ControlOperation::RequestReleaseReadinessEvaluation,
        ControlOperation::RetryEligibleJob,
    ] {
        assert!(matches!(
            credentials.authorize(
                &authority,
                COMMAND_TOKEN,
                grant.project,
                &grant.repository,
                operation,
                None,
            ),
            Err(JobStoreError::Unauthorized)
        ));
    }
    assert!(matches!(
        credentials.authorize(
            &authority,
            COMMAND_TOKEN,
            ProjectId::new(),
            &grant.repository,
            ControlOperation::RequestCertification,
            None,
        ),
        Err(JobStoreError::Unauthorized)
    ));
    assert!(matches!(
        credentials.authorize(
            &authority,
            COMMAND_TOKEN,
            grant.project,
            &RepositoryId::parse("other/repository")?,
            ControlOperation::RequestCertification,
            None,
        ),
        Err(JobStoreError::Unauthorized)
    ));
    assert!(matches!(
        credentials.authorize(
            &authority,
            COMMAND_TOKEN,
            grant.project,
            &grant.repository,
            ControlOperation::RequestCertification,
            Some(&digest_bytes(b"foreign authority")),
        ),
        Err(JobStoreError::Precondition)
    ));

    Ok(())
}

#[test]
fn authority_context_excludes_credentials_but_binds_execution_selection() -> Result {
    let (authority, _) = fixture()?;
    let original = authority.grants[0].command_context()?;
    let mut rotated = authority.grants[0].clone();
    rotated.token_sha256 = digest_bytes(b"rotated legacy credential");
    assert_eq!(rotated.command_context()?, original);

    for change in 0..4 {
        let mut changed = rotated.clone();
        match change {
            0 => changed.maximum_attempts = 1,
            1 => changed.image = format!("python@sha256:{}", "b".repeat(64)),
            2 => changed.actor = GitActorId::parse(JobId::new().to_string())?,
            _ => changed.project = ProjectId::new(),
        }
        assert_ne!(changed.command_context()?, original);
    }

    let mut reviewed = rotated;
    reviewed.ironcrest = true;
    let reviewed_context = reviewed.command_context()?;
    assert_ne!(reviewed_context, original);
    reviewed.greywatch = true;
    assert_ne!(reviewed.command_context()?, reviewed_context);
    let greywatch_context = reviewed.command_context()?;
    reviewed.ironcrest_baseline = Some(SourceSubmissionId::new());
    assert_ne!(reviewed.command_context()?, greywatch_context);

    Ok(())
}

#[test]
fn command_configuration_rejects_ambient_authority_and_ambiguous_principals() -> Result {
    let (authority, value) = fixture()?;
    for operations in [
        serde_json::json!([]),
        serde_json::json!(["SIGN_CERTIFICATE"]),
        serde_json::json!(["CANCEL_ELIGIBLE_JOB", "CANCEL_ELIGIBLE_JOB"]),
    ] {
        let mut changed = value.clone();
        changed["principals"][0]["operations"] = operations;
        if let Ok(credentials) = serde_json::from_value::<CommandCredentials>(changed) {
            assert!(credentials.validate(&authority).is_err());
        }
    }
    for field in ["role", "shell", "signing_key", "authority_toml"] {
        let mut changed = value.clone();
        changed["principals"][0][field] = serde_json::json!("administrator");
        assert!(serde_json::from_value::<CommandCredentials>(changed).is_err());
    }
    let mut duplicated = value.clone();
    let duplicate = duplicated["principals"][0].clone();
    duplicated["principals"]
        .as_array_mut()
        .ok_or("missing principals")?
        .push(duplicate);
    assert!(
        serde_json::from_value::<CommandCredentials>(duplicated)?
            .validate(&authority)
            .is_err()
    );

    let mut wrong_actor = value;
    wrong_actor["principals"][0]["scope"]["actor"] =
        serde_json::to_value(GitActorId::parse(JobId::new().to_string())?)?;
    assert!(
        serde_json::from_value::<CommandCredentials>(wrong_actor)?
            .validate(&authority)
            .is_err()
    );

    Ok(())
}

#[test]
fn private_reload_revokes_operations_and_rejects_public_or_symlinked_credentials() -> Result {
    let (authority, mut value) = fixture()?;
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let root = root.path().canonicalize()?;
    let path = root.join("commands.json");
    std::fs::write(&path, serde_json::to_vec(&value)?)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let grant = &authority.grants[0];
    CommandCredentials::load(&path, &authority)?.authorize(
        &authority,
        COMMAND_TOKEN,
        grant.project,
        &grant.repository,
        ControlOperation::CancelEligibleJob,
        None,
    )?;

    value["principals"][0]["operations"] = serde_json::json!(["REQUEST_CERTIFICATION"]);
    std::fs::write(&path, serde_json::to_vec(&value)?)?;
    let reloaded = CommandCredentials::load(&path, &authority)?;
    assert!(matches!(
        reloaded.authorize(
            &authority,
            COMMAND_TOKEN,
            grant.project,
            &grant.repository,
            ControlOperation::CancelEligibleJob,
            None,
        ),
        Err(JobStoreError::Unauthorized)
    ));
    reloaded.authorize(
        &authority,
        COMMAND_TOKEN,
        grant.project,
        &grant.repository,
        ControlOperation::RequestCertification,
        None,
    )?;

    let link = root.join("link.json");
    std::os::unix::fs::symlink(&path, &link)?;
    assert!(CommandCredentials::load(&link, &authority).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(CommandCredentials::load(&path, &authority).is_err());

    Ok(())
}
