//! Owned project admission and exact Northgate source resolution.

use super::*;
use archcert_application::jobs::JobStoreError;
use archcert_control_plane::{AuthorityGrant, ControlPlane, ControlPlaneConfiguration};
use archcert_domain::{
    ProjectId, ingress::SourceSubmissionId, jobs::IdempotencyKey, source::RepositoryId,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use sqlx::Row;

fn public_key(value: &str) -> Result<(String, String)> {
    ensure!(
        value.len() <= 256 && !value.contains(['\n', '\r']),
        "INVALID_REQUEST"
    );
    let fields: Vec<_> = value.split_whitespace().collect();
    ensure!(
        fields.len() >= 2 && fields[0] == "ssh-ed25519",
        "INVALID_REQUEST"
    );
    let bytes = STANDARD.decode(fields[1]).map_err(|_| invalid())?;
    ensure!(
        bytes.len() == 51 && bytes[..19] == *b"\0\0\0\x0bssh-ed25519\0\0\0\x20",
        "INVALID_REQUEST"
    );
    Ok((
        format!("ssh-ed25519 {}", STANDARD.encode(&bytes)),
        digest_bytes(&bytes).as_str().into(),
    ))
}

pub(super) struct ProjectRegistration {
    pub name: String,
    pub description: String,
    pub repository: String,
    pub public_key: String,
    pub request_key: String,
}

impl Service {
    pub(super) async fn create_project(
        &self,
        identity: LocalIdentity,
        registration: ProjectRegistration,
    ) -> Result<Value> {
        let ProjectRegistration {
            name,
            description,
            repository,
            public_key: key,
            request_key,
        } = registration;

        ensure!(
            self.validate(&identity).await? == "ADMINISTRATOR",
            "UNAUTHORIZED"
        );
        ensure!(self.config.image.is_some(), "CONFIGURATION_REQUIRED");
        ensure!(
            !name.trim().is_empty()
                && name.len() <= 100
                && description.len() <= 2000
                && !name.chars().any(char::is_control)
                && !description.chars().any(|c| c.is_control() && c != '\n'),
            "INVALID_REQUEST"
        );
        RepositoryId::parse(repository.clone()).map_err(|_| invalid())?;
        ensure!(
            repository.len() <= 128
                && repository
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b)),
            "INVALID_REQUEST"
        );
        let (key, device) = public_key(&key)?;
        uuid::Uuid::parse_str(&request_key).map_err(|_| invalid())?;
        let id = ProjectId::new().to_string();
        let actor = uuid::Uuid::new_v4().to_string();

        let mut tx = self.pool.begin().await?;
        // Serializes local provisioning and rechecks current privileges under the lock.
        sqlx::query("SELECT singleton FROM local_instance FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
        let authorized: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM local_accounts WHERE id=$1 AND generation=$2 AND enabled AND role='ADMINISTRATOR')")
            .bind(&identity.principal)
            .bind(&identity.generation)
            .fetch_one(&mut *tx)
            .await?;
        ensure!(authorized, "UNAUTHORIZED");
        let existing =
            sqlx::query("SELECT * FROM local_projects WHERE owner=$1 AND request_key=$2")
                .bind(&identity.principal)
                .bind(&request_key)
                .fetch_optional(&mut *tx)
                .await?;
        let project = if let Some(row) = existing {
            ensure!(
                row.try_get::<String, _>("name")? == name.trim()
                    && row.try_get::<String, _>("description")? == description
                    && row.try_get::<String, _>("repository")? == repository
                    && row.try_get::<String, _>("public_key")? == key,
                "CONFLICT"
            );
            row.try_get::<String, _>("id")?
        } else {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM local_projects")
                .fetch_one(&mut *tx)
                .await?;
            ensure!(count < 16, "CONFIGURATION_REQUIRED");
            let duplicate: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM local_projects WHERE repository=$1 OR device=$2)",
            )
            .bind(&repository)
            .bind(&device)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(!duplicate, "CONFLICT");
            sqlx::query("INSERT INTO local_projects(id,owner,name,description,repository,public_key,device,actor,request_key,legacy_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
                .bind(&id)
                .bind(&identity.principal)
                .bind(name.trim())
                .bind(description)
                .bind(&repository)
                .bind(key)
                .bind(device)
                .bind(&actor)
                .bind(request_key)
                .bind(digest_bytes(entropy()?.as_bytes()).as_str())
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "INSERT INTO repository_grants(project,repository,actor) VALUES ($1,$2,$3)",
            )
            .bind(&id)
            .bind(&repository)
            .bind(actor)
            .execute(&mut *tx)
            .await?;
            audit(
                &mut tx,
                &identity.principal,
                "PROJECT_AND_REPOSITORY_REGISTERED",
                &id,
            )
            .await?;
            id
        };
        sqlx::query("UPDATE local_instance SET projection_pending=true WHERE singleton")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        self.publish().await?;
        Ok(json!({"project":project,"login_required":true}))
    }

    pub(super) async fn certify(
        &self,
        identity: LocalIdentity,
        project: String,
        submission: String,
        request_key: String,
    ) -> Result<Value> {
        let role = self.validate(&identity).await?;
        ensure!(
            ["ADMINISTRATOR", "OPERATOR"].contains(&role.as_str()),
            "UNAUTHORIZED"
        );
        let row = sqlx::query("SELECT * FROM local_projects WHERE id=$1 AND owner=$2")
            .bind(&project)
            .bind(&identity.principal)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| anyhow::anyhow!("UNAUTHORIZED"))?;
        let grant = self.grant(&row)?;
        let control = ControlPlane::connect(
            &std::env::var("ARCHCERT_DATABASE_URL")?,
            ControlPlaneConfiguration {
                source_store: self.config.root.join("sources"),
                artifact_root: self.config.root.join("artifacts"),
                grants: vec![grant.clone()],
            },
        )
        .await?;
        let job = control
            .submit(
                grant.actor,
                project.parse()?,
                grant.repository,
                SourceSubmissionId::parse(&submission)?,
                IdempotencyKey::parse(request_key)?,
            )
            .await
            .map_err(|e| match e {
                JobStoreError::Conflict => anyhow::anyhow!("CONFLICT"),
                JobStoreError::Unauthorized => anyhow::anyhow!("UNAUTHORIZED"),
                _ => anyhow::anyhow!("certification admission unavailable"),
            })?;
        Ok(json!({
            "job": job.id.to_string(),
            "project": project,
            "state": job.state,
        }))
    }

    pub(super) fn grant(&self, row: &sqlx::postgres::PgRow) -> Result<AuthorityGrant> {
        Ok(AuthorityGrant {
            project: row.try_get::<String, _>("id")?.parse()?,
            repository: RepositoryId::parse(row.try_get::<String, _>("repository")?)?,
            actor: archcert_domain::ingress::GitActorId::parse(row.try_get::<String, _>("actor")?)?,
            token_sha256: archcert_domain::Sha256Digest::parse(
                row.try_get::<String, _>("legacy_hash")?,
            )?,
            profile: "python".into(),
            image: self
                .config
                .image
                .clone()
                .ok_or_else(|| anyhow::anyhow!("CONFIGURATION_REQUIRED"))?,
            authority_toml: self.config.authority_toml.clone(),
            maximum_attempts: 1,
            ironcrest: false,
            greywatch: false,
            semantic_request_bytes: None,
            ironcrest_baseline: None,
            release_build: None,
        })
    }

    pub(super) async fn projects(&self, identity: &LocalIdentity) -> Result<Value> {
        let rows = sqlx::query("SELECT * FROM local_projects WHERE owner=$1 ORDER BY id LIMIT 16")
            .bind(&identity.principal)
            .fetch_all(&self.pool)
            .await?;
        let reader =
            archcert_gateway::AcceptedSubmissionReader::open(&self.config.root.join("sources"))?;
        let mut projects = Vec::new();
        for row in rows {
            let id: String = row.try_get("id")?;
            let repository: String = row.try_get("repository")?;
            let mut sources = Vec::new();
            for entry in std::fs::read_dir(self.config.root.join("sources"))?.take(33) {
                let entry = entry?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let Ok(submission) = SourceSubmissionId::parse(&name) else {
                    continue;
                };
                let Ok(accepted) = reader.load(&submission) else {
                    continue;
                };
                if accepted.snapshot.project().to_string() == id
                    && accepted.snapshot.repository().as_str() == repository
                {
                    sources.push(json!({
                        "submission": name,
                        "source": accepted.snapshot.identity(),
                        "completeness": accepted.snapshot.status(),
                    }));
                }
            }
            sources.sort_by(|a, b| a["submission"].as_str().cmp(&b["submission"].as_str()));
            projects.push(json!({
                "id": id,
                "name": row.try_get::<String,_>("name")?,
                "description": row.try_get::<String,_>("description")?,
                "repository": repository,
                "remote": format!("{}@127.0.0.1:projects/{}.git", self.config.ssh_user, id),
                "sources": sources,
            }));
        }
        Ok(json!({"projects":projects}))
    }
}
