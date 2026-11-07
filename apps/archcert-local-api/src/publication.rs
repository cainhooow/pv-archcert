//! Rebuildable private projections; durable identities remain in PostgreSQL.

use super::*;
use serde_json::Value;
use sqlx::Row;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

pub(super) fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(invalid)?;
    let temporary = parent.join(format!(".publish-{}", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

impl Service {
    pub(super) async fn publish(&self) -> Result<()> {
        let _lock = self.publication.lock().await;
        // A database advisory transaction lock also serializes host recovery processes.
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(714322881)")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT singleton FROM local_instance FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;

        let accounts = sqlx::query("SELECT * FROM local_accounts WHERE enabled ORDER BY id")
            .fetch_all(&mut *tx)
            .await?;
        let projects = sqlx::query("SELECT * FROM local_projects ORDER BY id")
            .fetch_all(&mut *tx)
            .await?;
        let mut principals = Vec::new();
        for account in &accounts {
            let id: String = account.try_get("id")?;
            let owned: Vec<String> = projects
                .iter()
                .filter(|p| p.try_get::<String, _>("owner").is_ok_and(|o| o == id))
                .map(|p| p.try_get("id"))
                .collect::<std::result::Result<_, _>>()?;
            principals.push(json!({
                "id": id,
                "token_sha256": digest_bytes(account.try_get::<String,_>("panel_credential")?.as_bytes()),
                "role": account.try_get::<String,_>("role")?,
                "projects": owned,
                "grant_generation": account.try_get::<String,_>("generation")?,
            }));
        }
        if principals.is_empty() {
            // No known credential exists for this inert bootstrap-only projection.
            principals.push(json!({
                "id": "setup_pending",
                "token_sha256": digest_bytes(entropy()?.as_bytes()),
                "role": "VIEWER",
                "projects": [],
            }));
        }
        let panel = json!({
            "schema": 1,
            "origin": self.config.origin,
            "development_http": true,
            "demonstration_data": false,
            "principals": principals,
            "audit_path": self.config.root.join("audit/panel.jsonl"),
        });
        let mut grants = Vec::new();
        let mut devices = std::collections::BTreeMap::<String, Value>::new();
        let mut authorized = String::new();
        for project in &projects {
            let grant = self.grant(project)?;
            grants.push(json!({
                "project": grant.project,
                "repository": grant.repository,
                "actor": grant.actor,
                "token_sha256": grant.token_sha256,
                "profile": grant.profile,
                "image": grant.image,
                "authority_toml": grant.authority_toml,
                "maximum_attempts": grant.maximum_attempts,
            }));
            let device: String = project.try_get("device")?;
            // Each repository retains its own key and actor.
            ensure!(
                !devices.contains_key(&device),
                "one SSH key per local repository is required"
            );
            let owner: String = project.try_get("owner")?;
            let enabled = accounts.iter().any(|account| {
                account
                    .try_get::<String, _>("id")
                    .is_ok_and(|id| id == owner)
            });
            devices.insert(
                device.clone(),
                json!({
                    "actor": grant.actor,
                    "device": device,
                    "enabled": enabled,
                    "repositories": [{
                        "project": grant.project,
                        "repository": grant.repository,
                        "route": format!("projects/{}.git", grant.project),
                        "object_format": "sha1",
                    }],
                }),
            );
            let forced = format!(
                "'{}' receive --config '{}' --device-key {}",
                self.config.gateway_binary.display(),
                self.config.root.join("config/gateway.json").display(),
                device
            );
            ensure!(
                !forced.contains(['\n', '\r', '"', '\\']),
                "unsupported installation path"
            );
            authorized.push_str(&format!(
                "restrict,command=\"{forced}\" {}\n",
                project.try_get::<String, _>("public_key")?
            ));
        }
        let gateway = json!({
            "git_executable": "/usr/bin/git",
            "store": self.config.root.join("sources"),
            "devices": devices.values().collect::<Vec<_>>(),
            "pack_limits": {
                "max_pack_bytes": 67108864,
                "max_objects": 25000,
                "max_object_bytes": 9437184,
                "max_decoded_bytes": 268435456,
                "max_delta_depth": 32,
                "max_expansion_ratio": 4096,
            },
            "session_seconds": 30,
            "max_submissions": 32,
        });
        let control = json!({
            "source_store": self.config.root.join("sources"),
            "artifact_root": self.config.root.join("artifacts"),
            "grants": grants,
        });

        audit(
            &mut tx,
            "LOCAL_PROVISIONER",
            "PROJECTION_PUBLICATION_INTENT",
            &self.config.instance,
        )
        .await?;
        // Files are projections, never proof of a DB transition. Each request rechecks DB revision.
        for (name, value) in [
            ("panel.json", panel),
            ("gateway.json", gateway),
            ("control.json", control),
        ] {
            replace(
                &self.config.root.join("config").join(name),
                &serde_json::to_vec_pretty(&value)?,
            )?;
        }
        replace(
            &self.config.root.join("git/authorized_keys"),
            authorized.as_bytes(),
        )?;
        audit(
            &mut tx,
            "LOCAL_PROVISIONER",
            "PROJECTION_PUBLISHED",
            &self.config.instance,
        )
        .await?;
        sqlx::query("UPDATE local_instance SET projection_pending=false WHERE singleton")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}
