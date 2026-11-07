//! Durable one-way bootstrap, password verification and account recovery.

use super::*;
use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use sqlx::Row;
use std::path::Path;

fn email(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    let pieces: Vec<_> = normalized.split('@').collect();
    ensure!(
        normalized.len() <= 254
            && pieces.len() == 2
            && !pieces[0].is_empty()
            && pieces[1].contains('.')
            && normalized.bytes().all(|b| b.is_ascii_graphic()),
        "INVALID_REQUEST"
    );
    Ok(normalized)
}

fn password_policy(password: &str, confirmation: &str) -> Result<()> {
    ensure!(
        password == confirmation
            && !password.trim().is_empty()
            && (12..=128).contains(&password.chars().count())
            && password.len() <= 512
            && !password.chars().any(char::is_control),
        "INVALID_REQUEST"
    );
    Ok(())
}

pub(super) fn password_hash(password: &str) -> Result<String> {
    let salt = SaltString::encode_b64(&hex::decode(&entropy()?[..32])?).map_err(|_| invalid())?;
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|_| invalid())?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| invalid())
}

impl Service {
    pub(super) async fn instance_state(&self) -> Result<String> {
        let migrated: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=11 AND success)",
        )
        .fetch_one(&self.pool)
        .await?;
        ensure!(migrated, "RECOVERY_REQUIRED");

        let row = sqlx::query(
            "SELECT instance,state,projection_pending FROM local_instance WHERE singleton",
        )
        .fetch_optional(&self.pool)
        .await?;
        let row = row.ok_or_else(|| anyhow::anyhow!("RECOVERY_REQUIRED"))?;
        ensure!(
            row.try_get::<String, _>("instance")? == self.config.instance,
            "RECOVERY_REQUIRED"
        );
        let state: String = row.try_get("state")?;
        if state == "INITIALIZED" && row.try_get::<bool, _>("projection_pending")? {
            return Ok("RECOVERY_REQUIRED".into());
        }
        Ok(state)
    }

    pub(super) async fn initialize(&self, renew: bool) -> Result<()> {
        let secret = entropy()?;
        let mut tx = self.pool.begin().await?;
        if !renew {
            sqlx::query("INSERT INTO local_instance(instance,state) VALUES ($1,'UNINITIALIZED')")
                .bind(&self.config.instance)
                .execute(&mut *tx)
                .await?;
        }
        let row =
            sqlx::query("SELECT instance,state FROM local_instance WHERE singleton FOR UPDATE")
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            row.try_get::<String, _>("instance")? == self.config.instance
                && ["UNINITIALIZED", "SETUP_PENDING"]
                    .contains(&row.try_get::<String, _>("state")?.as_str()),
            "setup is permanently closed"
        );
        publication::replace(
            &self.config.root.join("bootstrap/setup-secret"),
            secret.as_bytes(),
        )?;
        sqlx::query("UPDATE local_instance SET state='SETUP_PENDING',setup_hash=$1,setup_until=floor(extract(epoch FROM clock_timestamp()))+1800 WHERE singleton")
            .bind(digest_bytes(secret.as_bytes()).as_str())
            .execute(&mut *tx)
            .await?;
        audit(
            &mut tx,
            "HOST_OPERATOR",
            if renew {
                "SETUP_RENEWED"
            } else {
                "SETUP_PENDING"
            },
            &self.config.instance,
        )
        .await?;
        tx.commit().await?;
        self.publish().await
    }

    async fn budget(&self) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let used: i32 = sqlx::query_scalar("UPDATE local_login_budget SET used=CASE WHEN window_start <= clock_timestamp()-interval '1 minute' THEN 1 ELSE used+1 END,window_start=CASE WHEN window_start <= clock_timestamp()-interval '1 minute' THEN clock_timestamp() ELSE window_start END WHERE singleton RETURNING used")
            .fetch_one(&mut *tx).await?;
        audit(
            &mut tx,
            "UNKNOWN",
            "AUTHENTICATION_ATTEMPT",
            &self.config.instance,
        )
        .await?;
        tx.commit().await?;
        ensure!(used <= 20, "RATE_LIMITED");
        Ok(())
    }

    pub(super) async fn validate(&self, identity: &LocalIdentity) -> Result<String> {
        ensure!(
            self.instance_state().await? == "INITIALIZED",
            "UNAUTHORIZED"
        );
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM local_accounts WHERE id=$1 AND generation=$2 AND enabled",
        )
        .bind(&identity.principal)
        .bind(&identity.generation)
        .fetch_optional(&self.pool)
        .await?;
        role.ok_or_else(|| anyhow::anyhow!("UNAUTHORIZED"))
    }

    pub(super) async fn setup(
        &self,
        secret: String,
        display_name: String,
        address: String,
        password: String,
        confirmation: String,
    ) -> Result<()> {
        self.budget().await?;
        ensure!(
            self.instance_state().await? == "SETUP_PENDING",
            "UNAUTHORIZED"
        );
        ensure!(
            !display_name.trim().is_empty()
                && display_name.len() <= 100
                && !display_name.chars().any(char::is_control),
            "INVALID_REQUEST"
        );
        let address = email(&address)?;
        password_policy(&password, &confirmation)?;
        let secret_hash = digest_bytes(secret.as_bytes());
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM local_instance WHERE singleton AND instance=$1 AND state='SETUP_PENDING' AND setup_hash=$2 AND setup_until>extract(epoch FROM clock_timestamp()))")
            .bind(&self.config.instance)
            .bind(secret_hash.as_str())
            .fetch_one(&self.pool)
            .await?;
        ensure!(valid && secret.len() == 64, "UNAUTHORIZED");
        let _slot = self
            .password_slots
            .try_acquire()
            .map_err(|_| anyhow::anyhow!("RATE_LIMITED"))?;
        let hash = tokio::task::spawn_blocking(move || password_hash(&password)).await??;
        let id = format!("local_{}", uuid::Uuid::new_v4().simple());

        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query("UPDATE local_instance SET state='INITIALIZED',projection_pending=true,setup_hash=NULL,setup_until=NULL WHERE singleton AND instance=$1 AND state='SETUP_PENDING' AND setup_hash=$2 AND setup_until>extract(epoch FROM clock_timestamp())")
            .bind(&self.config.instance)
            .bind(secret_hash.as_str())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        ensure!(changed == 1, "CONFLICT");
        sqlx::query("INSERT INTO local_accounts(id,display_name,email,password_hash,panel_credential,role,generation) VALUES ($1,$2,$3,$4,$5,'ADMINISTRATOR',$6)")
            .bind(&id)
            .bind(display_name.trim())
            .bind(address)
            .bind(hash)
            .bind(entropy()?)
            .bind(entropy()?)
            .execute(&mut *tx)
            .await?;
        audit(
            &mut tx,
            &id,
            "INITIAL_ADMINISTRATOR_CREATED",
            &self.config.instance,
        )
        .await?;
        tx.commit().await?;
        self.publish().await
    }

    pub(super) async fn login(&self, address: String, password: String) -> Result<String> {
        self.budget().await?;
        ensure!(
            self.instance_state().await? == "INITIALIZED" && password.len() <= 512,
            "UNAUTHORIZED"
        );
        let address = email(&address).map_err(|_| anyhow::anyhow!("UNAUTHORIZED"))?;
        let account = sqlx::query("SELECT id,password_hash,panel_credential,generation FROM local_accounts WHERE email=$1 AND enabled")
            .bind(address)
            .fetch_optional(&self.pool)
            .await?;
        let _slot = self
            .password_slots
            .try_acquire()
            .map_err(|_| anyhow::anyhow!("RATE_LIMITED"))?;
        let hash = account
            .as_ref()
            .map(|r| r.try_get::<String, _>("password_hash"))
            .transpose()?;
        let dummy = self.dummy_password_hash.clone();
        let verified = tokio::task::spawn_blocking(move || -> Result<bool> {
            let hash = match hash {
                Some(h) => h,
                None => dummy,
            };
            let parsed = PasswordHash::new(&hash).map_err(|_| invalid())?;
            Ok(Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok())
        })
        .await??;
        ensure!(verified && account.is_some(), "UNAUTHORIZED");
        let account = account.ok_or_else(invalid)?;
        let id: String = account.try_get("id")?;
        self.validate(&LocalIdentity {
            principal: id.clone(),
            generation: account.try_get("generation")?,
        })
        .await?;
        let mut tx = self.pool.begin().await?;
        audit(&mut tx, &id, "PASSWORD_LOGIN", &id).await?;
        tx.commit().await?;
        Ok(account.try_get("panel_credential")?)
    }

    pub(super) async fn recover_password(&self, address: &str, path: &Path) -> Result<()> {
        let bytes = read_private(path, 512)?;
        let password = std::str::from_utf8(&bytes)?.trim_end_matches('\n');
        password_policy(password, password)?;
        let hash = password_hash(password)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT singleton FROM local_instance FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
        let id: String = sqlx::query_scalar("UPDATE local_accounts SET password_hash=$1,generation=$2,panel_credential=$3 WHERE email=$4 AND enabled RETURNING id")
            .bind(hash)
            .bind(entropy()?)
            .bind(entropy()?)
            .bind(email(address)?)
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query("UPDATE local_instance SET projection_pending=true WHERE singleton")
            .execute(&mut *tx)
            .await?;
        audit(&mut tx, "HOST_OPERATOR", "PASSWORD_RECOVERED", &id).await?;
        tx.commit().await?;
        self.publish().await
    }

    pub(super) async fn set_role(&self, address: &str, role: &str) -> Result<()> {
        ensure!(
            [
                "VIEWER",
                "OPERATOR",
                "REVIEWER",
                "ADMINISTRATOR",
                "DISABLED"
            ]
            .contains(&role),
            "unsupported role"
        );
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT singleton FROM local_instance FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
        let id: String = sqlx::query_scalar("UPDATE local_accounts SET role=CASE WHEN $1='DISABLED' THEN role ELSE $1 END,enabled=($1<>'DISABLED'),generation=$2,panel_credential=$3 WHERE email=$4 RETURNING id")
            .bind(role)
            .bind(entropy()?)
            .bind(entropy()?)
            .bind(email(address)?)
            .fetch_one(&mut *tx)
            .await?;
        let remaining: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM local_accounts WHERE enabled AND role='ADMINISTRATOR'",
        )
        .fetch_one(&mut *tx)
        .await?;
        ensure!(remaining > 0, "cannot disable the last administrator");
        sqlx::query("UPDATE local_instance SET projection_pending=true WHERE singleton")
            .execute(&mut *tx)
            .await?;
        audit(&mut tx, "HOST_OPERATOR", "GRANT_CHANGED", &id).await?;
        tx.commit().await?;
        self.publish().await
    }
}
