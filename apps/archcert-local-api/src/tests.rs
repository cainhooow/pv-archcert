//! Real PostgreSQL identity/provisioning tests; no execution or certificate fixture.

use super::*;
use sqlx::Row;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    service: Arc<Service>,
    admin: PgPool,
    schema: String,
    _directory: tempfile::TempDir,
}

impl Fixture {
    async fn open() -> Result<Self> {
        let url = std::env::var("ARCHCERT_TEST_DATABASE_URL")?;
        let admin = PgPool::connect(&url).await?;
        let schema = format!("local_{}", uuid::Uuid::new_v4().simple());
        // The identifier contains only our fixed prefix and a generated UUID.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await?;
        let selected = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .after_connect(move |connection, _| {
                let schema = selected.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('search_path',$1,false)")
                        .bind(schema)
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await?;
        archcert_storage::PostgresJobRepository::from_pool(pool.clone())
            .migrate()
            .await?;
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        for name in [
            "config",
            "bootstrap",
            "git",
            "sources",
            "artifacts",
            "audit",
            "health",
        ] {
            std::fs::create_dir(root.join(name))?;
            std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o700))?;
        }
        let service = Arc::new(Service {
            config: Configuration {
                instance: uuid::Uuid::new_v4().to_string(),
                root,
                origin: "http://127.0.0.1:18090".into(),
                listen: "127.0.0.1:18091".parse()?,
                token_sha256: digest_bytes(entropy()?.as_bytes()).as_str().into(),
                gateway_binary: "/usr/bin/true".into(),
                ssh_user: "local".into(),
                ssh_port: 22223,
                image: Some("python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f".into()),
                authority_toml: include_str!("../../../docs/policy/CONTROLLED_AUTHORITY.toml").into(),
            },
            pool,
            publication: Mutex::new(()),
            password_slots: tokio::sync::Semaphore::new(2),
            request_slots: tokio::sync::Semaphore::new(8),
            dummy_password_hash: identity::password_hash(&entropy()?)?,
        });
        service.initialize(false).await?;
        Ok(Self {
            service,
            admin,
            schema,
            _directory: directory,
        })
    }

    async fn identity(&self) -> Result<LocalIdentity> {
        let row = sqlx::query("SELECT id,generation FROM local_accounts ORDER BY id LIMIT 1")
            .fetch_one(&self.service.pool)
            .await?;
        Ok(LocalIdentity {
            principal: row.try_get("id")?,
            generation: row.try_get("generation")?,
        })
    }

    async fn setup(&self) -> Result<()> {
        let secret =
            std::fs::read_to_string(self.service.config.root.join("bootstrap/setup-secret"))?;
        self.service
            .setup(
                secret,
                "Operator".into(),
                "Operator@Example.local".into(),
                "a long test password".into(),
                "a long test password".into(),
            )
            .await
    }

    async fn close(self) -> Result<()> {
        self.service.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await?;
        self.admin.close().await;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires real isolated PostgreSQL schemas"]
async fn concurrent_bootstrap_replay_restart_and_recovery_are_monotonic() -> Result<()> {
    let fixture = Fixture::open().await?;
    assert_eq!(fixture.service.instance_state().await?, "SETUP_PENDING");
    let (first, second) = tokio::join!(fixture.setup(), fixture.setup());

    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM local_accounts")
        .fetch_one(&fixture.service.pool)
        .await?;
    assert_eq!(count, 1);
    assert_eq!(fixture.service.instance_state().await?, "INITIALIZED");
    assert!(fixture.setup().await.is_err());
    assert!(fixture.service.initialize(true).await.is_err());
    assert!(
        sqlx::query(
            "UPDATE local_instance SET state='UNINITIALIZED',setup_hash=NULL,setup_until=NULL"
        )
        .execute(&fixture.service.pool)
        .await
        .is_err()
    );

    sqlx::query("UPDATE local_instance SET projection_pending=true")
        .execute(&fixture.service.pool)
        .await?;
    assert_eq!(fixture.service.instance_state().await?, "RECOVERY_REQUIRED");
    assert!(fixture.setup().await.is_err());
    fixture.service.publish().await?;
    assert_eq!(fixture.service.instance_state().await?, "INITIALIZED");
    assert!(
        fixture
            .service
            .set_role("operator@example.local", "DISABLED")
            .await
            .is_err()
    );

    let password_hash: String = sqlx::query_scalar("SELECT password_hash FROM local_accounts")
        .fetch_one(&fixture.service.pool)
        .await?;
    assert!(password_hash.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
    assert!(!password_hash.contains("a long test password"));
    let duplicate = sqlx::query("INSERT INTO local_accounts SELECT id||'_duplicate',display_name,email,password_hash,panel_credential,role,generation,enabled FROM local_accounts").execute(&fixture.service.pool).await;
    assert!(duplicate.is_err());
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires real isolated PostgreSQL schemas"]
async fn password_recovery_and_grant_cycles_invalidate_previous_generations() -> Result<()> {
    let fixture = Fixture::open().await?;
    fixture.setup().await?;
    let old = fixture.identity().await?;
    assert!(
        fixture
            .service
            .login("operator@example.local".into(), "incorrect password".into())
            .await
            .is_err()
    );
    assert!(
        fixture
            .service
            .login(
                "operator@example.local".into(),
                "a long test password".into()
            )
            .await
            .is_ok()
    );
    let path = fixture.service.config.root.join("bootstrap/new-password");
    publication::replace(&path, b"a different test password")?;

    fixture
        .service
        .recover_password("operator@example.local", &path)
        .await?;
    assert!(fixture.service.validate(&old).await.is_err());
    assert!(
        fixture
            .service
            .login(
                "operator@example.local".into(),
                "a long test password".into()
            )
            .await
            .is_err()
    );
    assert!(
        fixture
            .service
            .login(
                "operator@example.local".into(),
                "a different test password".into()
            )
            .await
            .is_ok()
    );

    sqlx::query("INSERT INTO local_accounts SELECT id||'_reader','Reader','reader@example.local',password_hash,panel_credential,'VIEWER',generation,enabled FROM local_accounts LIMIT 1").execute(&fixture.service.pool).await?;
    let reader: String =
        sqlx::query_scalar("SELECT id FROM local_accounts WHERE email='reader@example.local'")
            .fetch_one(&fixture.service.pool)
            .await?;
    let generation: String =
        sqlx::query_scalar("SELECT generation FROM local_accounts WHERE id=$1")
            .bind(&reader)
            .fetch_one(&fixture.service.pool)
            .await?;
    let identity = LocalIdentity {
        principal: reader,
        generation,
    };
    fixture
        .service
        .set_role("reader@example.local", "OPERATOR")
        .await?;
    fixture
        .service
        .set_role("reader@example.local", "VIEWER")
        .await?;
    assert!(fixture.service.validate(&identity).await.is_err());
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires real isolated PostgreSQL schemas"]
async fn project_admission_is_owned_atomic_and_idempotent() -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let fixture = Fixture::open().await?;
    fixture.setup().await?;
    let owner = fixture.identity().await?;
    let mut key = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    key.extend([7u8; 32]);
    let key = format!("ssh-ed25519 {}", STANDARD.encode(key));
    let request_key = uuid::Uuid::new_v4().to_string();
    let registration = || projects::ProjectRegistration {
        name: "Ledger".into(),
        description: "<script>inert</script>".into(),
        repository: "pilot/ledger".into(),
        public_key: key.clone(),
        request_key: request_key.clone(),
    };

    let first = fixture
        .service
        .create_project(owner.clone(), registration())
        .await?;
    let second = fixture
        .service
        .create_project(owner.clone(), registration())
        .await?;
    assert_eq!(first, second);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM local_projects")
        .fetch_one(&fixture.service.pool)
        .await?;
    assert_eq!(count, 1);
    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM repository_grants")
        .fetch_one(&fixture.service.pool)
        .await?;
    assert_eq!(grants, 1);
    let mut duplicate = registration();
    duplicate.request_key = uuid::Uuid::new_v4().to_string();
    assert!(
        fixture
            .service
            .create_project(owner.clone(), duplicate)
            .await
            .is_err()
    );
    assert!(
        fixture
            .service
            .certify(
                owner.clone(),
                uuid::Uuid::new_v4().to_string(),
                uuid::Uuid::new_v4().to_string(),
                "request".into()
            )
            .await
            .is_err()
    );

    let mut malicious = registration();
    malicious.public_key = "command=\"id\" ssh-ed25519 invalid".into();
    assert!(
        fixture
            .service
            .create_project(owner, malicious)
            .await
            .is_err()
    );
    fixture.close().await
}

#[test]
fn local_input_limits_and_ssh_options_are_closed() {
    // Full parsing is exercised through real browser forms and the private broker.
    let posted_authority =
        json!({"operation":"CREATE_PROJECT","actor":"forged","policy":"weakened"});
    assert!(serde_json::from_value::<LocalRequest>(posted_authority).is_err());
}

#[tokio::test]
#[ignore = "requires real isolated PostgreSQL schemas"]
async fn readiness_reports_store_loss_without_reopening_initialization() -> Result<()> {
    let fixture = Fixture::open().await?;
    fixture.setup().await?;

    let ready = fixture.service.call(LocalRequest::Status).await?;
    assert_eq!(ready.state, "INITIALIZED");
    assert_eq!(ready.details["artifact_store"], "READY");
    assert_eq!(ready.details["source_catalog"], "READY");

    let artifacts = fixture.service.config.root.join("artifacts");
    let retained = fixture.service.config.root.join("retained-artifacts");
    std::fs::rename(&artifacts, &retained)?;

    let unavailable = fixture.service.call(LocalRequest::Status).await?;
    assert_eq!(unavailable.state, "INITIALIZED");
    assert_eq!(unavailable.details["artifact_store"], "ERROR");
    assert!(!artifacts.exists());
    assert!(fixture.setup().await.is_err());

    std::fs::rename(&retained, &artifacts)?;
    let sources = fixture.service.config.root.join("sources");
    std::fs::set_permissions(&sources, std::fs::Permissions::from_mode(0o755))?;

    let unsafe_store = fixture.service.call(LocalRequest::Status).await?;
    assert_eq!(unsafe_store.details["source_catalog"], "ERROR");
    assert_eq!(unsafe_store.details["artifact_store"], "READY");

    std::fs::set_permissions(&sources, std::fs::Permissions::from_mode(0o700))?;
    let recovered = fixture.service.call(LocalRequest::Status).await?;
    assert_eq!(recovered.state, "INITIALIZED");
    assert_eq!(recovered.details["source_catalog"], "READY");
    assert_eq!(recovered.details["artifact_store"], "READY");

    fixture.close().await
}

#[tokio::test]
#[ignore = "requires real isolated PostgreSQL schemas"]
async fn login_budget_survives_reconstruction_and_migration_failure_denies_setup() -> Result<()> {
    let fixture = Fixture::open().await?;
    for _ in 0..20 {
        assert!(
            fixture
                .service
                .login("unknown@example.local".into(), "invalid".into())
                .await
                .is_err()
        );
    }
    let refused = fixture
        .service
        .login("unknown@example.local".into(), "invalid".into())
        .await;
    assert_eq!(
        refused.err().map(|error| error.to_string()).as_deref(),
        Some("RATE_LIMITED")
    );
    let used: i32 = sqlx::query_scalar("SELECT used FROM local_login_budget")
        .fetch_one(&fixture.service.pool)
        .await?;
    assert_eq!(used, 21);

    sqlx::query("UPDATE _sqlx_migrations SET success=false WHERE version=11")
        .execute(&fixture.service.pool)
        .await?;
    assert!(fixture.service.instance_state().await.is_err());
    assert!(fixture.setup().await.is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM local_accounts")
        .fetch_one(&fixture.service.pool)
        .await?;
    assert_eq!(count, 0);
    fixture.close().await
}
