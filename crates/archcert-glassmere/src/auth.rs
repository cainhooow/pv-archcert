//! Private provisioned credentials, expiring opaque sessions and append-only audit.

use archcert_domain::{ProjectId, source::digest_bytes};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_CONFIG_BYTES: u64 = 128 * 1024;
const MAX_AUDIT_BYTES: u64 = 16 * 1024 * 1024;
const SESSION_SECONDS: u64 = 1800;

/// Roles do not imply certification, release, signing or cross-project authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role {
    /// Read explicitly assigned projects and immutable evidence.
    Viewer,
    /// Read; workflow commands remain unsupported until separately qualified.
    Operator,
    /// Read; no new human disposition authority is introduced.
    Reviewer,
    /// Read assigned projects and inspect panel operational audit.
    Administrator,
}

/// External operator grant. A 256-bit random token is not a human password.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    /// Non-secret audit identity.
    pub id: String,
    /// SHA-256 of an independently generated high-entropy credential.
    pub token_sha256: String,
    /// Panel role, separate from project authorization.
    pub role: Role,
    /// Explicit project scope; no wildcard administrator grant.
    pub projects: Vec<ProjectId>,
}

/// Operator-selected private session configuration; never target repository data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PanelConfiguration {
    /// Contract version.
    pub schema: u32,
    /// Exact external origin; forwarded headers never select this value.
    pub origin: String,
    /// Explicit loopback HTTP mode; false requires HTTPS and Secure cookies.
    pub development_http: bool,
    /// Show a persistent development/demo label.
    pub demonstration_data: bool,
    /// Externally provisioned grants. No default account exists.
    pub principals: Vec<Principal>,
    /// Private append-only panel audit sink, independent of authority history.
    pub audit_path: PathBuf,
}

/// Fixed failures deliberately contain no credential, path or configuration bytes.
#[derive(Debug, Clone, Copy)]
pub enum AuthError {
    /// Missing or invalid session/credential.
    Unauthenticated,
    /// Caller role does not grant this operation.
    Forbidden,
    /// Private configuration/audit/session storage is unavailable.
    Unavailable,
    /// Operational request budget exhausted; no permanent account lockout.
    RateLimited,
}

fn private_file(path: &Path, append: bool) -> Result<File, AuthError> {
    let file = OpenOptions::new()
        .read(true)
        .append(append)
        .create(append)
        .mode(0o600)
        .custom_flags(
            rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32,
        )
        .open(path)
        .map_err(|_| AuthError::Unavailable)?;
    let metadata = file.metadata().map_err(|_| AuthError::Unavailable)?;

    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(AuthError::Unavailable);
    }

    Ok(file)
}

impl PanelConfiguration {
    /// Bounded no-follow private-file load; grants are rechecked on every request.
    pub fn load(path: &Path) -> Result<Self, AuthError> {
        let file = private_file(path, false)?;
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AuthError::Unavailable)?;

        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(AuthError::Unavailable);
        }

        let config: Self = serde_json::from_slice(&bytes).map_err(|_| AuthError::Unavailable)?;
        let origin_valid = if config.development_http {
            config
                .origin
                .strip_prefix("http://127.0.0.1:")
                .is_some_and(|port| port.parse::<u16>().is_ok_and(|p| p != 0))
        } else {
            config.origin.starts_with("https://")
                && !config.origin[8..].is_empty()
                && !config.origin[8..].contains(['/', '?', '#', '@'])
        };

        if config.schema != 1
            || !origin_valid
            || config.principals.is_empty()
            || config.principals.len() > 256
        {
            return Err(AuthError::Unavailable);
        }

        let mut ids = std::collections::BTreeSet::new();
        let mut hashes = std::collections::BTreeSet::new();
        for principal in &config.principals {
            if principal.id.is_empty()
                || principal.id.len() > 64
                || !principal
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                || principal.projects.len() > 256
                || archcert_domain::Sha256Digest::parse(&principal.token_sha256).is_err()
                || !ids.insert(principal.id.clone())
                || !hashes.insert(principal.token_sha256.clone())
            {
                return Err(AuthError::Unavailable);
            }
        }

        Ok(config)
    }
}

#[derive(Clone)]
struct Session {
    principal_id: String,
    grant_revision: String,
    csrf: String,
    expires: Instant,
    budget_start: Instant,
    requests: u32,
}

/// Public authenticated identity; contains no credential or token hash.
#[derive(Clone)]
pub struct Identity {
    /// Public operator identity.
    pub id: String,
    /// Exact role.
    pub role: Role,
    /// Explicit allowed projects.
    pub projects: Vec<ProjectId>,
    /// Session-bound CSRF capability, only inserted into same-origin forms.
    pub csrf: String,
}

struct LoginBudget {
    start: Instant,
    requests: u32,
}

/// Process-local sessions intentionally invalidate across restart. No browser storage.
pub struct Authentication {
    config_path: PathBuf,
    initial_origin: String,
    initial_development: bool,
    sessions: Mutex<HashMap<String, Session>>,
    login_budget: Mutex<LoginBudget>,
    audit: Mutex<(File, u64)>,
}

/// UTC Unix seconds; wall time is never used for session expiry or ordering.
pub fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unpredictable 256-bit local credential, used for bootstrap/session/CSRF only.
pub fn random_credential() -> Result<String, AuthError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AuthError::Unavailable)?;

    Ok(hex::encode(bytes))
}

impl Authentication {
    /// Open private configuration and audit before binding a network listener.
    pub fn open(path: PathBuf) -> Result<Self, AuthError> {
        let config = PanelConfiguration::load(&path)?;
        let mut file = private_file(&config.audit_path, true)?;
        let size = file.metadata().map_err(|_| AuthError::Unavailable)?.len();
        if size > MAX_AUDIT_BYTES {
            return Err(AuthError::Unavailable);
        }
        let mut existing = String::new();
        file.read_to_string(&mut existing)
            .map_err(|_| AuthError::Unavailable)?;
        let sequence = existing.lines().count() as u64;

        Ok(Self {
            config_path: path,
            initial_origin: config.origin,
            initial_development: config.development_http,
            sessions: Mutex::new(HashMap::new()),
            login_budget: Mutex::new(LoginBudget {
                start: Instant::now(),
                requests: 0,
            }),
            audit: Mutex::new((file, sequence)),
        })
    }

    /// Reload grants. Origin/cookie-security changes require an explicit restart.
    pub fn configuration(&self) -> Result<PanelConfiguration, AuthError> {
        let config = PanelConfiguration::load(&self.config_path)?;
        if config.origin != self.initial_origin
            || config.development_http != self.initial_development
        {
            return Err(AuthError::Unavailable);
        }

        Ok(config)
    }

    /// Audited append-only action without source text, credentials or raw paths.
    pub fn audit(&self, principal: &str, event: &str) -> Result<(), AuthError> {
        let mut audit = self.audit.lock().map_err(|_| AuthError::Unavailable)?;
        if audit
            .0
            .metadata()
            .map_err(|_| AuthError::Unavailable)?
            .len()
            > MAX_AUDIT_BYTES
        {
            return Err(AuthError::Unavailable);
        }
        audit.1 += 1;
        let record = serde_json::json!({
            "sequence": audit.1,
            "timestamp_utc_unix": unix_seconds(),
            "principal": principal,
            "event": event,
        });
        serde_json::to_writer(&mut audit.0, &record).map_err(|_| AuthError::Unavailable)?;
        audit
            .0
            .write_all(b"\n")
            .map_err(|_| AuthError::Unavailable)?;
        audit.0.sync_data().map_err(|_| AuthError::Unavailable)
    }

    /// Same-origin credential exchange with a process-wide bounded attempt budget.
    pub fn login(&self, credential: &str) -> Result<(String, String), AuthError> {
        {
            let mut budget = self
                .login_budget
                .lock()
                .map_err(|_| AuthError::Unavailable)?;
            if budget.start.elapsed() >= Duration::from_secs(60) {
                budget.start = Instant::now();
                budget.requests = 0;
            }
            budget.requests += 1;
            if budget.requests > 20 {
                return Err(AuthError::RateLimited);
            }
        }

        let config = self.configuration()?;
        let digest = digest_bytes(credential.as_bytes());
        let principal = config
            .principals
            .iter()
            .find(|p| credential.len() == 64 && p.token_sha256 == digest.as_str());
        let Some(principal) = principal else {
            self.audit("UNKNOWN", "LOGIN_DENIED")?;
            return Err(AuthError::Unauthenticated);
        };

        let token = random_credential()?;
        let csrf = random_credential()?;
        let mut sessions = self.sessions.lock().map_err(|_| AuthError::Unavailable)?;
        sessions.retain(|_, session| session.expires > Instant::now());
        if sessions.len() >= 256 {
            return Err(AuthError::RateLimited);
        }
        self.audit(&principal.id, "LOGIN")?;
        sessions.insert(
            digest_bytes(token.as_bytes()).as_str().into(),
            Session {
                principal_id: principal.id.clone(),
                grant_revision: digest_bytes(
                    &serde_json::to_vec(principal).map_err(|_| AuthError::Unavailable)?,
                )
                .as_str()
                .into(),
                csrf,
                expires: Instant::now() + Duration::from_secs(SESSION_SECONDS),
                budget_start: Instant::now(),
                requests: 0,
            },
        );
        let secure = if config.development_http {
            ""
        } else {
            "; Secure"
        };

        Ok((
            token.clone(),
            format!(
                "archcert_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}{secure}"
            ),
        ))
    }

    /// Session signature is opaque entropy; tampering never authenticates. Grants
    /// and their exact revision are checked for every query/download/action.
    pub fn authenticate(&self, token: &str) -> Result<Identity, AuthError> {
        if token.len() != 64 {
            return Err(AuthError::Unauthenticated);
        }
        let config = self.configuration()?;
        let mut sessions = self.sessions.lock().map_err(|_| AuthError::Unavailable)?;
        let session = sessions
            .get_mut(digest_bytes(token.as_bytes()).as_str())
            .ok_or(AuthError::Unauthenticated)?;
        let principal = config
            .principals
            .iter()
            .find(|p| p.id == session.principal_id)
            .ok_or(AuthError::Unauthenticated)?;
        let revision =
            digest_bytes(&serde_json::to_vec(principal).map_err(|_| AuthError::Unavailable)?);

        if session.expires <= Instant::now() || session.grant_revision != revision.as_str() {
            return Err(AuthError::Unauthenticated);
        }
        if session.budget_start.elapsed() >= Duration::from_secs(60) {
            session.budget_start = Instant::now();
            session.requests = 0;
        }
        session.requests += 1;
        if session.requests > 240 {
            return Err(AuthError::RateLimited);
        }

        Ok(Identity {
            id: principal.id.clone(),
            role: principal.role,
            projects: principal.projects.clone(),
            csrf: session.csrf.clone(),
        })
    }

    /// Invalidate this exact server session; no ordinary user can delete audit.
    pub fn logout(&self, token: &str, identity: &Identity, csrf: &str) -> Result<(), AuthError> {
        if csrf != identity.csrf {
            self.audit(&identity.id, "CSRF_DENIED")?;
            return Err(AuthError::Forbidden);
        }
        self.audit(&identity.id, "LOGOUT")?;
        self.sessions
            .lock()
            .map_err(|_| AuthError::Unavailable)?
            .remove(digest_bytes(token.as_bytes()).as_str());

        Ok(())
    }

    /// Bounded forensic inspection for panel Administrators only.
    pub fn audit_page(&self, identity: &Identity) -> Result<String, AuthError> {
        if identity.role != Role::Administrator {
            self.audit(&identity.id, "AUTHORIZATION_DENIED")?;
            return Err(AuthError::Forbidden);
        }
        let config = self.configuration()?;
        let file = private_file(&config.audit_path, false)?;
        let mut bytes = Vec::new();
        file.take(MAX_AUDIT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AuthError::Unavailable)?;
        if bytes.len() as u64 > MAX_AUDIT_BYTES {
            return Err(AuthError::Unavailable);
        }

        Ok(String::from_utf8_lossy(&bytes)
            .lines()
            .rev()
            .take(50)
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn provision(path: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/glassmere-provision");
        let output = std::process::Command::new("/usr/bin/python3")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg(script)
            .arg("--config")
            .arg(path)
            .args(["--operator", "authentication-regression"])
            .args(args)
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "private provisioning failed for {}",
                args.first().copied().unwrap_or("missing action")
            )
            .into());
        }

        Ok(())
    }

    fn delivered(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;

        Ok(value["credential"].as_str().ok_or("credential")?.into())
    }

    #[test]
    fn provisioned_grant_rotation_and_revocation_invalidate_existing_sessions()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        let configuration = root.join("panel.json");
        let initial_access = root.join("initial-access.json");
        let rotated_access = root.join("rotated-access.json");
        let reader_access = root.join("reader-access.json");
        let initial_path = initial_access.to_str().ok_or("path")?;
        let rotated_path = rotated_access.to_str().ok_or("path")?;
        let reader_path = reader_access.to_str().ok_or("path")?;

        provision(
            &configuration,
            &[
                "bootstrap",
                "--principal",
                "admin",
                "--origin",
                "https://glassmere.internal",
                "--credential-file",
                initial_path,
            ],
        )?;
        let initial_credential = delivered(&initial_access)?;
        let auth = Authentication::open(configuration.clone()).map_err(|_| "authentication")?;
        let (original_session, cookie) = auth.login(&initial_credential).map_err(|_| "login")?;

        assert!(cookie.contains("; Secure"));
        assert_eq!(
            auth.authenticate(&original_session)
                .map_err(|_| "session")?
                .role,
            Role::Administrator
        );

        provision(
            &configuration,
            &["set-grant", "--principal", "admin", "--role", "VIEWER"],
        )?;

        assert!(matches!(
            auth.authenticate(&original_session),
            Err(AuthError::Unauthenticated)
        ));
        let (viewer_session, _) = auth
            .login(&initial_credential)
            .map_err(|_| "viewer login")?;
        assert_eq!(
            auth.authenticate(&viewer_session)
                .map_err(|_| "session")?
                .role,
            Role::Viewer
        );

        provision(
            &configuration,
            &[
                "rotate",
                "--principal",
                "admin",
                "--credential-file",
                rotated_path,
            ],
        )?;
        let rotated_credential = delivered(&rotated_access)?;

        assert!(matches!(
            auth.authenticate(&viewer_session),
            Err(AuthError::Unauthenticated)
        ));
        assert!(matches!(
            auth.login(&initial_credential),
            Err(AuthError::Unauthenticated)
        ));
        let (rotated_session, _) = auth
            .login(&rotated_credential)
            .map_err(|_| "rotated login")?;

        provision(
            &configuration,
            &[
                "add",
                "--principal",
                "reader",
                "--role",
                "VIEWER",
                "--credential-file",
                reader_path,
            ],
        )?;
        provision(&configuration, &["revoke", "--principal", "admin"])?;

        assert!(matches!(
            auth.authenticate(&rotated_session),
            Err(AuthError::Unauthenticated)
        ));
        assert!(matches!(
            auth.login(&rotated_credential),
            Err(AuthError::Unauthenticated)
        ));
        assert!(auth.login(&delivered(&reader_access)?).is_ok());

        let provisioning_audit =
            std::fs::read_to_string(root.join("panel.json.provisioning.jsonl"))?;

        assert!(!provisioning_audit.contains(&initial_credential));
        assert!(!provisioning_audit.contains(&rotated_credential));
        assert!(provisioning_audit.contains("authentication-regression"));
        assert!(provisioning_audit.contains("revoke"));

        Ok(())
    }

    #[test]
    fn expired_sessions_and_restarts_do_not_preserve_access()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let credential = random_credential().map_err(|_| "entropy")?;
        let path = root.path().join("config.json");
        let configuration = PanelConfiguration {
            schema: 1,
            origin: "https://glassmere.internal".into(),
            development_http: false,
            demonstration_data: false,
            principals: vec![Principal {
                id: "viewer".into(),
                token_sha256: digest_bytes(credential.as_bytes()).as_str().into(),
                role: Role::Viewer,
                projects: vec![],
            }],
            audit_path: root.path().join("audit.jsonl"),
        };
        std::fs::write(&path, serde_json::to_vec(&configuration)?)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let auth = Authentication::open(path.clone()).map_err(|_| "auth")?;
        let (token, cookie) = auth.login(&credential).map_err(|_| "login")?;
        assert!(cookie.contains("; Secure"));
        assert!(auth.authenticate(&token).is_ok());

        {
            let mut sessions = auth.sessions.lock().map_err(|_| "mutex")?;
            let session = sessions
                .get_mut(digest_bytes(token.as_bytes()).as_str())
                .ok_or("session")?;
            session.expires = Instant::now() - Duration::from_secs(1);
        }

        assert!(matches!(
            auth.authenticate(&token),
            Err(AuthError::Unauthenticated)
        ));
        let restarted = Authentication::open(path).map_err(|_| "restart")?;
        assert!(matches!(
            restarted.authenticate(&token),
            Err(AuthError::Unauthenticated)
        ));

        Ok(())
    }
}
