//! Explicit system Git adapter. All candidate bytes are independently validated
//! before receive-pack; Git provides maintained advertisement/report semantics.
use crate::{IngressError, unavailable};
use archcert_domain::GitObjectId;
use archcert_source::GitObjectFormat;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// Observed adapter identity, not cryptographic executable attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedGit {
    /// Explicit authority-selected executable.
    pub executable: PathBuf,
    /// Bounded Git-reported version.
    pub version: String,
}
pub(crate) struct SystemGit {
    executable: PathBuf,
    root: PathBuf,
    deadline: Instant,
    observed: ObservedGit,
}
impl SystemGit {
    pub fn new(executable: &Path, root: &Path, seconds: u64) -> Result<Self, IngressError> {
        if !executable.is_absolute() {
            return Err(IngressError::Unavailable);
        }
        let mut git = Self {
            executable: executable.into(),
            root: root.into(),
            deadline: Instant::now() + Duration::from_secs(seconds),
            observed: ObservedGit {
                executable: executable.into(),
                version: String::new(),
            },
        };
        let version = git.run(&["--version"], None)?;
        let version = std::str::from_utf8(&version).map_err(unavailable)?.trim();
        if !version.starts_with("git version ")
            || version.len() > 256
            || !version.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        {
            return Err(IngressError::Unavailable);
        }
        git.observed.version = version.to_owned();
        Ok(git)
    }
    pub fn observed(&self) -> &ObservedGit {
        &self.observed
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.executable);
        cmd.env_clear()
            .current_dir(&self.root)
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", &self.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("LC_ALL", "C")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "credential.helper=",
                "-c",
                "protocol.allow=never",
                "-c",
                "gc.auto=0",
                "-c",
                "maintenance.auto=false",
                "-c",
                "receive.unpackLimit=0",
                "-c",
                "receive.autogc=false",
                "-c",
                "receive.maxInputSize=67108864",
                "-c",
                "receive.denyDeletes=true",
                "-c",
                "receive.shallowUpdate=true",
                "-c",
                "receive.denyNonFastForwards=true",
                "-c",
                "receive.fsckObjects=true",
                "-c",
                "transfer.fsckObjects=true",
            ]);
        cmd
    }
    fn run(&self, args: &[&str], input: Option<File>) -> Result<Vec<u8>, IngressError> {
        let mut stdout = tempfile::tempfile_in(&self.root).map_err(unavailable)?;
        let stderr = tempfile::tempfile_in(&self.root).map_err(unavailable)?;
        let mut child = self
            .command()
            .args(args)
            .stdin(input.map_or(Stdio::null(), Stdio::from))
            .stdout(stdout.try_clone().map_err(unavailable)?)
            .stderr(stderr.try_clone().map_err(unavailable)?)
            .spawn()
            .map_err(unavailable)?;
        let status = loop {
            if stdout.metadata().map_err(unavailable)?.len() > 65536
                || stderr.metadata().map_err(unavailable)?.len() > 65536
                || Instant::now() > self.deadline
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err(IngressError::Limit);
            }
            if let Some(status) = child.try_wait().map_err(unavailable)? {
                break status;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        if !status.success()
            || stdout.metadata().map_err(unavailable)?.len() > 65536
            || stderr.metadata().map_err(unavailable)?.len() > 65536
        {
            return Err(IngressError::Rejected);
        }
        stdout.rewind().map_err(unavailable)?;
        let mut bytes = Vec::new();
        stdout
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
        Ok(bytes)
    }
    pub fn init(&self, format: GitObjectFormat) -> Result<(), IngressError> {
        self.run(
            &[
                "init",
                "--bare",
                "--template=",
                &format!("--object-format={}", format.name()),
                "repository",
            ],
            None,
        )?;
        Ok(())
    }
    pub fn advertise(&self) -> Result<Vec<u8>, IngressError> {
        self.run(
            &[
                "receive-pack",
                "--stateless-rpc",
                "--advertise-refs",
                "repository",
            ],
            None,
        )
    }
    pub fn receive(
        &self,
        commands: &[u8],
        pack: &[u8],
        reference: &str,
        commit: &GitObjectId,
    ) -> Result<Vec<u8>, IngressError> {
        let mut request = tempfile::tempfile_in(&self.root).map_err(unavailable)?;
        request.write_all(commands).map_err(unavailable)?;
        request.write_all(pack).map_err(unavailable)?;
        request.rewind().map_err(unavailable)?;
        let response = self.run(
            &["receive-pack", "--stateless-rpc", "repository"],
            Some(request),
        )?;
        // Never trust subprocess exit alone: report-status failures may still exit 0.
        let received = fs::read(self.root.join("repository").join(reference))
            .map_err(|_| IngressError::Rejected)?;
        if received != format!("{}\n", commit.as_str()).as_bytes() {
            return Err(IngressError::Rejected);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_environment_and_hooks_are_constructed() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let git = SystemGit::new(Path::new("/usr/bin/git"), root.path(), 10)?;
        let cmd = git.command();
        let env: std::collections::BTreeMap<_, _> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for forbidden in [
            "SSH_AUTH_SOCK",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GITHUB_TOKEN",
        ] {
            assert!(!env.contains_key(forbidden));
        }
        assert_eq!(
            env.get("GIT_CONFIG_GLOBAL"),
            Some(&Some("/dev/null".into()))
        );
        assert_eq!(
            env.get("GIT_CONFIG_SYSTEM"),
            Some(&Some("/dev/null".into()))
        );
        assert!(cmd.get_args().any(|a| a == "core.hooksPath=/dev/null"));
        assert_eq!(
            env.get("HOME"),
            Some(&Some(root.path().to_string_lossy().into_owned()))
        );
        Ok(())
    }
}
