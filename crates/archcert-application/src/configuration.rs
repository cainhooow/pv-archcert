//! Project requests, authority policy and operator runtime settings are separate trust domains.

use crate::validation::{EvidenceCategory, ProjectExecutionRequest, RequestedStep};
use archcert_domain::execution::{ExecutionCommand, ExecutionError};
use serde::Deserialize;
use std::{collections::BTreeSet, io::Read, path::PathBuf};
use thiserror::Error;

/// Current project configuration schema. Other versions explicitly reject.
pub const PROJECT_SCHEMA: u32 = 1;
/// Input allocation bound before TOML decoding.
pub const MAX_PROJECT_CONFIGURATION_BYTES: u64 = 256 * 1024;

/// Strict, validated project request. Cannot deserialize authority/runtime settings.
#[derive(Debug, Clone)]
pub struct ProjectConfiguration {
    name: String,
    execution: Option<ProjectExecutionRequest>,
}
/// Project configuration rejection, distinct from later authority profile resolution.
#[derive(Debug, Error)]
pub enum ConfigurationError {
    /// Bounded input could not be read.
    #[error("project configuration read failed")]
    Read,
    /// Oversized input is rejected before decoding.
    #[error("project configuration exceeds 256 KiB")]
    TooLarge,
    /// Strict TOML grammar, including unknown fields.
    #[error("invalid project configuration: {0}")]
    Syntax(#[from] toml::de::Error),
    /// Schema dispatch is explicit.
    #[error("unsupported project configuration schema {0}; supported schema is 1")]
    UnknownSchema(u32),
    /// Structural request constraints failed.
    #[error("invalid project configuration: {0}")]
    Invalid(&'static str),
    /// Literal command construction failed.
    #[error(transparent)]
    Command(#[from] ExecutionError),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConfiguration {
    schema: u32,
    project: WireProject,
    execution: Option<WireExecution>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProject {
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireExecution {
    profile: String,
    commands: Vec<WireCommand>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCommand {
    name: String,
    program: String,
    args: Vec<String>,
    #[serde(default = "source_directory")]
    working_directory: String,
    #[serde(default)]
    evidence: EvidenceCategory,
}
fn source_directory() -> String {
    "/source".into()
}
/// Stable step IDs cannot contain terminal controls, whitespace or path delimiters.
pub(crate) fn valid_step_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
impl ProjectConfiguration {
    /// One production parsing entry point, shared by config-check, run and tests.
    pub fn parse(text: &str) -> Result<Self, ConfigurationError> {
        if text.len() as u64 > MAX_PROJECT_CONFIGURATION_BYTES {
            return Err(ConfigurationError::TooLarge);
        }
        let wire: WireConfiguration = toml::from_str(text)?;
        if wire.schema != PROJECT_SCHEMA {
            return Err(ConfigurationError::UnknownSchema(wire.schema));
        }
        if wire.project.name.trim().is_empty()
            || wire.project.name.len() > 256
            || wire.project.name.chars().any(char::is_control)
        {
            return Err(ConfigurationError::Invalid("invalid project.name"));
        }
        let execution = wire
            .execution
            .map(|execution| {
                if !valid_step_id(&execution.profile) {
                    return Err(ConfigurationError::Invalid("invalid requested profile ID"));
                }
                if execution.commands.is_empty() || execution.commands.len() > 32 {
                    return Err(ConfigurationError::Invalid("command count must be 1..=32"));
                }
                let mut names = BTreeSet::new();
                let mut steps = Vec::new();
                for command in execution.commands {
                    if !valid_step_id(&command.name) || !names.insert(command.name.clone()) {
                        return Err(ConfigurationError::Invalid(
                            "invalid or duplicate command name",
                        ));
                    }
                    steps.push(RequestedStep {
                        id: command.name,
                        command: ExecutionCommand::new(
                            command.program,
                            command.args,
                            command.working_directory,
                        )?,
                        evidence: command.evidence,
                    });
                }
                Ok(ProjectExecutionRequest::new(execution.profile, steps))
            })
            .transpose()?;
        Ok(Self {
            name: wire.project.name,
            execution,
        })
    }
    /// Reads at most the parser budget plus one byte, preventing unbounded file reads.
    pub fn read(reader: impl Read) -> Result<Self, ConfigurationError> {
        let mut bytes = Vec::new();
        reader
            .take(MAX_PROJECT_CONFIGURATION_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ConfigurationError::Read)?;
        if bytes.len() as u64 > MAX_PROJECT_CONFIGURATION_BYTES {
            return Err(ConfigurationError::TooLarge);
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ConfigurationError::Invalid("configuration must be UTF-8"))?;
        Self::parse(text)
    }
    /// Diagnostic project name, never authority identity.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Requested steps; absence means no project-requested execution.
    pub fn execution_request(&self) -> Option<&ProjectExecutionRequest> {
        self.execution.as_ref()
    }
}

/// Trusted operator locations. No project Deserialize implementation exists.
#[derive(Debug)]
pub struct RuntimeConfiguration {
    /// Explicit absolute Docker client location.
    pub docker_executable: PathBuf,
    /// Explicit Unix endpoint, validated by the runtime adapter.
    pub docker_endpoint: String,
    /// Private authority-owned source materialization root.
    pub workspace_root: PathBuf,
}
