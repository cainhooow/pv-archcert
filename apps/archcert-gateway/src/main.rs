//! Restricted OpenSSH forced command. Source reception never creates a job.
use anyhow::{Context, Result};
use archcert_domain::ingress::{DeviceKeyId, SourceSubmissionId};
use archcert_gateway::DevelopmentSubmissionStore;
use clap::{Parser, Subcommand};
use std::{
    io::{BufReader, Read, Write},
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(about = "Northgate authenticated source ingress; no certification authority")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Exports source-only v1 Protobuf observations to stdout (not canonical bytes).
    ExportProto {
        /// Private development source store root.
        #[arg(long)]
        store: PathBuf,
        /// Exact accepted submission UUID; export grants no authority.
        submission: String,
    },
    /// OpenSSH-only forced command; fingerprint is fixed in authorized_keys.
    Receive {
        /// Private operator configuration, outside all target repositories.
        #[arg(long)]
        config: PathBuf,
        /// SHA-256 public key fingerprint, fixed by the authority forced command.
        #[arg(long)]
        device_key: String,
    },
    /// Operator-only controlled external resolution into a new source submission.
    Resolve {
        /// Private authority configuration containing exact content grants.
        #[arg(long)]
        config: PathBuf,
        /// Exact original incomplete submission UUID.
        submission: String,
    },
    /// Operator inspection of an accepted immutable development submission.
    Show {
        /// Private development source store root.
        #[arg(long)]
        store: PathBuf,
        /// Exact authority-generated submission UUID.
        submission: String,
    },
}
struct DeadlineInput {
    input: std::io::Stdin,
    deadline: Instant,
}
impl Read for DeadlineInput {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "receive deadline"))?;
        let timeout = Timespec {
            tv_sec: remaining.as_secs() as i64,
            tv_nsec: i64::from(remaining.subsec_nanos()),
        };
        let mut fds = [PollFd::new(&self.input, PollFlags::IN)];
        if poll(&mut fds, Some(&timeout))? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "receive deadline",
            ));
        }
        self.input.read(out)
    }
}
fn run() -> Result<()> {
    match Cli::parse().command {
        Command::ExportProto { store, submission } => {
            let store = DevelopmentSubmissionStore::open(&store, 32)?;
            let source = store.load(&SourceSubmissionId::parse(&submission)?)?;
            let state = source.evidence.source_submission_state()?;
            let bytes = archcert_protocol::protobuf::encode_submission(&state)?;
            std::io::stdout().lock().write_all(&bytes)?;
        }
        Command::Receive { config, device_key } => {
            let config = archcert_gateway::read_configuration(&config)?;
            let original = std::env::var("SSH_ORIGINAL_COMMAND")
                .context("OpenSSH original command required")?;
            let input = DeadlineInput {
                input: std::io::stdin(),
                deadline: Instant::now() + Duration::from_secs(config.session_seconds),
            };
            let result = archcert_gateway::receive(
                &config,
                &DeviceKeyId::parse(device_key)?,
                &original,
                BufReader::new(input),
                std::io::stdout().lock(),
            )?;
            eprintln!(
                "SOURCE {} submission={} source_sha256={}",
                result.status,
                result.submission,
                result
                    .source
                    .context("source identity missing")?
                    .snapshot_sha256
                    .as_str()
            );
        }
        Command::Resolve { config, submission } => {
            let config = archcert_gateway::read_resolution_configuration(&config)?;
            let evidence = archcert_gateway::resolve_submission(
                &config,
                &SourceSubmissionId::parse(&submission)?,
            )?;
            println!("{}", serde_json::to_string_pretty(&evidence)?);
        }
        Command::Show { store, submission } => {
            let store = DevelopmentSubmissionStore::open(&store, 32)?;
            let source = store.load(&SourceSubmissionId::parse(&submission)?)?;
            println!("{}", serde_json::to_string_pretty(&source.evidence)?);
        }
    }
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("NORTHGATE: source receive or inspection failed");
        std::process::exit(1);
    }
}
