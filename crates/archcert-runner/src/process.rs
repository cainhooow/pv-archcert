//! Nonblocking bounded subprocess I/O. Only the trusted runtime CLI runs locally.
use archcert_domain::{
    Sha256Digest,
    execution::{CapturedStream, ExecutionError as Error, TerminationReason},
};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) struct Capture {
    hash: Sha256,
    bytes: u64,
    excerpt: Vec<u8>,
    limit: u64,
    prefix: u64,
    eof: bool,
}
impl Capture {
    pub(crate) fn new(limit: u64, prefix: u64) -> Self {
        Self {
            hash: Sha256::new(),
            bytes: 0,
            excerpt: Vec::new(),
            limit,
            prefix,
            eof: false,
        }
    }
    fn read(&mut self, pipe: &mut impl Read) -> Result<bool, Error> {
        // Fixed work per iteration prevents a flooding stream starving deadline/stderr checks.
        let mut buf = [0u8; 8192];
        for _ in 0..8 {
            match pipe.read(&mut buf) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => {
                    self.hash.update(&buf[..n]);
                    self.bytes = self.bytes.saturating_add(n as u64);
                    let retain =
                        (self.prefix.saturating_sub(self.excerpt.len() as u64) as usize).min(n);
                    self.excerpt.extend_from_slice(&buf[..retain]);
                    if self.bytes > self.limit {
                        return Ok(true);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Error::RuntimeFailure),
            }
        }
        Ok(self.bytes > self.limit)
    }
    pub(crate) fn finish(self) -> Result<CapturedStream, Error> {
        Ok(CapturedStream {
            sha256: Sha256Digest::parse(hex::encode(self.hash.finalize()))
                .map_err(|_| Error::RuntimeFailure)?,
            observed_bytes: self.bytes,
            truncated: self.bytes > self.excerpt.len() as u64,
            excerpt: self.excerpt,
            complete: self.eof,
        })
    }
}

pub(crate) struct ProcessOutput {
    pub(crate) code: Option<i32>,
    pub(crate) stdout: CapturedStream,
    pub(crate) stderr: CapturedStream,
    pub(crate) trigger: Option<TerminationReason>,
}

/// Child guard prevents ordinary errors/panic abandoning the local runtime client.
struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(crate) struct IoPolicy {
    pub(crate) timeout: Duration,
    pub(crate) stdout: u64,
    pub(crate) stderr: u64,
    pub(crate) prefix: u64,
}

pub(crate) fn run(
    mut command: Command,
    input: &[u8],
    policy: IoPolicy,
    mut terminate: impl FnMut(),
) -> Result<ProcessOutput, Error> {
    command
        .stdin(if input.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = ChildGuard(command.spawn().map_err(|_| Error::RuntimeFailure)?);
    let mut stdout = child.0.stdout.take().ok_or(Error::RuntimeFailure)?;
    let mut stderr = child.0.stderr.take().ok_or(Error::RuntimeFailure)?;
    let mut stdin = child.0.stdin.take();
    fcntl_setfl(
        &stdout,
        fcntl_getfl(&stdout).map_err(|_| Error::RuntimeFailure)? | OFlags::NONBLOCK,
    )
    .map_err(|_| Error::RuntimeFailure)?;
    fcntl_setfl(
        &stderr,
        fcntl_getfl(&stderr).map_err(|_| Error::RuntimeFailure)? | OFlags::NONBLOCK,
    )
    .map_err(|_| Error::RuntimeFailure)?;
    if let Some(pipe) = &stdin {
        fcntl_setfl(
            pipe,
            fcntl_getfl(pipe).map_err(|_| Error::RuntimeFailure)? | OFlags::NONBLOCK,
        )
        .map_err(|_| Error::RuntimeFailure)?;
    }
    let mut out = Capture::new(policy.stdout, policy.prefix.min(policy.stdout));
    let mut err = Capture::new(policy.stderr, policy.prefix.min(policy.stderr));
    let started = Instant::now();
    let mut trigger = None;
    let mut drain_deadline = None;
    let mut written = 0;
    let mut status = None;
    loop {
        let stdout_limit = if !out.eof {
            out.read(&mut stdout)?
        } else {
            false
        };
        let stderr_limit = if !err.eof {
            err.read(&mut stderr)?
        } else {
            false
        };
        if let Some(pipe) = &mut stdin {
            let end = (written + 65536).min(input.len());
            match pipe.write(&input[written..end]) {
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    stdin = None;
                }
            }
            if written == input.len() {
                stdin = None;
            }
        }
        if status.is_none() {
            status = child.0.try_wait().map_err(|_| Error::RuntimeFailure)?;
        }
        // A completed client still needs pipe EOF. A runtime client closing stdin
        // early is not successful transfer, even if it reports exit zero.
        if trigger.is_none() {
            trigger = if stdout_limit {
                Some(TerminationReason::StdoutLimit)
            } else if stderr_limit {
                Some(TerminationReason::StderrLimit)
            } else if started.elapsed() >= policy.timeout {
                Some(TerminationReason::Timeout)
            } else {
                None
            };
            if trigger.is_some() {
                // Outside the target: kill the entire container before detaching the client.
                terminate();
                stdin = None;
                drain_deadline = Some(Instant::now() + Duration::from_secs(2));
            }
        }
        if status.is_some() && out.eof && err.eof {
            break;
        }
        if drain_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            let _ = child.0.kill();
            status = child.0.wait().ok();
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    if written != input.len() && trigger.is_none() {
        return Err(Error::RuntimeFailure);
    }
    Ok(ProcessOutput {
        code: status.and_then(|s| s.code()),
        stdout: out.finish()?,
        stderr: err.finish()?,
        trigger,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_prefix_hashes_every_observed_byte_and_escapes_terminal_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = b"\x1b[2Jbinary\xfflong";
        let mut capture = Capture::new(100, 3);
        assert!(!capture.read(&mut &bytes[..])?);
        let captured = capture.finish()?;
        assert_eq!(
            captured.sha256,
            archcert_domain::source::digest_bytes(bytes)
        );
        assert_eq!(captured.excerpt, &bytes[..3]);
        assert!(captured.truncated && captured.complete);
        let json = serde_json::to_string(&captured)?;
        assert!(!json.contains('\x1b'));
        Ok(())
    }
    #[test]
    fn output_budget_is_explicit_and_incomplete_hash_never_claims_full_stream() -> Result<(), Error>
    {
        let mut capture = Capture::new(2, 1);
        assert!(capture.read(&mut &b"flood"[..])?);
        let stream = capture.finish()?;
        assert_eq!(stream.observed_bytes, 5);
        assert!(stream.truncated);
        assert!(!stream.complete);
        Ok(())
    }
}
