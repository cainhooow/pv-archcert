//! Bounded framing around gitoxide's pack entry and delta implementations.

use crate::loose::{ObjectReader, validate_objects};
use archcert_application::source::{GitGateway, SourceQuarantine, ValidatedSource};
use archcert_domain::{
    GitObjectId,
    source::{RepositoryId, ResourceLimit, SourceError, SourceLimits},
};
use flate2::{Decompress, FlushDecompress, Status};
use gix_pack::data::{self, entry::Header};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    io::{BufRead, Read},
    sync::Arc,
};

fn malformed(error: std::io::Error) -> SourceError {
    if error.kind() == std::io::ErrorKind::TimedOut {
        SourceError::SessionTimeout
    } else if error.get_ref().is_some_and(|e| e.is::<PackByteLimit>()) {
        limit(ResourceLimit::PackBytes)
    } else {
        SourceError::MalformedGitObject
    }
}

#[derive(Debug)]
struct PackByteLimit;

impl std::fmt::Display for PackByteLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pack byte budget exhausted")
    }
}

impl std::error::Error for PackByteLimit {}

fn invalid<E>(_: E) -> SourceError {
    SourceError::MalformedGitObject
}

fn limit(kind: ResourceLimit) -> SourceError {
    SourceError::LimitExceeded(kind)
}

/// Authority-selected object format. Never inferred from an untrusted Git config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitObjectFormat {
    /// Git SHA-1 compatibility; independent source identity still uses SHA-256.
    Sha1,
    /// Git's SHA-256 object format.
    Sha256,
}

impl GitObjectFormat {
    /// Hexadecimal object ID width.
    pub fn width(self) -> usize {
        self.kind().len_in_bytes() * 2
    }

    fn kind(self) -> gix_hash::Kind {
        match self {
            Self::Sha1 => gix_hash::Kind::Sha1,
            Self::Sha256 => gix_hash::Kind::Sha256,
        }
    }

    fn hash(self, bytes: &[u8]) -> String {
        match self {
            Self::Sha1 => hex::encode(sha1::Sha1::digest(bytes)),
            Self::Sha256 => hex::encode(sha2::Sha256::digest(bytes)),
        }
    }

    /// Git format name for the isolated protocol adapter.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }
}

/// Finite transport, decoding and expansion budgets, separate from tree traversal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackLimits {
    /// Maximum complete pack, including headers and trailer.
    pub max_pack_bytes: u64,
    /// Maximum advertised pack entries, including unreachable entries.
    pub max_objects: u32,
    /// Maximum entry payload or resolved individual object bytes.
    pub max_object_bytes: u64,
    /// Aggregate inflated entry bytes plus retained resolved object bytes and decode work.
    pub max_decoded_bytes: u64,
    /// Maximum number of delta ancestors before decoding.
    pub max_delta_depth: u32,
    /// Maximum resolved bytes per compressed entry byte, with a 1 KiB allowance.
    pub max_expansion_ratio: u64,
}

impl Default for PackLimits {
    fn default() -> Self {
        Self {
            max_pack_bytes: 64 * 1024 * 1024,
            max_objects: 25_000,
            max_object_bytes: 9 * 1024 * 1024,
            max_decoded_bytes: 256 * 1024 * 1024,
            max_delta_depth: 32,
            max_expansion_ratio: 4096,
        }
    }
}

impl PackLimits {
    /// Rejects zero, overflow-prone or unsafe development budgets.
    pub fn validate(self) -> Result<Self, SourceError> {
        if self.max_pack_bytes == 0
            || self.max_pack_bytes > 256 * 1024 * 1024
            || self.max_objects == 0
            || self.max_objects > 100_000
            || self.max_object_bytes == 0
            || self.max_object_bytes > 32 * 1024 * 1024
            || self.max_decoded_bytes == 0
            || self.max_decoded_bytes > 1024 * 1024 * 1024
            || self.max_delta_depth == 0
            || self.max_delta_depth > 64
            || self.max_expansion_ratio == 0
            || self.max_expansion_ratio > 4096
        {
            return Err(SourceError::UnsupportedRepository);
        }

        Ok(self)
    }
}

/// Measurements collected even when pack reception fails. A prefix has no complete digest.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackReception {
    /// Bytes inspected by framing, including one verified excess byte at the cap.
    pub bytes: u64,
    /// Entry count from the parsed pack header, when available.
    pub objects: Option<u32>,
    /// Sum of declared inflated entry sizes inspected so far.
    pub inflated_bytes: u64,
}

struct Capture<'a, R> {
    observation: &'a mut PackReception,
    inner: R,
    bytes: Vec<u8>,
    cap: u64,
}

impl<R: BufRead> Read for Capture<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        let n = {
            let input = self.fill_buf()?;
            let n = input.len().min(out.len());
            out[..n].copy_from_slice(&input[..n]);
            n
        };
        self.consume(n);

        Ok(n)
    }
}

impl<R: BufRead> BufRead for Capture<'_, R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        let remaining = self.cap.saturating_sub(self.bytes.len() as u64) as usize;

        if remaining == 0 {
            if self.inner.fill_buf()?.is_empty() {
                return Ok(&[]);
            }

            // Inspect one actual excess byte without retaining an unbounded suffix.
            self.observation.bytes = self.cap + 1;
            return Err(std::io::Error::other(PackByteLimit));
        }

        let input = self.inner.fill_buf()?;

        Ok(&input[..input.len().min(remaining)])
    }

    fn consume(&mut self, n: usize) {
        // Only called with bytes returned by fill_buf/read in this module or gitoxide.
        if let Ok(input) = self.inner.fill_buf() {
            self.bytes.extend_from_slice(&input[..n]);
        }

        self.inner.consume(n);
        self.observation.bytes = self.bytes.len() as u64;
    }
}

/// Reads exactly one self-contained pack from a live receive stream without waiting
/// for EOF. Entry headers use gitoxide. Inflation uses fixed buffers and rejects
/// overproduction immediately; no allocation follows an unchecked declared size.
/// Thin bases outside this submission are deliberately unsupported.
pub fn receive_pack(
    reader: impl BufRead,
    format: GitObjectFormat,
    limits: PackLimits,
) -> Result<Vec<u8>, SourceError> {
    receive_pack_observed(reader, format, limits, &mut PackReception::default())
}

/// Receives a pack while retaining bounded progress measurements on failure.
pub fn receive_pack_observed(
    reader: impl BufRead,
    format: GitObjectFormat,
    limits: PackLimits,
    observation: &mut PackReception,
) -> Result<Vec<u8>, SourceError> {
    receive_pack_until(reader, format, limits, observation, None)
}

/// Applies the session deadline during framing and fixed-buffer inflation too.
pub fn receive_pack_until(
    reader: impl BufRead,
    format: GitObjectFormat,
    limits: PackLimits,
    observation: &mut PackReception,
    deadline: Option<std::time::Instant>,
) -> Result<Vec<u8>, SourceError> {
    *observation = PackReception::default();
    let limits = limits.validate()?;
    let mut input = Capture {
        observation,
        inner: reader,
        bytes: Vec::new(),
        cap: limits.max_pack_bytes,
    };
    let mut header = [0; data::header::SIZE];
    input.read_exact(&mut header).map_err(malformed)?;
    let (_, count) = data::header::decode(&header).map_err(invalid)?;

    input.observation.objects = Some(count);

    if count > limits.max_objects {
        return Err(limit(ResourceLimit::Objects));
    }

    let mut total = 0u64;

    for _ in 0..count {
        check_deadline(deadline)?;
        let offset = input.bytes.len() as u64;
        let entry =
            data::Entry::from_read(&mut input, offset, format.width() / 2).map_err(malformed)?;

        if entry.decompressed_size > limits.max_object_bytes {
            return Err(limit(ResourceLimit::ObjectBytes));
        }

        total = total
            .checked_add(entry.decompressed_size)
            .ok_or(limit(ResourceLimit::ObjectWorkBytes))?;

        input.observation.inflated_bytes = total;

        if total > limits.max_decoded_bytes {
            return Err(limit(ResourceLimit::ObjectWorkBytes));
        }

        let mut decoder = Decompress::new(true);
        let mut output = [0; 8192];

        loop {
            check_deadline(deadline)?;
            let before_in = decoder.total_in();
            let before_out = decoder.total_out();
            let status = decoder
                .decompress(
                    input.fill_buf().map_err(malformed)?,
                    &mut output,
                    FlushDecompress::None,
                )
                .map_err(invalid)?;
            input.consume((decoder.total_in() - before_in) as usize);

            if decoder.total_out() > entry.decompressed_size {
                return Err(SourceError::MalformedGitObject);
            }

            if status == Status::StreamEnd {
                break;
            }

            if decoder.total_in() == before_in && decoder.total_out() == before_out {
                return Err(SourceError::MalformedGitObject);
            }
        }

        if decoder.total_out() != entry.decompressed_size {
            return Err(SourceError::MalformedGitObject);
        }
    }

    let end = input.bytes.len();
    let mut trailer = vec![0; format.width() / 2];
    input.read_exact(&mut trailer).map_err(malformed)?;

    if format.hash(&input.bytes[..end]) != hex::encode(trailer) {
        return Err(SourceError::ObjectIdentityMismatch);
    }

    Ok(input.bytes)
}

fn check_deadline(deadline: Option<std::time::Instant>) -> Result<(), SourceError> {
    if deadline.is_some_and(|end| std::time::Instant::now() >= end) {
        return Err(SourceError::SessionTimeout);
    }

    Ok(())
}

/// Decoder work measured according to the existing conservative accounting algorithm.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackDecoding {
    /// Inflated entry bytes plus resolution ancestry work charged before decoding.
    pub work_bytes: u64,
    /// Successfully verified pack entries, including duplicate identities.
    pub resolved_objects: u32,
}

/// Immutable, independently decoded pack, suitable for the existing source port.
/// No Git executable is involved in object validation or source hashing.
pub struct PackedGitGateway {
    repository: RepositoryId,
    objects: Arc<PackObjects>,
}

struct PackObjects {
    objects: BTreeMap<String, Vec<u8>>,
}

impl PackedGitGateway {
    /// Validates framing, checksums, all deltas and resource budgets before exposing
    /// a quarantine reader. Selected commit/tree grammar remains the M1 validator.
    pub fn new(
        repository: RepositoryId,
        bytes: &[u8],
        format: GitObjectFormat,
        limits: PackLimits,
    ) -> Result<Self, SourceError> {
        Self::new_until(
            repository,
            bytes,
            format,
            limits,
            std::time::Instant::now() + std::time::Duration::from_secs(30),
            &mut PackDecoding::default(),
        )
    }

    /// Decodes under the same absolute authority deadline as input and system Git.
    pub fn new_until(
        repository: RepositoryId,
        bytes: &[u8],
        format: GitObjectFormat,
        limits: PackLimits,
        deadline: std::time::Instant,
        observation: &mut PackDecoding,
    ) -> Result<Self, SourceError> {
        *observation = PackDecoding::default();
        let limits = limits.validate()?;
        check_deadline(Some(deadline))?;

        if bytes.len() as u64 > limits.max_pack_bytes {
            return Err(limit(ResourceLimit::PackBytes));
        }

        let framed = receive_pack_until(
            std::io::Cursor::new(bytes),
            format,
            limits,
            &mut PackReception::default(),
            Some(deadline),
        )?;

        if framed.len() != bytes.len() {
            return Err(SourceError::MalformedGitObject);
        }

        let file = data::File::from_data(framed, "quarantined.pack".into(), format.kind())
            .map_err(invalid)?
            .with_alloc_limit_bytes(Some(
                (limits.max_object_bytes * 2 + limits.max_decoded_bytes.min(32 * 1024 * 1024))
                    as usize,
            ));
        let mut entries = BTreeMap::new();
        let mut offset = data::header::SIZE as u64;
        let mut inflate = gix_zlib::Inflate::default();
        let mut work = 0u64;

        for _ in 0..file.num_objects() {
            check_deadline(Some(deadline))?;

            let entry = file.entry(offset).map_err(invalid)?;
            work = work
                .checked_add(entry.decompressed_size)
                .ok_or(limit(ResourceLimit::ObjectWorkBytes))?;
            let mut out = vec![0; entry.decompressed_size as usize];
            let consumed = file
                .decompress_entry(&entry, &mut inflate, &mut out)
                .map_err(invalid)?;
            offset = entry
                .data_offset
                .checked_add(consumed as u64)
                .ok_or(SourceError::MalformedGitObject)?;
            entries.insert(entry.pack_offset(), (entry, consumed as u64));
        }

        if offset != file.pack_end() as u64 {
            return Err(SourceError::MalformedGitObject);
        }

        let mut objects = BTreeMap::new();
        let mut identities = BTreeMap::<String, data::Entry>::new();
        let mut resolved = BTreeMap::<u64, (u32, u64)>::new();
        let mut pending = entries.clone();

        // A round either resolves at least one object or rejects missing/cyclic bases.
        // Work is bounded by object count times the hard delta depth ceiling.
        for _ in 0..=limits.max_delta_depth + 1 {
            if pending.is_empty() {
                break;
            }

            let mut progress = false;

            for (&at, (stored_entry, compressed)) in &entries {
                check_deadline(Some(deadline))?;

                let entry = stored_entry.clone();
                let compressed = *compressed;

                if !pending.contains_key(&at) {
                    continue;
                }

                let base = match entry.header {
                    Header::OfsDelta { base_distance } => Some(
                        entry
                            .checked_base_pack_offset(base_distance)
                            .ok_or(SourceError::MalformedGitObject)?,
                    ),
                    Header::RefDelta { base_id } => identities
                        .get(&base_id.to_string())
                        .map(data::Entry::pack_offset),
                    _ => None,
                };

                if let Header::OfsDelta { .. } = entry.header
                    && !entries.contains_key(&base.ok_or(SourceError::MalformedGitObject)?)
                {
                    return Err(SourceError::MalformedGitObject);
                }

                if entry.header.is_delta() && base.is_none() {
                    continue;
                }

                let (depth, chain_work) = if let Some(base) = base {
                    let Some(&(depth, chain_work)) = resolved.get(&base) else {
                        continue;
                    };
                    (depth + 1, chain_work)
                } else {
                    (0, 0)
                };

                if depth > limits.max_delta_depth {
                    return Err(limit(ResourceLimit::DeltaDepth));
                }

                let resolve_header = |id: &gix_hash::oid| {
                    Ok(identities
                        .get(&id.to_string())
                        .cloned()
                        .map(data::decode::header::ResolvedBase::InPack))
                };
                let header = file
                    .decode_header(entry.clone(), &mut inflate, &resolve_header)
                    .map_err(invalid)?;

                if header.object_size > limits.max_object_bytes {
                    return Err(limit(ResourceLimit::ObjectBytes));
                }

                if header.object_size
                    > compressed
                        .saturating_mul(limits.max_expansion_ratio)
                        .saturating_add(1024)
                {
                    return Err(limit(ResourceLimit::DeltaExpansion));
                }

                let chain_work = chain_work
                    .checked_add(entry.decompressed_size)
                    .and_then(|v| v.checked_add(header.object_size))
                    .ok_or(limit(ResourceLimit::ObjectWorkBytes))?;
                work = work
                    .checked_add(chain_work)
                    .ok_or(limit(ResourceLimit::ObjectWorkBytes))?;

                observation.work_bytes = work;

                if work > limits.max_decoded_bytes {
                    return Err(limit(ResourceLimit::ObjectWorkBytes));
                }

                let resolve = |id: &gix_hash::oid, _: &mut Vec<u8>| {
                    Ok(identities
                        .get(&id.to_string())
                        .cloned()
                        .map(data::decode::entry::ResolvedBase::InPack))
                };

                let mut out = Vec::new();
                let outcome = file
                    .decode_entry(
                        entry.clone(),
                        &mut out,
                        &mut inflate,
                        &resolve,
                        &mut gix_pack::cache::Never,
                    )
                    .map_err(invalid)?;

                if out.len() as u64 != header.object_size || outcome.num_deltas != depth {
                    return Err(SourceError::MalformedGitObject);
                }

                let mut raw = format!("{} {}\0", outcome.kind, out.len()).into_bytes();
                raw.extend_from_slice(&out);
                let oid = format.hash(&raw);

                if let Some(old) = objects.insert(oid.clone(), raw.clone())
                    && old != raw
                {
                    return Err(SourceError::ObjectIdentityMismatch);
                }

                // Keep the first verified base mapping immutable. A duplicate
                // object stored as a delta must not redirect an earlier ref base
                // into itself or silently deepen already checked ancestry.
                identities.entry(oid).or_insert(entry);
                resolved.insert(at, (depth, chain_work));
                pending.remove(&at);
                observation.resolved_objects += 1;
                progress = true;
            }

            if !progress {
                return Err(SourceError::MalformedGitObject);
            }
        }

        if !pending.is_empty() {
            return Err(limit(ResourceLimit::DeltaDepth));
        }

        Ok(Self {
            repository,
            objects: Arc::new(PackObjects { objects }),
        })
    }
}

impl ObjectReader for PackObjects {
    fn read_object(
        &self,
        oid: &GitObjectId,
        cap: u64,
        work_remaining: u64,
    ) -> Result<(Vec<u8>, u64), SourceError> {
        let bytes = self
            .objects
            .get(oid.as_str())
            .ok_or(SourceError::CommitNotFound)?;

        if bytes.len() as u64 > cap {
            return Err(limit(ResourceLimit::ObjectBytes));
        }

        if bytes.len() as u64 > work_remaining {
            return Err(limit(ResourceLimit::ObjectWorkBytes));
        }

        Ok((bytes.clone(), bytes.len() as u64))
    }
}

struct PackQuarantine(Arc<PackObjects>);

impl GitGateway for PackedGitGateway {
    fn validation_version(&self) -> &'static str {
        "archcert-pack-v1"
    }

    fn quarantine(
        &self,
        repository: &RepositoryId,
    ) -> Result<Box<dyn SourceQuarantine>, SourceError> {
        if repository != &self.repository {
            return Err(SourceError::RepositoryAccessFailure);
        }

        Ok(Box::new(PackQuarantine(Arc::clone(&self.objects))))
    }
}

impl SourceQuarantine for PackQuarantine {
    fn validate(
        &mut self,
        commit: &GitObjectId,
        limits: SourceLimits,
    ) -> Result<ValidatedSource, SourceError> {
        validate_objects(self.0.as_ref(), commit, limits)
    }
}

#[cfg(test)]
mod reception_tests {
    use super::*;
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    fn pack() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = data::header::encode(data::Version::V2, 1).to_vec();
        Header::Blob.write_to(3, &mut bytes)?;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"abc")?;
        bytes.extend(encoder.finish()?);
        bytes.extend(sha1::Sha1::digest(bytes.clone()));

        Ok(bytes)
    }

    #[test]
    fn exact_pack_capacity_and_rejected_prefix_are_distinguished()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = pack()?;
        let mut observation = PackReception::default();
        let limits = PackLimits {
            max_pack_bytes: bytes.len() as u64,
            ..PackLimits::default()
        };

        assert_eq!(
            receive_pack_observed(
                std::io::Cursor::new(&bytes),
                GitObjectFormat::Sha1,
                limits,
                &mut observation
            )?,
            bytes
        );
        assert_eq!(observation.bytes, bytes.len() as u64);
        assert_eq!(observation.objects, Some(1));

        let limits = PackLimits {
            max_pack_bytes: bytes.len() as u64 - 1,
            ..limits
        };
        let result = receive_pack_observed(
            std::io::Cursor::new(&bytes),
            GitObjectFormat::Sha1,
            limits,
            &mut observation,
        );

        assert_eq!(result, Err(limit(ResourceLimit::PackBytes)));
        assert_eq!(observation.bytes, bytes.len() as u64);

        Ok(())
    }

    #[test]
    fn oversized_declared_entry_and_count_reject_before_allocation()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = data::header::encode(data::Version::V2, 1).to_vec();
        Header::Blob.write_to(u64::MAX, &mut bytes)?;
        let mut observation = PackReception::default();

        assert_eq!(
            receive_pack_observed(
                std::io::Cursor::new(&bytes),
                GitObjectFormat::Sha1,
                PackLimits::default(),
                &mut observation
            ),
            Err(limit(ResourceLimit::ObjectBytes))
        );

        let header = data::header::encode(data::Version::V2, 25_001);

        assert_eq!(
            receive_pack_observed(
                std::io::Cursor::new(header),
                GitObjectFormat::Sha1,
                PackLimits::default(),
                &mut observation
            ),
            Err(limit(ResourceLimit::Objects))
        );
        assert_eq!(observation.objects, Some(25_001));
        assert_eq!(observation.bytes, 12);

        Ok(())
    }

    #[test]
    fn timeout_is_preserved_instead_of_malformed_object() {
        assert_eq!(
            malformed(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "untrusted detail"
            )),
            SourceError::SessionTimeout
        );
        assert_eq!(
            malformed(std::io::Error::other("untrusted detail")),
            SourceError::MalformedGitObject
        );
    }
}
