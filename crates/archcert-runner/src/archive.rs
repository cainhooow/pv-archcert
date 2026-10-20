//! Controlled archive transfer: never unpack runtime archives onto the host.
use archcert_domain::{
    SourceIdentity,
    execution::ExecutionError as Error,
    source::{SourceBinding, SourceFile, SourceManifest, SourceMode, SourcePath},
};
use std::{
    collections::BTreeSet,
    io::{Cursor, Read, Write},
    os::unix::ffi::OsStrExt,
};

// Source schema defaults plus conservative tar overhead. The export has its own
// hard ceiling even when a caller raises materialization limits.
pub(crate) const MAX_ARCHIVE: u64 = 96 * 1024 * 1024;
const MAX_FILES: usize = 10_000;
const MAX_BYTES: u64 = 64 * 1024 * 1024;

fn dirs(files: &[SourceFile]) -> Result<BTreeSet<String>, Error> {
    let mut dirs = BTreeSet::from(["source".to_owned()]);
    for file in files {
        let parts: Vec<_> = file.path().as_str().split('/').collect();
        for end in 1..parts.len() {
            dirs.insert(format!("source/{}", parts[..end].join("/")));
            if dirs.len() > 10_001 {
                return Err(Error::SourceIntegrity);
            }
        }
    }
    Ok(dirs)
}
fn header(mode: u32, size: u64, kind: tar::EntryType) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    h.set_uid(10001);
    h.set_gid(10001);
    h.set_mtime(0);
    h.set_mode(mode);
    h.set_size(size);
    h.set_entry_type(kind);
    h
}
struct ArchiveBuffer(Vec<u8>);
impl Write for ArchiveBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len() as u64 + bytes.len() as u64 > MAX_ARCHIVE {
            return Err(std::io::Error::other("archive budget exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn encode(files: &[SourceFile]) -> Result<Vec<u8>, Error> {
    if files.len() > MAX_FILES
        || files.iter().map(|f| f.bytes().len() as u64).sum::<u64>() > MAX_BYTES
    {
        return Err(Error::SourceIntegrity);
    }
    let mut builder = tar::Builder::new(ArchiveBuffer(Vec::new()));
    builder.follow_symlinks(false);
    for dir in dirs(files)? {
        builder
            .append_data(
                &mut header(0o555, 0, tar::EntryType::Directory),
                dir,
                &[][..],
            )
            .map_err(|_| Error::SourceIntegrity)?;
    }
    for file in files {
        let path = format!("source/{}", file.path().as_str());
        match file.mode() {
            SourceMode::File | SourceMode::Executable => {
                builder
                    .append_data(
                        &mut header(
                            if file.mode() == SourceMode::Executable {
                                0o555
                            } else {
                                0o444
                            },
                            file.bytes().len() as u64,
                            tar::EntryType::Regular,
                        ),
                        path,
                        file.bytes(),
                    )
                    .map_err(|_| Error::SourceIntegrity)?;
            }
            SourceMode::Symlink => {
                let target = std::ffi::OsStr::from_bytes(file.bytes());
                builder
                    .append_link(&mut header(0o777, 0, tar::EntryType::Symlink), path, target)
                    .map_err(|_| Error::SourceIntegrity)?;
            }
            _ => return Err(Error::SourceIntegrity),
        }
    }
    let bytes = builder.into_inner().map_err(|_| Error::SourceIntegrity)?.0;
    if bytes.len() as u64 > MAX_ARCHIVE {
        return Err(Error::SourceIntegrity);
    }
    Ok(bytes)
}

/// Independently reconstruct the stopped sandbox source view. No host extraction,
/// lossy decoding, hardlink/device support or trusting a target-provided manifest.
#[cfg(test)]
pub(crate) fn verify(bytes: &[u8], identity: &SourceIdentity) -> Result<(), Error> {
    verify_bound(bytes, identity, &SourceBinding::default())
}
pub(crate) fn verify_bound(
    bytes: &[u8],
    identity: &SourceIdentity,
    binding: &SourceBinding,
) -> Result<(), Error> {
    if bytes.len() as u64 > MAX_ARCHIVE {
        return Err(Error::SourceIntegrity);
    }
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut files = Vec::new();
    let mut directories = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    for item in archive.entries().map_err(|_| Error::SourceIntegrity)? {
        let mut entry = item.map_err(|_| Error::SourceIntegrity)?;
        let raw = entry.path_bytes();
        let kind = entry.header().entry_type();
        let raw_text = std::str::from_utf8(&raw).map_err(|_| Error::SourceIntegrity)?;
        let text = if kind.is_dir() {
            raw_text.strip_suffix('/').unwrap_or(raw_text)
        } else {
            raw_text
        }
        .to_owned();
        if !names.insert(text.clone()) || names.len() > 20_001 {
            return Err(Error::SourceIntegrity);
        }
        let permissions = entry.header().mode().map_err(|_| Error::SourceIntegrity)?;
        if text == "source" {
            if !kind.is_dir() || permissions & 0o7777 != 0o555 {
                return Err(Error::SourceIntegrity);
            }
            directories.insert(text);
            continue;
        }
        let relative = text.strip_prefix("source/").ok_or(Error::SourceIntegrity)?;
        let path =
            SourcePath::from_bytes(relative.as_bytes()).map_err(|_| Error::SourceIntegrity)?;
        let permissions = entry.header().mode().map_err(|_| Error::SourceIntegrity)?;
        if kind.is_dir() {
            if permissions & 0o7777 != 0o555 {
                return Err(Error::SourceIntegrity);
            }
            directories.insert(text);
            continue;
        }
        let (mode, content) = if kind.is_file() {
            let mode = match permissions & 0o7777 {
                0o444 => SourceMode::File,
                0o555 => SourceMode::Executable,
                _ => return Err(Error::SourceIntegrity),
            };
            let size = entry.size();
            if size > 8 * 1024 * 1024 || total.saturating_add(size) > MAX_BYTES {
                return Err(Error::SourceIntegrity);
            }
            let mut content = Vec::new();
            (&mut entry)
                .take(size + 1)
                .read_to_end(&mut content)
                .map_err(|_| Error::SourceIntegrity)?;
            if content.len() as u64 != size {
                return Err(Error::SourceIntegrity);
            }
            (mode, content)
        } else if kind.is_symlink() {
            let link = entry.link_name_bytes().ok_or(Error::SourceIntegrity)?;
            if link.is_empty() || link.len() > 4096 || link.contains(&0) {
                return Err(Error::SourceIntegrity);
            }
            (SourceMode::Symlink, link.into_owned())
        } else {
            return Err(Error::SourceIntegrity);
        };
        total += content.len() as u64;
        files.push(SourceFile::new(path, mode, content));
        if files.len() > MAX_FILES || total > MAX_BYTES {
            return Err(Error::SourceIntegrity);
        }
    }
    if directories != dirs(&files)? {
        return Err(Error::SourceIntegrity);
    }
    let manifest = SourceManifest::new(files.iter().map(SourceFile::manifest_entry).collect())
        .map_err(|_| Error::SourceIntegrity)?;
    if binding
        .digest(&manifest)
        .map_err(|_| Error::SourceIntegrity)?
        != identity.snapshot_sha256
    {
        return Err(Error::SourceIntegrity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use archcert_domain::{GitObjectId, source::digest_bytes};
    #[test]
    fn unexpected_directories_modes_hardlinks_and_traversal_reject()
    -> Result<(), Box<dyn std::error::Error>> {
        let files = [SourceFile::new(
            SourcePath::from_bytes(b"a")?,
            SourceMode::File,
            b"abc".to_vec(),
        )];
        let identity = SourceIdentity {
            commit: GitObjectId::parse("a".repeat(40))?,
            tree: GitObjectId::parse("b".repeat(40))?,
            snapshot_sha256: SourceManifest::new(
                files.iter().map(SourceFile::manifest_entry).collect(),
            )?
            .digest(),
        };
        for variation in 0..5 {
            let mut builder = tar::Builder::new(Vec::new());
            builder.append_data(
                &mut header(
                    if variation == 0 { 0o777 } else { 0o555 },
                    0,
                    tar::EntryType::Directory,
                ),
                "source",
                &[][..],
            )?;
            if variation == 1 {
                builder.append_data(
                    &mut header(0o555, 0, tar::EntryType::Directory),
                    "source/extra",
                    &[][..],
                )?;
            }
            if variation == 2 {
                builder.append_link(
                    &mut header(0o444, 0, tar::EntryType::Link),
                    "source/a",
                    "/etc/host-only",
                )?;
            } else if variation == 3 {
                let mut h = header(0o444, 3, tar::EntryType::Regular);
                h.as_mut_bytes()[..512]
                    .iter_mut()
                    .take(100)
                    .for_each(|b| *b = 0);
                h.as_mut_bytes()[..10].copy_from_slice(b"source/../");
                h.set_cksum();
                builder.append(&h, &b"abc"[..])?;
            } else {
                builder.append_data(
                    &mut header(
                        if variation == 4 { 0o4755 } else { 0o444 },
                        3,
                        tar::EntryType::Regular,
                    ),
                    "source/a",
                    &b"abc"[..],
                )?;
            }
            assert_eq!(
                verify(&builder.into_inner()?, &identity),
                Err(Error::SourceIntegrity),
                "variation {variation}"
            );
        }
        Ok(())
    }
    #[test]
    fn archive_writer_enforces_storage_limit_before_allocating_output() {
        let mut writer = ArchiveBuffer(Vec::new());
        assert!(writer.write(&[0; 512]).is_ok());
        // Seed a near-limit logical buffer once; an excessive next write must
        // fail without extending it. No unbounded archive is ever constructed.
        writer.0.resize(MAX_ARCHIVE as usize, 0);
        assert!(writer.write(b"x").is_err());
        assert_eq!(writer.0.len(), MAX_ARCHIVE as usize);
    }

    #[test]
    fn source_archive_round_trip_and_substitution_rejection()
    -> Result<(), Box<dyn std::error::Error>> {
        let files = vec![
            SourceFile::new(
                SourcePath::from_bytes(b"dir/a")?,
                SourceMode::Executable,
                b"abc".to_vec(),
            ),
            SourceFile::new(
                SourcePath::from_bytes(b"escape")?,
                SourceMode::Symlink,
                b"/host/secret".to_vec(),
            ),
        ];
        let mut identity = SourceIdentity {
            commit: GitObjectId::parse("a".repeat(40))?,
            tree: GitObjectId::parse("b".repeat(40))?,
            snapshot_sha256: SourceManifest::new(
                files.iter().map(SourceFile::manifest_entry).collect(),
            )?
            .digest(),
        };
        let bytes = encode(&files)?;
        verify(&bytes, &identity)?;
        identity.snapshot_sha256 = digest_bytes(b"other");
        assert_eq!(verify(&bytes, &identity), Err(Error::SourceIntegrity));
        assert_eq!(verify(b"not a tar", &identity), Err(Error::SourceIntegrity));
        Ok(())
    }
}

#[cfg(test)]
mod resolved_tests {
    use super::*;
    use archcert_domain::{
        GitObjectId, ProjectId,
        source::{RepositoryId, ResolvedDependency, SourceSnapshot, digest_bytes},
    };
    #[test]
    fn stopped_sandbox_view_verifies_resolved_recipe_and_rejects_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let data = b"verified LFS content";
        let path = SourcePath::from_bytes(b"asset")?;
        let pointer = format!(
            "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {}\n",
            digest_bytes(data).as_str(),
            data.len()
        );
        let original = SourceSnapshot::seal(
            ProjectId::new(),
            RepositoryId::parse("test/repository")?,
            GitObjectId::parse("1".repeat(40))?,
            GitObjectId::parse("2".repeat(40))?,
            vec![SourceFile::new(
                path.clone(),
                SourceMode::File,
                pointer.into_bytes(),
            )],
            3,
            1,
        )?;
        let snapshot = SourceSnapshot::seal_resolved(
            &original,
            vec![SourceFile::new(
                path.clone(),
                SourceMode::File,
                data.to_vec(),
            )],
            vec![ResolvedDependency::Lfs {
                path: path.clone(),
                sha256: digest_bytes(data),
                size: data.len() as u64,
            }],
            2,
        )?;
        let bytes = encode(snapshot.files())?;
        verify_bound(&bytes, snapshot.identity(), snapshot.binding())?;
        assert_eq!(
            verify(&bytes, snapshot.identity()),
            Err(Error::SourceIntegrity)
        );
        let substituted = encode(&[SourceFile::new(
            path,
            SourceMode::File,
            b"substitution".to_vec(),
        )])?;
        assert_eq!(
            verify_bound(&substituted, snapshot.identity(), snapshot.binding()),
            Err(Error::SourceIntegrity)
        );
        Ok(())
    }
}
