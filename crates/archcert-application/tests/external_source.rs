//! External bytes require authority mapping and verification; no URL fetch exists.
use archcert_application::external_source::{ExternalSourceAuthority, resolve_external_source};
use archcert_domain::{
    GitObjectId, ProjectId,
    materialization::SnapshotReference,
    source::{
        RepositoryId, SourceError, SourceFile, SourceLimits, SourceMode, SourcePath,
        SourceSnapshot, digest_bytes,
    },
};
use std::{io::Read, sync::Arc};
struct Authority {
    lfs: Vec<u8>,
    submodule: Option<Arc<SourceSnapshot>>,
    wrong_commit: bool,
}
impl ExternalSourceAuthority for Authority {
    fn lfs_object(
        &self,
        _: &SourceSnapshot,
        _: &SourcePath,
        _: &archcert_domain::Sha256Digest,
    ) -> Result<Box<dyn Read + '_>, SourceError> {
        Ok(Box::new(std::io::Cursor::new(&self.lfs)))
    }
    fn submodule(
        &self,
        _: &SourceSnapshot,
        _: &SourcePath,
    ) -> Result<(SnapshotReference, Arc<SourceSnapshot>), SourceError> {
        let snapshot = self
            .submodule
            .as_ref()
            .ok_or(SourceError::IncompleteExternalSource)?;
        let mut identity = snapshot.identity().clone();
        if self.wrong_commit {
            identity.commit = GitObjectId::parse("9".repeat(40))
                .map_err(|_| SourceError::InternalIntegrityFailure)?;
        }
        Ok((
            SnapshotReference {
                project: snapshot.project(),
                repository: snapshot.repository().clone(),
                identity,
            },
            Arc::clone(snapshot),
        ))
    }
}
fn snapshot(files: Vec<SourceFile>) -> Result<Arc<SourceSnapshot>, Box<dyn std::error::Error>> {
    Ok(Arc::new(SourceSnapshot::seal(
        ProjectId::new(),
        RepositoryId::parse("authority/repository")?,
        GitObjectId::parse("1".repeat(40))?,
        GitObjectId::parse("2".repeat(40))?,
        files,
        3,
        1,
    )?))
}
fn file(name: &str, mode: SourceMode, bytes: &[u8]) -> Result<SourceFile, SourceError> {
    Ok(SourceFile::new(
        SourcePath::from_bytes(name.as_bytes())?,
        mode,
        bytes.to_vec(),
    ))
}
#[test]
fn lfs_digest_and_size_are_verified_in_a_new_immutable_representation()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = b"resolved source";
    let pointer = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {}\n",
        digest_bytes(bytes).as_str(),
        bytes.len()
    );
    let original = snapshot(vec![file("data", SourceMode::File, pointer.as_bytes())?])?;
    let identity = original.identity().clone();
    let authority = Authority {
        lfs: bytes.to_vec(),
        submodule: None,
        wrong_commit: false,
    };
    let resolved =
        resolve_external_source(Arc::clone(&original), &authority, SourceLimits::default())?;
    assert_eq!(resolved.files()[0].bytes(), bytes);
    assert_ne!(resolved.digest(), &identity.snapshot_sha256);
    assert_eq!(original.identity(), &identity);
    assert!(original.require_complete().is_err());
    let repeated =
        resolve_external_source(Arc::clone(&original), &authority, SourceLimits::default())?;
    assert_eq!(resolved.canonical_bytes(), repeated.canonical_bytes());
    for lfs in [b"wrong content".to_vec(), b"resolved source extra".to_vec()] {
        assert!(
            resolve_external_source(
                Arc::clone(&original),
                &Authority {
                    lfs,
                    submodule: None,
                    wrong_commit: false
                },
                SourceLimits::default()
            )
            .is_err()
        );
    }
    Ok(())
}
#[test]
fn submodule_urls_are_never_authority_and_only_exact_complete_mappings_resolve()
-> Result<(), Box<dyn std::error::Error>> {
    let child = snapshot(vec![file("child", SourceMode::File, b"immutable")?])?;
    for url in [
        "file:///etc",
        "https://localhost/",
        "http://169.254.169.254/",
        "ssh://git@internal/",
        "https://user:password@example.com/repo",
        "https://127.0.0.1/repo",
    ] {
        let original = snapshot(vec![
            file(
                ".gitmodules",
                SourceMode::File,
                format!("[submodule \"module\"]\npath = module\nurl = {url}\n").as_bytes(),
            )?,
            file(
                "module",
                SourceMode::Submodule,
                child.identity().commit.as_str().as_bytes(),
            )?,
        ])?;
        assert!(
            resolve_external_source(
                Arc::clone(&original),
                &Authority {
                    lfs: vec![],
                    submodule: None,
                    wrong_commit: false
                },
                SourceLimits::default()
            )
            .is_err()
        );
        assert!(
            resolve_external_source(
                Arc::clone(&original),
                &Authority {
                    lfs: vec![],
                    submodule: Some(Arc::clone(&child)),
                    wrong_commit: true
                },
                SourceLimits::default()
            )
            .is_err()
        );
        let resolved = resolve_external_source(
            original,
            &Authority {
                lfs: vec![],
                submodule: Some(Arc::clone(&child)),
                wrong_commit: false,
            },
            SourceLimits::default(),
        )?;
        assert!(
            resolved
                .files()
                .iter()
                .any(|f| f.path().as_str() == "module/child")
        );
    }
    Ok(())
}
