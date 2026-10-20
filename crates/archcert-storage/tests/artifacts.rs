//! Real filesystem object semantics, independent of PostgreSQL metadata.
use archcert_application::{artifacts::ImmutableArtifactStore, jobs::ArtifactReference};
use archcert_domain::{ProjectId, source::digest_bytes};
use archcert_storage::artifacts::FilesystemArtifactStore;
use std::os::unix::fs::PermissionsExt;
#[tokio::test]
async fn immutable_objects_reject_mismatch_truncation_substitution_and_cross_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let store =
        FilesystemArtifactStore::open_unencrypted_development(&root.path().canonicalize()?)?;
    let project = ProjectId::new();
    let bytes = b"immutable evidence";
    let r = ArtifactReference {
        sha256: digest_bytes(bytes),
        size: bytes.len() as u64,
        schema: 1,
        producer: "test".into(),
    };
    assert!(store.get(project, &r).await.is_err());
    assert!(store.put(project, &r, b"truncated").await.is_err());
    store.put(project, &r, bytes).await?;
    store.put(project, &r, bytes).await?;
    assert_eq!(store.get(project, &r).await?, bytes);
    assert!(store.get(ProjectId::new(), &r).await.is_err());
    assert!(store.put(project, &r, b"replacement").await.is_err());
    let mut mismatch = r.clone();
    mismatch.size += 1;
    assert!(store.get(project, &mismatch).await.is_err());
    let scope = root.path().join(project.to_string());
    std::fs::write(scope.join(".staging-orphan"), b"interrupted upload")?;
    assert_eq!(store.get(project, &r).await?, bytes);
    let object = scope.join(r.sha256.as_str());
    std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&object, b"substituted bytes!")?;
    assert!(store.get(project, &r).await.is_err());
    assert!(store.put(project, &r, bytes).await.is_err());
    std::fs::remove_file(&object)?;
    std::os::unix::fs::symlink(scope.join(".staging-orphan"), &object)?;
    assert!(store.get(project, &r).await.is_err());
    Ok(())
}
