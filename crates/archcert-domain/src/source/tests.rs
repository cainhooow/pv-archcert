use super::*;

fn entry(path: &str, bytes: &[u8], mode: SourceMode) -> Result<ManifestEntry, SourceError> {
    Ok(ManifestEntry::new(
        SourcePath::from_bytes(path.as_bytes())?,
        mode,
        digest_bytes(bytes),
        bytes.len() as u64,
    ))
}

fn snapshot(
    files: Vec<SourceFile>,
    time: u64,
) -> Result<SourceSnapshot, Box<dyn std::error::Error>> {
    Ok(SourceSnapshot::seal(
        ProjectId::new(),
        RepositoryId::parse("test/repository")?,
        GitObjectId::parse("1".repeat(40))?,
        GitObjectId::parse("2".repeat(40))?,
        files,
        3,
        time,
    )?)
}

#[test]
fn validated_values_cannot_be_bypassed_by_deserialization() {
    assert!(serde_json::from_str::<GitObjectId>("\"HEAD\"").is_err());
    assert!(serde_json::from_str::<Sha256Digest>("\"claimed\"").is_err());
    assert!(serde_json::from_str::<SourcePath>("\"../escape\"").is_err());
    assert!(serde_json::from_str::<RepositoryId>("\"\"").is_err());
    assert!(RepositoryId::parse("project/source-1").is_ok());
}

#[test]
fn paths_are_preserved_or_explicitly_rejected() -> Result<(), SourceError> {
    for path in [
        "",
        "..",
        ".",
        "../escape",
        "/absolute",
        "a/../b",
        "a//b",
        "a/",
        "C:/file",
        "a\\b",
        ".GIT/config",
        "NUL.txt",
        "a.",
        "a ",
        "a\0b",
        "a\nb",
        "cafe\u{301}.txt",
    ] {
        assert_eq!(
            SourcePath::from_bytes(path.as_bytes()),
            Err(SourceError::InvalidSourcePath),
            "{path:?}"
        );
    }

    assert_eq!(
        SourcePath::from_bytes(&[0xff]),
        Err(SourceError::InvalidSourcePath)
    );
    assert_eq!(
        SourcePath::from_bytes("café/résumé.txt".as_bytes())?.as_str(),
        "café/résumé.txt"
    );

    Ok(())
}

#[test]
fn duplicate_and_prefix_aliases_are_rejected() -> Result<(), SourceError> {
    for paths in [
        ["a", "a"],
        ["A", "a"],
        ["a", "a/b"],
        ["Dir/a", "dir/b"],
        ["Ä", "ä"],
    ] {
        let entries = paths
            .into_iter()
            .map(|p| entry(p, b"", SourceMode::File))
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(
            SourceManifest::new(entries),
            Err(SourceError::PathCollision)
        );
    }

    assert!(
        SourceManifest::new(vec![
            entry("dir/a", b"", SourceMode::File)?,
            entry("dir/b", b"", SourceMode::File)?
        ])
        .is_ok()
    );

    Ok(())
}

#[test]
fn sha256_known_answer() {
    assert_eq!(
        digest_bytes(b"abc").as_str(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn canonical_manifest_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let empty = SourceManifest::new(vec![])?;

    assert_eq!(
        hex::encode(empty.canonical_bytes()),
        "41524348434552542d534f5552434500000000010000000000000000"
    );

    let one = SourceManifest::new(vec![entry("a", b"abc", SourceMode::File)?])?;

    assert_eq!(
        hex::encode(one.canonical_bytes()),
        concat!(
            "41524348434552542d534f5552434500000000010000000000000001",
            "000000000000000161000081a4",
            "6261373831366266386630316366656134313431343064653564616532323233",
            "6230303336316133393631373761396362343130666636316632303031356164",
            "0000000000000003"
        )
    );
    // Independent fixed digest values are also recorded in ADR-0006.
    assert_eq!(
        empty.digest().as_str(),
        "7a72bb7d625a4c191642a375d2d51096a904593ce6cb8599c33a32b8389f424c"
    );
    assert_eq!(
        one.digest().as_str(),
        "252d8a8aa373a45994b32021ac661a412b3c90138086686e41aaf92a491b2175"
    );

    Ok(())
}

#[test]
fn every_permutation_has_the_same_source_identity() -> Result<(), SourceError> {
    let source = [
        entry("a", b"alpha", SourceMode::File)?,
        entry("b", b"beta", SourceMode::Executable)?,
        entry("dir/c", b"\0\xff", SourceMode::File)?,
        entry("link", b"../../outside", SourceMode::Symlink)?,
    ];
    let expected = SourceManifest::new(source.to_vec())?;

    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let mut indices = [a, b, c, d];
                    indices.sort();

                    if indices != [0, 1, 2, 3] {
                        continue;
                    }

                    let actual = SourceManifest::new(
                        [a, b, c, d].iter().map(|i| source[*i].clone()).collect(),
                    )?;

                    assert_eq!(actual.canonical_bytes(), expected.canonical_bytes());
                    assert_eq!(actual.digest(), expected.digest());
                }
            }
        }
    }

    Ok(())
}

#[test]
fn content_mode_path_and_symlink_target_bind_the_digest() -> Result<(), SourceError> {
    let base = SourceManifest::new(vec![entry("a", b"abc", SourceMode::File)?])?.digest();

    for changed in [
        entry("a", b"abd", SourceMode::File)?,
        entry("a", b"abc", SourceMode::Executable)?,
        entry("b", b"abc", SourceMode::File)?,
        entry("a", b"abc", SourceMode::Symlink)?,
    ] {
        assert_ne!(SourceManifest::new(vec![changed])?.digest(), base);
    }

    Ok(())
}

#[test]
fn timestamps_and_authority_metadata_do_not_affect_digest() -> Result<(), Box<dyn std::error::Error>>
{
    let file = SourceFile::new(
        SourcePath::from_bytes(b"a")?,
        SourceMode::File,
        b"abc".to_vec(),
    );

    assert_eq!(
        snapshot(vec![file.clone()], 0)?.identity().snapshot_sha256,
        snapshot(vec![file], u64::MAX)?.identity().snapshot_sha256
    );

    Ok(())
}

#[test]
fn tampering_and_wrong_expected_digest_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut source = snapshot(
        vec![SourceFile::new(
            SourcePath::from_bytes(b"a")?,
            SourceMode::File,
            b"original".to_vec(),
        )],
        1,
    )?;
    let expected = source.identity().snapshot_sha256.clone();
    source.verify(&expected)?;

    assert_eq!(
        source.verify(&digest_bytes(b"wrong")),
        Err(SourceError::SnapshotDigestMismatch)
    );

    // Private test access models corruption in a future persistence adapter.
    source.files[0].bytes[0] ^= 1;

    assert_eq!(
        source.verify(&expected),
        Err(SourceError::SnapshotDigestMismatch)
    );

    Ok(())
}

#[test]
fn incomplete_states_never_allow_runner_handoff() -> Result<(), Box<dyn std::error::Error>> {
    let pointer = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize 99\n",
        "a".repeat(64)
    );

    for file in [
        SourceFile::new(
            SourcePath::from_bytes(b"large")?,
            SourceMode::File,
            pointer.into_bytes(),
        ),
        SourceFile::new(
            SourcePath::from_bytes(b"module")?,
            SourceMode::Submodule,
            "b".repeat(40).into_bytes(),
        ),
    ] {
        let source = snapshot(vec![file], 0)?;

        assert_eq!(source.status(), SourceStatus::IncompleteExternalSource);
        assert_eq!(
            source.require_complete(),
            Err(SourceError::IncompleteExternalSource)
        );
        assert_eq!(source.external().len(), 1);
    }

    let complete = snapshot(vec![], 0)?;

    assert_eq!(complete.status(), SourceStatus::Complete);

    complete.require_complete()?;

    Ok(())
}

#[test]
fn malformed_lfs_is_rejected_instead_of_falsely_complete() -> Result<(), Box<dyn std::error::Error>>
{
    for bytes in [
        b"version https://git-lfs.github.com/spec/v1\n".as_slice(),
        b"version https://git-lfs.github.com/spec/v2\n",
        b"version https://git-lfs.github.com/spec/v1\noid sha256:bad\nsize 1\n",
    ] {
        let result = snapshot(
            vec![SourceFile::new(
                SourcePath::from_bytes(b"lfs")?,
                SourceMode::File,
                bytes.to_vec(),
            )],
            0,
        );

        assert!(
            matches!(result, Err(error) if error.downcast_ref::<SourceError>() == Some(&SourceError::InvalidLfsPointer))
        );
    }

    Ok(())
}

#[test]
fn input_errors_and_internal_failures_remain_distinct() -> Result<(), serde_json::Error> {
    let input = serde_json::to_value(SourceError::MalformedGitObject)?;
    let internal = serde_json::to_value(SourceError::InternalIntegrityFailure)?;

    assert_ne!(input, internal);
    assert_eq!(
        SourceError::SnapshotDigestMismatch.to_string(),
        "snapshot digest mismatch"
    );

    Ok(())
}

#[test]
fn external_evidence_tampering_is_detected_by_reconstruction()
-> Result<(), Box<dyn std::error::Error>> {
    let mut source = snapshot(
        vec![SourceFile::new(
            SourcePath::from_bytes(b"module")?,
            SourceMode::Submodule,
            "a".repeat(40).into_bytes(),
        )],
        0,
    )?;
    let expected = source.identity().snapshot_sha256.clone();
    source.external.clear();

    assert_eq!(
        source.verify(&expected),
        Err(SourceError::SnapshotDigestMismatch)
    );

    Ok(())
}

#[test]
fn resolved_binding_preserves_original_and_rejects_content_recipe_substitution()
-> Result<(), Box<dyn std::error::Error>> {
    let payload = b"resolved bytes";
    let path = SourcePath::from_bytes(b"data")?;
    let pointer = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {}\n",
        digest_bytes(payload).as_str(),
        payload.len()
    );
    let original = snapshot(
        vec![
            SourceFile::new(path.clone(), SourceMode::Executable, pointer.into_bytes()),
            SourceFile::new(
                SourcePath::from_bytes(b"keep")?,
                SourceMode::File,
                b"unchanged".to_vec(),
            ),
        ],
        1,
    )?;
    let replacement = ResolvedDependency::Lfs {
        path: path.clone(),
        sha256: digest_bytes(payload),
        size: payload.len() as u64,
    };
    let files = vec![
        SourceFile::new(path, SourceMode::Executable, payload.to_vec()),
        original.files()[1].clone(),
    ];
    let resolved =
        SourceSnapshot::seal_resolved(&original, files.clone(), vec![replacement.clone()], 2)?;
    resolved.require_complete()?;

    assert_eq!(resolved.binding().original(), Some(original.identity()));
    assert_eq!(resolved.identity().commit, original.identity().commit);
    assert_eq!(resolved.identity().tree, original.identity().tree);
    assert_eq!(resolved.schema_version(), 2);
    assert!(original.require_complete().is_err());

    let replay =
        SourceSnapshot::seal_resolved(&original, files.clone(), vec![replacement.clone()], 9999)?;

    assert_eq!(resolved.identity(), replay.identity());
    assert_eq!(
        digest_bytes(&resolved.binding().canonical_bytes(resolved.manifest())?),
        resolved.identity().snapshot_sha256
    );
    assert_ne!(
        resolved.manifest().digest(),
        resolved.identity().snapshot_sha256
    );

    for mutation in 0..5 {
        let mut files = files.clone();
        let mut deps = vec![replacement.clone()];

        match mutation {
            0 => {
                files[0] = SourceFile::new(
                    files[0].path().clone(),
                    SourceMode::Executable,
                    b"substitution".to_vec(),
                )
            }
            1 => {
                files[1] = SourceFile::new(
                    files[1].path().clone(),
                    SourceMode::File,
                    b"modified".to_vec(),
                )
            }
            2 => {
                files.pop();
            }
            3 => {
                files[0] =
                    SourceFile::new(files[0].path().clone(), SourceMode::File, payload.to_vec())
            }
            _ => deps.clear(),
        }

        assert!(
            SourceSnapshot::seal_resolved(&original, files, deps, 2).is_err(),
            "mutation {mutation}"
        );
    }

    let mut claimed = serde_json::to_value(resolved.binding())?;
    claimed["dependencies"][0]["sha256"] = serde_json::json!(digest_bytes(b"other"));
    let substituted: SourceBinding = serde_json::from_value(claimed)?;

    assert!(substituted.digest(resolved.manifest()).is_err());

    Ok(())
}

#[test]
fn recursive_resolved_children_verify_exact_identities_and_bound_depth()
-> Result<(), Box<dyn std::error::Error>> {
    let mut child = snapshot(
        vec![SourceFile::new(
            SourcePath::from_bytes(b"file")?,
            SourceMode::File,
            b"child".to_vec(),
        )],
        1,
    )?;

    for depth in 1..=33 {
        let path = SourcePath::from_bytes(b"module")?;
        let parent = snapshot(
            vec![SourceFile::new(
                path.clone(),
                SourceMode::Submodule,
                child.identity().commit.as_str().as_bytes().to_vec(),
            )],
            1,
        )?;
        let mut dependency = ResolvedDependency::Submodule {
            path,
            project: child.project(),
            repository: child.repository().clone(),
            identity: child.identity().clone(),
            binding: Box::new(child.binding().clone()),
        };
        let files = child
            .files()
            .iter()
            .map(|f| {
                Ok(SourceFile::new(
                    SourcePath::from_bytes(format!("module/{}", f.path().as_str()).as_bytes())?,
                    f.mode(),
                    f.bytes().to_vec(),
                ))
            })
            .collect::<Result<Vec<_>, SourceError>>()?;

        if depth == 1 {
            if let ResolvedDependency::Submodule { identity, .. } = &mut dependency {
                identity.snapshot_sha256 = digest_bytes(b"other child");
            }

            assert!(
                SourceSnapshot::seal_resolved(&parent, files.clone(), vec![dependency.clone()], 2)
                    .is_err()
            );

            if let ResolvedDependency::Submodule { identity, .. } = &mut dependency {
                *identity = child.identity().clone();
            }
        }

        let result = SourceSnapshot::seal_resolved(&parent, files, vec![dependency], 2);

        if depth == 33 {
            assert!(matches!(
                result,
                Err(SourceError::LimitExceeded(ResourceLimit::TreeDepth))
            ));
        } else {
            child = result?;
            child.require_complete()?;
        }
    }

    Ok(())
}

#[test]
fn expanded_children_cannot_hide_incomplete_lfs_or_reparse_verified_lfs_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let inner=b"version https://git-lfs.github.com/spec/v1\noid sha256:1111111111111111111111111111111111111111111111111111111111111111\nsize 1\n";
    let child = snapshot(
        vec![SourceFile::new(
            SourcePath::from_bytes(b"data")?,
            SourceMode::File,
            inner.to_vec(),
        )],
        1,
    )?;

    fn expand(child: &SourceSnapshot) -> Result<SourceSnapshot, Box<dyn std::error::Error>> {
        let path = SourcePath::from_bytes(b"module")?;
        let parent = snapshot(
            vec![SourceFile::new(
                path.clone(),
                SourceMode::Submodule,
                child.identity().commit.as_str().as_bytes().to_vec(),
            )],
            1,
        )?;

        Ok(SourceSnapshot::seal_resolved(
            &parent,
            vec![SourceFile::new(
                SourcePath::from_bytes(b"module/data")?,
                SourceMode::File,
                child.files()[0].bytes().to_vec(),
            )],
            vec![ResolvedDependency::Submodule {
                path,
                project: child.project(),
                repository: child.repository().clone(),
                identity: child.identity().clone(),
                binding: Box::new(child.binding().clone()),
            }],
            2,
        )?)
    }

    assert!(expand(&child).is_err());

    // An acquired object may itself happen to contain pointer-shaped content.
    // Its verified byte digest is final source, and must not initiate another fetch.
    let outer = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {}\n",
        digest_bytes(inner).as_str(),
        inner.len()
    );
    let original = snapshot(
        vec![SourceFile::new(
            SourcePath::from_bytes(b"data")?,
            SourceMode::File,
            outer.into_bytes(),
        )],
        1,
    )?;
    let complete = SourceSnapshot::seal_resolved(
        &original,
        child.files().to_vec(),
        vec![ResolvedDependency::Lfs {
            path: SourcePath::from_bytes(b"data")?,
            sha256: digest_bytes(inner),
            size: inner.len() as u64,
        }],
        2,
    )?;
    complete.require_complete()?;
    expand(&complete)?.require_complete()?;

    Ok(())
}
