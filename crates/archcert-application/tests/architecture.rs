//! Small Cargo metadata dependency guard, also run by the default workspace tests.
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
};

fn allowed_inward_dependency(package: &str, dependency: &str) -> bool {
    match package {
        "archcert-domain" => {
            !dependency.starts_with("archcert-")
                && ![
                    "axum", "tokio", "rustix", "sqlx", "diesel", "bollard", "git2", "gix",
                    "reqwest", "tar", "flate2",
                ]
                .contains(&dependency)
        }
        "archcert-application" => {
            !dependency.starts_with("archcert-") || dependency == "archcert-domain"
        }
        "archcert-policy" => {
            (!dependency.starts_with("archcert-")
                || ["archcert-domain", "archcert-application"].contains(&dependency))
                && ![
                    "axum", "tokio", "rustix", "sqlx", "diesel", "bollard", "git2", "gix",
                    "reqwest", "tar", "flate2",
                ]
                .contains(&dependency)
        }
        "archcert-runner" => dependency != "archcert-materialization",
        _ => true,
    }
}
#[test]
fn workspace_dependencies_point_inward_and_scaffolds_stay_outside_active_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let metadata = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .output()?;
    assert!(metadata.status.success(), "cargo metadata failed");
    let metadata: Value = serde_json::from_slice(&metadata.stdout)?;
    let mut graph = BTreeMap::<String, Vec<String>>::new();
    for package in metadata["packages"].as_array().ok_or("packages missing")? {
        let name = package["name"].as_str().ok_or("package name missing")?;
        for dependency in package["dependencies"]
            .as_array()
            .ok_or("dependencies missing")?
        {
            let dep = dependency["name"]
                .as_str()
                .ok_or("dependency name missing")?;
            // Runner test fixtures may compose materialization; inward layers
            // must stay independent even through dev dependencies.
            let runner_fixture = name == "archcert-runner" && dependency["kind"] == "dev";
            assert!(
                runner_fixture || allowed_inward_dependency(name, dep),
                "forbidden architecture edge: {name} -> {dep}"
            );
            if dependency["kind"] != "dev" {
                graph.entry(name.into()).or_default().push(dep.into());
            }
        }
    }
    let mut pending = vec!["archcert-cli".to_owned(), "archcertd".to_owned()];
    let mut seen = BTreeSet::new();
    while let Some(name) = pending.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        assert!(
            !["archcert-evidence", "archcert-crypto"].contains(&name.as_str()),
            "inactive scaffold enters active TCB: {name}"
        );
        pending.extend(graph.get(&name).into_iter().flatten().cloned());
    }
    Ok(())
}
#[test]
fn guard_rejects_forbidden_dependencies_including_renamed_package_names() {
    for (owner, dep) in [
        ("archcert-domain", "archcert-application"),
        ("archcert-domain", "archcert-source"),
        ("archcert-domain", "axum"),
        ("archcert-domain", "tokio"),
        ("archcert-application", "archcert-protocol"),
        ("archcert-application", "archcert-runner"),
        ("archcert-runner", "archcert-materialization"),
        ("archcert-domain", "archcert-policy"),
        ("archcert-application", "archcert-policy"),
        ("archcert-policy", "archcert-runner"),
        ("archcert-policy", "archcert-materialization"),
        ("archcert-policy", "archcert-protocol"),
        ("archcert-policy", "axum"),
        ("archcert-policy", "rustix"),
    ] {
        assert!(!allowed_inward_dependency(owner, dep));
    }
    assert!(allowed_inward_dependency(
        "archcert-application",
        "archcert-domain"
    ));
}
