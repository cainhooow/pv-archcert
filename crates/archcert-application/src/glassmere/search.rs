//! Exact operational lookup. A matching row establishes no cryptographic verdict.

use crate::jobs::JobStoreError;
use archcert_domain::{GitObjectId, ProjectId, Sha256Digest, jobs::JobId, source::digest_bytes};
use serde::{Deserialize, Serialize};

/// Fixed search dimensions; no candidate SQL, wildcard or arbitrary field selector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SearchKind {
    /// Exact project UUID within the already selected project scope.
    Project,
    /// Exact accepted commit object ID.
    Commit,
    /// Canonical certificate payload or registered envelope digest.
    Certificate,
    /// Registered immutable object digest, including release artifacts.
    Artifact,
    /// Registered canonical Release Permit payload or envelope digest.
    Permit,
    /// Exact durable certification job UUID.
    #[default]
    Job,
    /// Exact durable job state.
    Status,
    /// Recorded deterministic evaluation disposition; not signature verification.
    Verdict,
}

impl SearchKind {
    /// Stable query vocabulary, independent of Rust debug formatting.
    pub fn name(self) -> &'static str {
        match self {
            Self::Project => "PROJECT",
            Self::Commit => "COMMIT",
            Self::Certificate => "CERTIFICATE",
            Self::Artifact => "ARTIFACT",
            Self::Permit => "PERMIT",
            Self::Job => "JOB",
            Self::Status => "STATUS",
            Self::Verdict => "VERDICT",
        }
    }
}

/// Bounded exact query. Cursor binding prevents accidental continuation of another search.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    /// Fixed dimension; the HTML form defaults to exact job lookup.
    #[serde(default)]
    pub kind: SearchKind,
    /// Exact value; never substring, wildcard, regular expression or source expression.
    #[serde(default)]
    pub value: String,
    /// Bounded keyset cursor; not a credential or authorization capability.
    pub after: Option<String>,
}

impl SearchQuery {
    fn prefix(&self, project: ProjectId) -> String {
        let context = format!(
            "glassmere-search-v1/{project}/{}/{}",
            self.kind.name(),
            self.value
        );
        format!("{}:", digest_bytes(context.as_bytes()).as_str())
    }

    /// Validate exact syntax and return the bound row key. Scope authorization is separate.
    pub fn after_key(&self, project: ProjectId) -> Result<&str, JobStoreError> {
        if self.value.is_empty() || self.value.len() > 64 {
            return Err(JobStoreError::Invalid);
        }
        let valid = match self.kind {
            SearchKind::Project => self
                .value
                .parse::<ProjectId>()
                .is_ok_and(|id| id.to_string() == self.value),
            SearchKind::Commit => {
                GitObjectId::parse(&self.value).is_ok_and(|id| id.as_str() == self.value)
            }
            SearchKind::Certificate | SearchKind::Artifact | SearchKind::Permit => {
                Sha256Digest::parse(&self.value).is_ok_and(|digest| digest.as_str() == self.value)
            }
            SearchKind::Job => {
                JobId::parse(&self.value).is_ok_and(|id| id.to_string() == self.value)
            }
            SearchKind::Status => [
                "QUEUED",
                "RUNNING",
                "EVALUATING",
                "SIGNING",
                "COMPLETED",
                "NOT_ELIGIBLE",
                "INCONCLUSIVE",
            ]
            .contains(&self.value.as_str()),
            SearchKind::Verdict => {
                ["ELIGIBLE", "NOT_ELIGIBLE", "INCONCLUSIVE"].contains(&self.value.as_str())
            }
        };
        if !valid {
            return Err(JobStoreError::Invalid);
        }

        let Some(cursor) = &self.after else {
            return Ok("");
        };
        if cursor.len() > 256 {
            return Err(JobStoreError::Invalid);
        }
        let prefix = self.prefix(project);
        let key = cursor.strip_prefix(&prefix).ok_or(JobStoreError::Invalid)?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_-".contains(&byte))
        {
            return Err(JobStoreError::Invalid);
        }

        Ok(key)
    }

    /// Bind an adapter-selected continuation key to this exact project and query.
    pub fn cursor(&self, project: ProjectId, key: &str) -> String {
        format!("{}{key}", self.prefix(project))
    }
}

/// One selected operational record; original object verification stays separate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchHit {
    /// Stable sort key; not a timestamp or authority sequence.
    pub key: String,
    /// Exact job, source submission, session, invocation or project.
    pub entity: String,
    /// Fixed record category/role.
    pub kind: String,
    /// Explicit retained metadata state, not a new verdict.
    pub state: String,
    /// Registered original bytes where the hit resolves to evidence.
    pub digest: Option<String>,
}

/// One independently evaluated current search page. Concurrent inserts never duplicate keys.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchPage {
    /// Query contract version.
    pub schema: u32,
    /// Already authorized project scope.
    pub project: ProjectId,
    /// Exact query echoed for inspection and navigation.
    pub query: SearchQuery,
    /// At most the fixed Glassmere page size.
    pub hits: Vec<SearchHit>,
    /// Present only if the query observed another matching key.
    pub next: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_values_reject_wildcards_noncanonical_ids_and_unknown_dispositions() {
        let project = ProjectId::new();
        for (kind, value) in [
            (SearchKind::Job, "*".into()),
            (SearchKind::Commit, "a".repeat(39)),
            (SearchKind::Commit, "A".repeat(40)),
            (SearchKind::Artifact, "a".repeat(65)),
            (SearchKind::Certificate, "%".into()),
            (SearchKind::Permit, "a_b".into()),
            (SearchKind::Status, "RUNNING OR true".into()),
            (SearchKind::Verdict, "PROVEN".into()),
            (SearchKind::Project, project.to_string().replace('-', "")),
        ] {
            let query = SearchQuery {
                kind,
                value,
                after: None,
            };
            assert!(matches!(
                query.after_key(project),
                Err(JobStoreError::Invalid)
            ));
        }
    }

    #[test]
    fn cursor_is_bound_to_project_dimension_and_value_without_granting_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = ProjectId::new();
        let mut query = SearchQuery {
            kind: SearchKind::Status,
            value: "QUEUED".into(),
            after: None,
        };
        let key = "JOB/10000000-0000-4000-8000-000000000001";
        query.after = Some(query.cursor(project, key));
        assert_eq!(query.after_key(project)?, key);
        assert!(query.after_key(ProjectId::new()).is_err());

        let mut changed = query.clone();
        changed.value = "RUNNING".into();
        assert!(changed.after_key(project).is_err());
        changed = query.clone();
        changed.kind = SearchKind::Verdict;
        changed.value = "ELIGIBLE".into();
        assert!(changed.after_key(project).is_err());
        query.after = Some(query.cursor(project, "<script>"));
        assert!(query.after_key(project).is_err());
        query.after = Some(query.cursor(project, &"x".repeat(256)));
        assert!(query.after_key(project).is_err());

        Ok(())
    }
}
