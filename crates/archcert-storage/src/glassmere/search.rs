//! Fixed project-scoped search statements. No candidate-selected SQL or wildcard scans.

use super::*;
use archcert_application::glassmere::search::{SearchHit, SearchKind, SearchPage, SearchQuery};

impl ObservationRepository {
    /// Exact equality predicates, a fixed result bound and inherited statement deadline.
    /// A search hit is metadata; only original-byte verification can establish validity.
    pub async fn search(&self, project: ProjectId, query: &SearchQuery) -> Result<SearchPage> {
        let after = query.after_key(project)?;

        let statement = match query.kind {
            SearchKind::Project => {
                r#"
                SELECT 'PROJECT/' || project AS page_key, project AS entity,
                       'PROJECT' AS kind, 'REGISTERED PROJECT' AS state, NULL::text AS digest
                FROM repository_grants WHERE project=$1 AND project=$2 GROUP BY project
            "#
            }
            SearchKind::Commit => {
                r#"
                SELECT 'SOURCE/' || submission AS page_key, submission AS entity,
                       'SOURCE' AS kind, 'ACCEPTED IMMUTABLE SOURCE' AS state, NULL::text AS digest
                FROM accepted_sources WHERE project=$1 AND source->>'commit'=$2
                UNION ALL
                SELECT 'JOB/' || id AS page_key, id AS entity, 'JOB' AS kind,
                       state, NULL::text AS digest
                FROM certification_jobs WHERE project=$1 AND inputs->'source'->>'commit'=$2
                UNION ALL
                SELECT 'SEMANTIC/' || id AS page_key, id AS entity, 'SEMANTIC_SESSION' AS kind,
                       'INSPECT ACCEPTED GATE / REVIEW EVIDENCE' AS state, NULL::text AS digest
                FROM ironcrest_sessions WHERE project=$1 AND pin->'source'->>'commit'=$2
                UNION ALL
                SELECT 'RELEASE/' || invocation AS page_key, invocation AS entity, 'RELEASE' AS kind,
                       'VERIFY EXACT RELEASE READINESS' AS state, NULL::text AS digest
                FROM release_invocations WHERE project=$1
                  AND admission->'input'->'certified_source'->'source'->>'commit'=$2
            "#
            }
            SearchKind::Job => {
                r#"
                SELECT 'JOB/' || id AS page_key, id AS entity, 'JOB' AS kind,
                       state, NULL::text AS digest
                FROM certification_jobs WHERE project=$1 AND id=$2
            "#
            }
            SearchKind::Status => {
                r#"
                SELECT 'JOB/' || id AS page_key, id AS entity, 'JOB' AS kind,
                       state, NULL::text AS digest
                FROM certification_jobs WHERE project=$1 AND state=$2
            "#
            }
            SearchKind::Verdict => {
                r#"
                SELECT 'JOB/' || id AS page_key, id AS entity, 'JOB' AS kind,
                       state, NULL::text AS digest
                FROM certification_jobs WHERE project=$1 AND evaluation IS NOT NULL AND (
                    ($2='ELIGIBLE' AND eligible IS TRUE) OR
                    ($2='NOT_ELIGIBLE' AND state='NOT_ELIGIBLE') OR
                    ($2='INCONCLUSIVE' AND state='INCONCLUSIVE')
                )
            "#
            }
            SearchKind::Certificate => {
                r#"
                SELECT 'CERTIFICATE/' || id AS page_key, id AS entity,
                       'CERTIFICATE' AS kind, state, certificate->'artifact'->>'sha256' AS digest
                FROM certification_jobs WHERE project=$1 AND (
                    certificate->'issuance'->>'certificate_sha256'=$2 OR
                    certificate->'artifact'->>'sha256'=$2
                )
                UNION ALL
                SELECT 'RELEASE_CERTIFICATE/' || e.invocation AS page_key, e.invocation AS entity,
                       'SOURCE_CERTIFICATE' AS kind,
                       CASE WHEN e.available THEN 'AVAILABLE' ELSE 'STAGING' END AS state,
                       e.reference->>'sha256' AS digest
                FROM release_evidence e JOIN release_invocations i
                  ON i.project=e.project AND i.invocation=e.invocation
                WHERE e.project=$1 AND e.role='SOURCE_CERTIFICATE' AND (
                    e.reference->>'sha256'=$2 OR
                    i.admission->'input'->'certified_source'->>'certificate_sha256'=$2
                )
            "#
            }
            SearchKind::Artifact => {
                r#"
                SELECT 'CERTIFICATION/' || a.job || '/' || a.kind || '/' || a.attempt AS page_key,
                       a.job AS entity, a.kind, a.state, a.reference->>'sha256' AS digest
                FROM artifacts a JOIN certification_jobs j ON j.id=a.job
                WHERE j.project=$1 AND a.reference->>'sha256'=$2
                UNION ALL
                SELECT 'SEMANTIC/' || e.session || '/' || e.role AS page_key,
                       e.session AS entity, e.role AS kind, e.state, e.reference->>'sha256' AS digest
                FROM ironcrest_evidence e JOIN ironcrest_sessions s ON s.id=e.session
                WHERE s.project=$1 AND e.reference->>'sha256'=$2
                UNION ALL
                SELECT 'RELEASE/' || invocation || '/' || role AS page_key,
                       invocation AS entity, role AS kind,
                       CASE WHEN available THEN 'AVAILABLE' ELSE 'STAGING' END AS state,
                       reference->>'sha256' AS digest
                FROM release_evidence WHERE project=$1 AND reference->>'sha256'=$2
            "#
            }
            SearchKind::Permit => {
                r#"
                SELECT 'PERMIT/' || invocation || '/' || role AS page_key,
                       invocation AS entity, role AS kind,
                       CASE WHEN available THEN 'AVAILABLE' ELSE 'STAGING' END AS state,
                       reference->>'sha256' AS digest
                FROM release_evidence WHERE project=$1
                  AND role IN ('PERMIT_PAYLOAD','PERMIT_ENVELOPE') AND reference->>'sha256'=$2
            "#
            }
        };

        // Only the fixed statements above enter SQL syntax. All request values,
        // including the validated cursor, remain bound data parameters.
        let sql = sqlx::AssertSqlSafe(format!(
            "SELECT * FROM ({statement}) matched WHERE page_key > $3 ORDER BY page_key LIMIT 51"
        ));
        let mut transaction = self.begin().await?;
        let rows = sqlx::query(sql)
            .bind(project.to_string())
            .bind(&query.value)
            .bind(after)
            .fetch_all(&mut *transaction)
            .await
            .map_err(db)?;

        let has_more = rows.len() > MAX_PAGE_SIZE;
        let hits = rows
            .into_iter()
            .take(MAX_PAGE_SIZE)
            .map(|row| {
                Ok(SearchHit {
                    key: row.try_get("page_key").map_err(db)?,
                    entity: row.try_get("entity").map_err(db)?,
                    kind: row.try_get("kind").map_err(db)?,
                    state: row.try_get("state").map_err(db)?,
                    digest: row.try_get("digest").map_err(db)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let next = if has_more {
            hits.last().map(|hit| query.cursor(project, &hit.key))
        } else {
            None
        };

        transaction.commit().await.map_err(db)?;

        Ok(SearchPage {
            schema: 1,
            project,
            query: query.clone(),
            hits,
            next,
        })
    }
}
