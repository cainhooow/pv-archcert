//! Exact operational search UI. Results remain private metadata, never authority.

use super::*;
use archcert_application::glassmere::search::{SearchKind, SearchPage, SearchQuery};
use std::fmt::Write;

pub(super) async fn page(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(query): Query<SearchQuery>,
) -> Response {
    let id = match identity(&panel, &headers) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let project = match project_scope(&panel, &id, &project) {
        Ok(project) => project,
        Err(error) => return error.into_response(),
    };

    if query.value.is_empty() && query.after.is_none() {
        return html(
            &panel,
            "Exact operational search",
            &form(project, &query),
            Some(&id),
        );
    }
    if query.after_key(project).is_err() {
        return query_error(JobStoreError::Invalid);
    }

    match panel.query.search(project, &query).await {
        Ok(page) if page.project == project && page.hits.len() <= MAX_PAGE_SIZE => html(
            &panel,
            "Exact operational search",
            &results(&page),
            Some(&id),
        ),
        Ok(_) => query_error(JobStoreError::Unavailable),
        Err(error) => query_error(error),
    }
}

pub(super) async fn api(
    State(panel): State<Arc<Panel>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(query): Query<SearchQuery>,
) -> Response {
    let id = match identity(&panel, &headers) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let project = match project_scope(&panel, &id, &project) {
        Ok(project) => project,
        Err(error) => return error.into_response(),
    };
    if query.after_key(project).is_err() {
        return query_error(JobStoreError::Invalid);
    }

    match panel.query.search(project, &query).await {
        Ok(page) if page.project == project && page.hits.len() <= MAX_PAGE_SIZE => {
            match serde_json::to_vec(&page) {
                Ok(bytes) if bytes.len() <= 2 * 1024 * 1024 => {
                    ([(header::CONTENT_TYPE, "application/json")], bytes).into_response()
                }
                _ => error(StatusCode::PAYLOAD_TOO_LARGE, "LIMIT_EXCEEDED"),
            }
        }
        Ok(_) => query_error(JobStoreError::Unavailable),
        Err(error) => query_error(error),
    }
}

fn form(project: ProjectId, query: &SearchQuery) -> String {
    let mut result = format!(
        "<a class=back href=\"/projects/{project}\">← Project</a><section class=panel><h2>Exact operational search</h2><p>Search this authorized project using complete identities or recorded job states. Matches are metadata; inspect original bytes and backend verification before interpreting validity. Wildcards and substring scans are unsupported.</p><form method=get action=\"/projects/{project}/search\"><label for=search-kind>Search dimension</label><select id=search-kind name=kind>"
    );
    for (kind, label) in [
        (SearchKind::Project, "Project UUID"),
        (SearchKind::Commit, "Commit SHA"),
        (
            SearchKind::Certificate,
            "Certificate payload or envelope digest",
        ),
        (SearchKind::Artifact, "Immutable artifact digest"),
        (
            SearchKind::Permit,
            "Release Permit payload or envelope digest",
        ),
        (SearchKind::Job, "Job UUID"),
        (SearchKind::Status, "Job state"),
        (SearchKind::Verdict, "Recorded evaluation disposition"),
    ] {
        let selected = if kind == query.kind { " selected" } else { "" };
        let _ = write!(
            result,
            "<option value=\"{}\"{selected}>{label}</option>",
            kind.name()
        );
    }
    let _ = write!(
        result,
        "</select><label for=search-value>Exact value</label><input id=search-value name=value required maxlength=64 value=\"{}\" autocomplete=off spellcheck=false><button>Search</button></form><p class=muted>Job states: QUEUED, RUNNING, EVALUATING, SIGNING, COMPLETED, NOT_ELIGIBLE, INCONCLUSIVE. Evaluation dispositions: ELIGIBLE, NOT_ELIGIBLE, INCONCLUSIVE. COMPLETED and ELIGIBLE alone are not signature verification.</p></section>",
        render::escape(&query.value)
    );

    result
}

fn results(page: &SearchPage) -> String {
    let mut result = form(page.project, &page.query);
    result.push_str("<section class=panel><h2>Matching records</h2><div class=table-scroll><table><thead><tr><th scope=col>Kind</th><th scope=col>Exact entity</th><th scope=col>Recorded state</th><th scope=col>Original bytes digest</th></tr></thead><tbody>");
    for hit in &page.hits {
        let url = if let Some(digest) = &hit.digest {
            Some(format!(
                "/projects/{}/evidence/{}/{}",
                page.project, hit.entity, digest
            ))
        } else if hit.kind == "JOB" {
            Some(format!("/projects/{}/jobs/{}", page.project, hit.entity))
        } else if hit.kind == "PROJECT" {
            Some(format!("/projects/{}", page.project))
        } else if hit.kind == "SEMANTIC_SESSION" {
            Some(format!(
                "/projects/{}/semantic/{}",
                page.project, hit.entity
            ))
        } else if hit.kind == "RELEASE" {
            Some(format!(
                "/projects/{}/readiness/{}",
                page.project, hit.entity
            ))
        } else {
            None
        };
        let entity = if let Some(url) = url {
            format!(
                "<a href=\"{}\">{}</a>",
                render::escape(&url),
                render::escape(&hit.entity)
            )
        } else {
            render::escape(&hit.entity)
        };
        let _ = write!(
            result,
            "<tr><td>{}</td><td class=mono>{entity}</td><td>{}</td><td class=mono>{}</td></tr>",
            render::escape(&hit.kind),
            render::escape(&hit.state),
            render::escape(hit.digest.as_deref().unwrap_or("NOT AN OBJECT REFERENCE"))
        );
    }
    if page.hits.is_empty() {
        result.push_str(
            "<tr><td colspan=4>No matching records in this authorized project and query.</td></tr>",
        );
    }
    result.push_str(
        "</tbody></table></div></section><nav class=pagination aria-label=\"Search pages\">",
    );
    let path = format!(
        "/projects/{}/search?kind={}&amp;value={}",
        page.project,
        page.query.kind.name(),
        render::escape(&page.query.value)
    );
    let _ = write!(result, "<a href=\"{path}\">Start search again</a>");
    if let Some(next) = &page.next {
        let _ = write!(
            result,
            "<a href=\"{path}&amp;after={}\">Next matching records</a>",
            render::escape(next)
        );
    }
    result.push_str("</nav><p class=muted>Each page is a fresh read. New earlier keys appear after restarting the search; changing states can remove records from a filter. Cursor order is not authority ordering.</p>");

    result
}
