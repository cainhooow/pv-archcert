//! Semantic server-rendered HTML. Every external value is inert escaped text.

use crate::auth::{Identity, PanelConfiguration};
use archcert_application::glassmere::*;
use serde::Serialize;
use std::fmt::Write;

/// Escape all text/attribute contexts; no repository HTML or Markdown is trusted.
pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn enum_text(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "UNKNOWN / UNSUPPORTED".into())
}

pub fn page(
    title: &str,
    body: &str,
    identity: Option<&Identity>,
    config: &PanelConfiguration,
) -> String {
    let account = identity.map(|id| format!(
        "<div class=account><span>{} · {}</span><form method=post action=/logout><input type=hidden name=csrf value=\"{}\"><button class=quiet>Sign out</button></form></div>",
        escape(&id.id), enum_text(&id.role), escape(&id.csrf),
    )).unwrap_or_default();
    let notice = if config.demonstration_data {
        "<div class=demo>DEVELOPMENT / DEMONSTRATION DATA <span>M9 INCOMPLETE — DEVELOPMENT PREVIEW</span></div>"
    } else {
        "<div class=demo>M9 INCOMPLETE — OPERATIONAL OBSERVATION PREVIEW</div>"
    };

    format!(
        r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{} · Glassmere / ArchCert</title><link rel="stylesheet" href="/assets/panel.css"><script src="/assets/panel.js" defer></script></head>
<body><a class="skip" href="#main">Skip to content</a><aside class="sidebar"><a class="brand" href="/projects"><span class="brand-mark">A</span><span>ARCHCERT<small>Glassmere / Operations</small></span></a>
<div class="nav-label">WORKSPACE</div><nav aria-label="Workspace"><a href="/projects">◫ &nbsp; Projects</a><a href="/audit">≡ &nbsp; Panel audit</a></nav>
<div class="boundary"><span class="dot"></span> OBSERVATION SURFACE<p>The panel observes authority.<br>The panel does not become authority.</p><small>Genesis / Firstwarden<br>NOT STARTED</small></div></aside>
<div class="workspace"><header><div>PRIVATE CONTROL PLANE <span class="header-divider">/</span> <strong>Glassmere</strong></div>{account}</header>{notice}<main id="main"><div class="eyebrow">ARCHCERT OPERATIONAL VISIBILITY</div><h1>{}</h1>{body}</main>
<footer>Development signing · Exact immutable identities · No independent certification<br>This is engineering self-validation under a shared implementation/authority context. It is not independent certification and does not replace Genesis / Firstwarden.</footer></div></body></html>"##,
        escape(title),
        escape(title)
    )
}

pub fn login() -> String {
    "<section class=login><h2>Private operator access</h2><p>Use your individually provisioned development access credential. Your project grants and role are checked by the server.</p><form method=post action=/login><label for=credential>Access credential</label><input id=credential name=credential type=password autocomplete=off required minlength=64 maxlength=64 spellcheck=false><button>Sign in to Glassmere <span aria-hidden=true>→</span></button></form><p class=muted>No shared default account. Sessions expire after 30 minutes and are invalidated on logout or service restart.</p></section>".into()
}

pub fn projects(projects: &[ProjectObservation], after: Option<String>) -> String {
    let mut result = String::from(
        "<p class=lede>Inspect exact source, evidence and release authorization. Select a project to open its durable operational history.</p><section class=panel><div class=panel-heading><h2>Authorized projects</h2><span class=tag>PRIVATE · PROJECT SCOPED</span></div><div class=table-scroll><table><thead><tr><th scope=col>Project identity</th><th scope=col>Repository registry</th><th scope=col>Observation</th></tr></thead><tbody>",
    );
    for project in projects {
        let _ = write!(
            result,
            "<tr><td><a class=mono href=/projects/{}>{}</a></td><td>{}</td><td><span class=tag>SELECT EXACT SOURCE</span></td></tr>",
            project.project,
            project.project,
            escape(&project.repository)
        );
    }
    if projects.is_empty() {
        result.push_str(
            "<tr><td colspan=3>NONE EXIST in your explicitly authorized project scope.</td></tr>",
        );
    }
    result.push_str("</tbody></table></div></section>");
    if let Some(after) = after {
        let _ = write!(
            result,
            "<a class=button href=/projects?after={}>Next project page →</a>",
            escape(&after)
        );
    }

    result
}

pub fn project_nav(project: &ProjectSnapshot, section: &str) -> String {
    let mut result = format!(
        "<div class=project-heading><div><span class=muted>PROJECT</span><p class=mono>{}</p></div><div><span class=muted>REPOSITORY REGISTRY</span><p>{}</p></div></div><nav class=tabs aria-label=\"Project views\">",
        project.project.project,
        escape(&project.project.repository)
    );
    for (path, label) in [
        ("overview", "Overview"),
        ("certifications", "Certifications"),
        ("readiness", "Release readiness"),
        ("evidence", "Evidence"),
        ("knowledge", "Asterwyn"),
        ("semantic", "Greywatch"),
        ("jobs", "Jobs"),
        ("timeline", "Timeline"),
        ("search", "Search"),
    ] {
        let active = if section == path {
            " aria-current=page"
        } else {
            ""
        };
        if path == "search" {
            let _ = write!(
                result,
                "<a href=/projects/{}/search{active}>{label}</a>",
                project.project.project
            );
        } else {
            let _ = write!(
                result,
                "<a href=/projects/{}/{}?offset={}{}>{label}</a>",
                project.project.project, path, project.offset, active
            );
        }
    }
    result.push_str("</nav>");

    result
}

fn fields(fields: &[ObservationField]) -> String {
    let mut result = String::from("<dl class=facts>");
    for field in fields {
        let _ = write!(
            result,
            "<div><dt>{}</dt><dd>{}<small>Source: {}</small></dd></div>",
            escape(&field.label),
            escape(&field.value),
            escape(&field.provenance)
        );
    }
    result.push_str("</dl>");

    result
}

fn entities(snapshot: &ProjectSnapshot, entities: &[EntityObservation], path: &str) -> String {
    let mut result = String::from(
        "<div class=table-scroll><table><thead><tr><th scope=col>Immutable / durable identity</th><th scope=col>Type</th><th scope=col>Recorded state</th></tr></thead><tbody>",
    );
    for entity in entities {
        let _ = write!(
            result,
            "<tr><td><a class=mono href=/projects/{}/{}/{}>{}</a></td><td>{}</td><td><span class=tag>{}</span></td></tr>",
            snapshot.project.project,
            path,
            escape(&entity.id),
            escape(&entity.id),
            escape(&entity.kind),
            escape(&entity.state)
        );
    }
    if entities.is_empty() {
        result.push_str("<tr><td colspan=3>NONE EXIST on this bounded page. Unavailable reads return a separate error.</td></tr>");
    }
    result.push_str("</tbody></table></div>");

    result
}

pub fn evidence_table(
    snapshot: &ProjectSnapshot,
    predicate: impl Fn(&EvidenceObservation) -> bool,
) -> String {
    let mut result = String::from(
        "<div class=table-scroll><table><thead><tr><th scope=col>Role / evidence identity</th><th scope=col>Schema / producer</th><th scope=col>Size</th><th scope=col>Acceptance</th></tr></thead><tbody>",
    );
    let mut count = 0;
    for item in snapshot.evidence.iter().filter(|e| predicate(e)) {
        count += 1;
        let _ = write!(
            result,
            "<tr><td><a href=/projects/{}/evidence/{}/{}>{}<small class=mono>{}</small></a></td><td>{}<small>{}</small></td><td>{} bytes</td><td>{}</td></tr>",
            snapshot.project.project,
            escape(&item.entity),
            escape(&item.sha256),
            escape(&item.role),
            escape(&item.sha256),
            item.schema,
            escape(&item.producer),
            item.size,
            escape(&item.state)
        );
    }
    if count == 0 {
        result.push_str("<tr><td colspan=4>NONE EXIST on this evidence page. Other collection pages may contain additional records.</td></tr>");
    }
    result.push_str("</tbody></table></div>");

    result
}

pub fn project(
    snapshot: &ProjectSnapshot,
    section: &str,
    selected: Option<&str>,
) -> Option<String> {
    let mut result = project_nav(snapshot, section);
    if let Some(id) = selected {
        let entities = match section {
            "certifications" | "jobs" => &snapshot.jobs,
            "semantic" => &snapshot.sessions,
            _ => return None,
        };
        let entity = entities.iter().find(|e| e.id == id)?;
        let _ = write!(
            result,
            "<section class=panel><div class=panel-heading><h2>{}</h2><span class=tag>{}</span></div><p class=mono>{}</p>{}</section><section class=panel><h2>Bound immutable evidence</h2>{}</section>",
            escape(&entity.kind),
            escape(&entity.state),
            escape(&entity.id),
            fields(&entity.fields),
            evidence_table(snapshot, |e| e.entity == id)
        );
        result.push_str(&timeline(snapshot));
        result.push_str(&page_footer(snapshot, section, Some(id)));
        return Some(result);
    }

    match section {
        "overview" => {
            result.push_str("<div class=callout><strong>No release selected</strong><p>Release authorization is exact source + exact artifact. Open an immutable invocation under Release readiness. No branch name or latest-row heuristic is treated as certified identity.</p></div>");
            let _ = write!(
                result,
                "<div class=metrics><section><span>Source records on page</span><strong>{}</strong><small>Accepted immutable identities</small></section><section><span>Certification jobs on page</span><strong>{}</strong><small>Durable state, not signature verification</small></section><section><span>Release invocations on page</span><strong>{}</strong><small>Exact artifact authorization</small></section></div>",
                snapshot.sources.len(),
                snapshot.jobs.len(),
                snapshot.releases.len()
            );
            result.push_str("<section class=panel><h2>Source identity</h2>");
            for source in &snapshot.sources {
                let _ = write!(
                    result,
                    "<details><summary class=mono>{}</summary>{}</details>",
                    escape(&source.id),
                    fields(&source.fields)
                );
            }
            if snapshot.sources.is_empty() {
                result.push_str("<p>NONE EXIST on this page.</p>");
            }
            result.push_str("</section><section class=panel><h2>Certification & active work</h2>");
            result.push_str(&entities(snapshot, &snapshot.jobs, "certifications"));
            result.push_str(
                "</section><section class=panel><h2>Known uncertainty and scope</h2><ul>",
            );
            for limitation in &snapshot.limitations {
                let _ = write!(result, "<li>{}</li>", escape(limitation));
            }
            result.push_str("</ul></section>");
        }
        "certifications" | "jobs" => {
            let _ = write!(
                result,
                "<section class=panel><h2>Durable certification jobs</h2><p>COMPLETED is retained workflow state. Inspect certificate bytes and verifier output before interpreting signature validity.</p>{}</section>",
                entities(snapshot, &snapshot.jobs, section)
            );
        }
        "readiness" => {
            result.push_str("<div class=callout><strong>Exact release selection required</strong><p>No release readiness is inferred from project health, semantic CLEAR or the existence of a certificate row.</p></div><section class=panel><h2>Immutable release invocations</h2>");
            result.push_str(&entities(snapshot, &snapshot.releases, "readiness"));
            result.push_str("</section>");
        }
        "evidence" => {
            result.push_str("<section class=panel><h2>Immutable evidence references</h2><p>Acceptance metadata, verified bytes and derived projections are distinct. Original evidence cannot be edited in Glassmere.</p>");
            result.push_str(&evidence_table(snapshot, |_| true));
            result.push_str("</section>");
        }
        "knowledge" => {
            result.push_str("<div class=callout><strong>Asterwyn: bounded structural knowledge</strong><p>Coverage: PARTIAL / NOT_PROVEN until the exact knowledge artifact is inspected. Blind spots remain explicit. Syntax extraction does not establish compiler-complete analysis. Missing baseline or unsupported relations can require full review.</p></div><section class=panel><h2>Knowledge, impact & selected authority scenarios</h2>");
            result.push_str(&evidence_table(snapshot, |e| {
                ["KNOWLEDGE", "IMPACT", "CHALLENGE_PLAN", "AUTHORITY_PROFILE"]
                    .contains(&e.role.as_str())
            }));
            result.push_str("</section>");
        }
        "semantic" => {
            result.push_str("<div class=callout><strong>SUPPLEMENTAL / NON-AUTHORITATIVE</strong><p>Semantic CLEAR adds zero deterministic proof. Contradictions require authority resolution. Citation identity is separate from reasoning correctness; unresolved prose is never rendered as a verified source link.</p></div><section class=panel><h2>Greywatch sessions</h2>");
            result.push_str(&entities(snapshot, &snapshot.sessions, "semantic"));
            result.push_str(&evidence_table(snapshot, |e| {
                ["REQUEST", "REVIEW", "GATE", "CHALLENGE_RESULT"].contains(&e.role.as_str())
            }));
            result.push_str("</section>");
        }
        "timeline" => {
            result.push_str(&timeline(snapshot));
        }
        _ => return None,
    }

    result.push_str(&page_footer(snapshot, section, None));

    Some(result)
}

fn timeline(snapshot: &ProjectSnapshot) -> String {
    let mut result = String::new();
    result.push_str("<section class=panel><h2>Forensic timeline</h2><p>Ordered by durable sequence within each original stream. Independent certification and release sequences do not establish a shared total order.</p><div class=table-scroll><table><thead><tr><th scope=col>Stream / sequence</th><th scope=col>Recorded event</th><th scope=col>Entity</th><th scope=col>UTC Unix seconds</th></tr></thead><tbody>");
    for item in &snapshot.timeline {
        let _ = write!(
            result,
            "<tr><td>{} / {}</td><td>{}</td><td class=mono><a href=/projects/{}/{}/{}>{}</a></td><td>{}</td></tr>",
            escape(&item.stream),
            item.sequence,
            escape(&item.event),
            snapshot.project.project,
            if item.stream == "RELEASE" {
                "readiness"
            } else {
                "certifications"
            },
            escape(&item.entity),
            escape(&item.entity),
            item.timestamp
        );
    }
    if snapshot.timeline.is_empty() {
        result.push_str("<tr><td colspan=4>NONE EXIST on this timeline page.</td></tr>");
    }
    result.push_str("</tbody></table></div></section>");

    result
}

fn page_footer(snapshot: &ProjectSnapshot, section: &str, selected: Option<&str>) -> String {
    let mut path = format!("/projects/{}/{}", snapshot.project.project, escape(section));
    if let Some(id) = selected {
        let _ = write!(path, "/{}", escape(id));
    }
    let mut result = String::new();
    let _ = write!(
        result,
        "<div class=pagination><span>Independent collection offset {} · up to {} items per collection</span>",
        snapshot.offset, snapshot.page_size
    );
    if snapshot.offset > 0 {
        let _ = write!(
            result,
            "<a href=\"{path}?offset={}\">← Previous page</a>",
            snapshot.offset.saturating_sub(MAX_PAGE_SIZE as u32)
        );
    }
    if snapshot.has_more && snapshot.offset < 100_000 {
        let _ = write!(
            result,
            "<a href=\"{path}?offset={}\">Next page →</a>",
            snapshot.offset + MAX_PAGE_SIZE as u32
        );
    } else if snapshot.has_more {
        result.push_str("<span>Collection offset limit reached. Select an exact object to inspect its bound history.</span>");
    }
    let _ = write!(
        result,
        "</div><details class=provenance><summary>Projection provenance · schema {}</summary><p class=mono>Revision: {}</p><p>Database snapshot: {} · Evaluated at {} UTC Unix seconds</p></details>",
        snapshot.schema,
        escape(&snapshot.revision),
        escape(&snapshot.database_snapshot),
        snapshot.evaluated_at
    );

    result
}

pub fn readiness(value: &ReleaseReadiness) -> String {
    let subject = &value.subject;
    let state = enum_text(&value.state);
    let mut result = format!(
        "<a class=back href=/projects/{}/readiness>← Release invocations</a><section class=readiness data-readiness data-revision=\"{}\" data-check-url=\"/api/v1/projects/{}/readiness/{}\"><span class=eyebrow>AUTHORITY-OWNED BACKEND OBSERVATION</span><h2>{}</h2><p class=freshness role=status>STALE / HISTORICAL SNAPSHOT — live revision not confirmed</p><p>Development authority scope. This observation is not a deployment capability, production trust claim or certificate.</p></section><section class=panel><h2>Exact release identity</h2><dl class=facts>",
        subject.project,
        escape(&value.revision),
        subject.project,
        escape(&subject.invocation),
        state
    );
    for (label, text) in [
        ("Project", subject.project.to_string()),
        ("Repository", subject.repository.clone()),
        ("Source commit", subject.source.commit.as_str().into()),
        ("Source tree", subject.source.tree.as_str().into()),
        (
            "Source snapshot",
            subject.source.snapshot_sha256.as_str().into(),
        ),
        (
            "Certificate",
            subject
                .certificate
                .clone()
                .unwrap_or_else(|| "MISSING".into()),
        ),
        (
            "Artifact SHA256",
            subject.artifact.clone().unwrap_or_else(|| "MISSING".into()),
        ),
        (
            "Release Permit",
            subject
                .permit
                .clone()
                .unwrap_or_else(|| "MISSING / INVALID".into()),
        ),
        ("Build invocation", subject.invocation.clone()),
    ] {
        let _ = write!(
            result,
            "<div><dt>{label}</dt><dd class=mono>{}</dd></div>",
            escape(&text)
        );
    }
    result.push_str("</dl></section><section class=panel><h2>Readiness explanation</h2>");
    if value.blockers.is_empty() {
        result.push_str("<p>All selected certificate, source, build recipe/environment, independent A/B completion, exact artifact, canonical comparison and Release Permit bindings verified through the existing M6 authority semantics.</p>");
    } else {
        result.push_str("<div class=table-scroll><table><thead><tr><th scope=col>Blocker</th><th scope=col>Explanation</th><th scope=col>Required action category</th></tr></thead><tbody>");
        for blocker in &value.blockers {
            let _ = write!(
                result,
                "<tr><td><strong>{}</strong></td><td>{}<small class=mono>{}</small></td><td>{}</td></tr>",
                enum_text(&blocker.code),
                escape(&blocker.summary),
                escape(&blocker.affected_identity),
                escape(&blocker.remediation_category)
            );
        }
        result.push_str("</tbody></table></div>");
    }
    let _ = write!(
        result,
        "</section><section class=panel><h2>Verification & assurance boundary</h2><p>Source: {}. Certificate/permit verification requires explicitly selected public keys. Existence alone is insufficient. Offline verification remains independent of Glassmere.</p><p>Knowledge coverage, semantic review and native qualification retain their exact evidence scope. No new production signing, expiry, revocation or independent certification is established.</p><p class=mono>Schema {} · revision {} · UTC Unix seconds {}</p></section>",
        escape(&value.provenance),
        value.schema,
        escape(&value.revision),
        value.evaluated_at
    );

    result
}

pub fn evidence(
    item: &EvidenceObservation,
    bytes: &[u8],
    project: archcert_domain::ProjectId,
    page: &crate::inspection::Page,
) -> String {
    let preview = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_PREVIEW_BYTES)]);
    let mut result = format!(
        "<a class=back href=/projects/{project}/evidence>← Evidence registry</a><section class=panel><div class=panel-heading><h2>{}</h2><span class=tag>IMMUTABLE ACCEPTED EVIDENCE</span></div><dl class=facts><div><dt>SHA256</dt><dd class=mono>{}</dd></div><div><dt>Schema / producer</dt><dd>{} / {}</dd></div><div><dt>Size / accepted state</dt><dd>{} bytes / {}</dd></div><div><dt>Owning entity</dt><dd class=mono>{}</dd></div></dl><a class=button href=/projects/{project}/download/{}/{}>Download original bytes</a><p class=muted>Original bytes and digest are preserved. The bounded preview below is inert text; JSON formatting is not canonical evidence.</p></section>",
        escape(&item.role),
        escape(&item.sha256),
        item.schema,
        escape(&item.producer),
        item.size,
        escape(&item.state),
        escape(&item.entity),
        escape(&item.entity),
        escape(&item.sha256)
    );

    if !item.verification.is_empty() {
        result.push_str("<section class=panel><h2>Selected-key verification</h2>");
        result.push_str(&fields(&item.verification));
        result.push_str("</section>");
    }

    if item.role == "REVIEW" {
        result.push_str("<div class=callout><strong>SUPPLEMENTAL / NON-AUTHORITATIVE</strong><p>CONTRADICTION / AUTHORITY RESOLUTION REQUIRED when recorded. CLEAR contributes zero deterministic proof. Only typed accepted citations establish object identity; arbitrary URLs remain inert text.</p></div>");
    }
    result.push_str(&crate::inspection::render(item, bytes, project, page));

    let _ = write!(
        result,
        "<section class=panel><details><summary>Raw data: bounded inert preview</summary><p>Showing at most {} of {} bytes. Binary or truncated text may be incomplete.</p><pre>{}</pre></details></section>",
        MAX_PREVIEW_BYTES,
        item.size,
        escape(&redact_preview(&preview))
    );

    result
}

/// Preview redaction is conservative and never changes immutable download bytes.
pub(crate) fn redact_preview(text: &str) -> String {
    let mut private_key = false;
    let mut output = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("-----begin") && lower.contains("private key") {
            private_key = true;
        }
        let sensitive = private_key
            || [
                "api_key",
                "api-key",
                "authorization:",
                "password",
                "postgres://",
                "postgresql://",
                "provider_token",
                "\"token\"",
                "cookie:",
                "set-cookie:",
            ]
            .iter()
            .any(|marker| lower.contains(marker));
        if sensitive {
            output.push("[REDACTED: possible credential material]");
        } else {
            output.push(line);
        }
        if lower.contains("-----end") && lower.contains("private key") {
            private_key = false;
        }
    }

    output.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_redacts_representative_credentials_and_private_key_bodies() {
        let text = "ordinary evidence\nAPI_KEY=secret-a\nAuthorization: Bearer secret-b\npostgres://user:secret-c@db/name\n-----BEGIN PRIVATE KEY-----\nsecret-key-body\n-----END PRIVATE KEY-----\nordinary trailing evidence";

        let redacted = redact_preview(text);

        for secret in ["secret-a", "secret-b", "secret-c", "secret-key-body"] {
            assert!(!redacted.contains(secret));
        }
        assert!(redacted.contains("ordinary evidence"));
        assert!(redacted.contains("ordinary trailing evidence"));
    }
}
