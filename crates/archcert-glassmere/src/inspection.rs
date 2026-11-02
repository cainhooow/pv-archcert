//! Bounded formatting of retained artifacts. Parsing never establishes authority.

use crate::render::escape;
use archcert_application::glassmere::{EvidenceObservation, MAX_PAGE_SIZE};
use archcert_domain::ProjectId;
use serde::Deserialize;
use serde_json::Value;
use std::fmt::Write;

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_FIELDS: usize = 1024;
const MAX_FIELD_CHARS: usize = 256;
const MAX_COLLECTIONS: usize = 32;
const MAX_DEPTH: usize = 5;

/// Presentation pagination only; no source, authority or execution selectors.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Page {
    #[serde(default)]
    pub(crate) item_offset: u32,
    pub(crate) collection: Option<String>,
}

impl Page {
    pub(crate) fn valid(&self) -> bool {
        self.item_offset <= 100_000 && self.collection.as_deref().is_none_or(valid_path)
    }
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 128
        && path.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

fn select<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut value = root;

    for part in path.split('.') {
        value = match value {
            Value::Object(fields) => fields.get(part)?,
            Value::Array(items) => items.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }

    Some(value)
}

fn sensitive(key: &str) -> bool {
    let normalized: String = key
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect();

    ["password", "credential", "secret", "privatekey", "apikey"]
        .iter()
        .any(|marker| normalized.contains(marker))
        || matches!(
            normalized.as_str(),
            "authorization" | "cookie" | "setcookie"
        )
        || normalized.ends_with("token")
}

fn scalar(key: &str, value: &Value) -> String {
    if sensitive(key) {
        return "[REDACTED: possible credential material]".into();
    }

    let encoded = value.to_string();
    let redacted = super::render::redact_preview(&encoded);
    if redacted != encoded {
        return "[REDACTED: possible credential material]".into();
    }

    let text = match value {
        Value::String(text) => text.clone(),
        Value::Null => "NOT AVAILABLE / NOT RECORDED".into(),
        _ => encoded,
    };
    let mut bounded: String = text.chars().take(MAX_FIELD_CHARS).collect();
    if text.chars().count() > MAX_FIELD_CHARS {
        bounded.push_str("… [display truncated]");
    }

    bounded
}

fn opaque_array(key: &str) -> bool {
    matches!(key, "response_bytes" | "bytes" | "excerpt")
}

fn collections<'a>(
    value: &'a Value,
    prefix: &str,
    depth: usize,
    output: &mut Vec<(String, &'a [Value])>,
) {
    if depth > MAX_DEPTH || output.len() >= MAX_COLLECTIONS {
        return;
    }
    let Some(fields) = value.as_object() else {
        return;
    };

    // Discover object-level collections without visiting their elements. Large
    // claims/graphs cannot multiply traversal work before a page is selected.
    for (key, value) in fields.iter().take(32) {
        if sensitive(key) || opaque_array(key) {
            continue;
        }
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        if !valid_path(&path) {
            continue;
        }

        match value {
            Value::Array(items) if output.len() < MAX_COLLECTIONS => {
                output.push((path, items));
            }
            Value::Object(_) => collections(value, &path, depth + 1, output),
            _ => {}
        }
    }
}

struct View<'a> {
    item: &'a EvidenceObservation,
    project: ProjectId,
    fields_left: usize,
    truncated: bool,
}

impl View<'_> {
    fn url(&self, collection: &str, offset: u32) -> String {
        format!(
            "/projects/{}/evidence/{}/{}?collection={}&item_offset={offset}",
            self.project,
            escape(&self.item.entity),
            escape(&self.item.sha256),
            collection,
        )
    }

    fn fields(&mut self, value: &Value, prefix: &str, depth: usize, output: &mut String) {
        if self.fields_left == 0 || depth > MAX_DEPTH {
            self.truncated = true;
            return;
        }

        let Some(fields) = value.as_object() else {
            self.field(prefix, value, output);
            return;
        };

        for (key, value) in fields.iter().take(32) {
            if self.fields_left == 0 {
                self.truncated = true;
                break;
            }
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };

            if sensitive(key) {
                self.field(&path, &Value::String("[REDACTED]".into()), output);
                continue;
            }

            match value {
                Value::Object(_) => {
                    if valid_path(&path) {
                        self.fields_left -= 1;
                        let _ = write!(
                            output,
                            "<div><dt>{}</dt><dd><a href=\"{}\">Inspect nested fields</a></dd></div>",
                            escape(&path),
                            self.url(&path, 0)
                        );
                    }
                    self.fields(value, &path, depth + 1, output);
                }
                Value::Array(items) => {
                    self.fields_left -= 1;
                    let _ = write!(
                        output,
                        "<div><dt>{}</dt><dd>{} recorded items",
                        escape(&path.chars().take(128).collect::<String>()),
                        items.len()
                    );
                    if !opaque_array(key) && valid_path(&path) {
                        let _ = write!(
                            output,
                            " · <a href=\"{}\">Inspect collection</a>",
                            self.url(&path, 0)
                        );
                    } else {
                        output.push_str(" · original byte content is available separately");
                    }
                    output.push_str("</dd></div>");
                }
                _ => self.field(&path, value, output),
            }
        }

        self.truncated |= fields.len() > 32;
    }

    fn field(&mut self, path: &str, value: &Value, output: &mut String) {
        if self.fields_left == 0 {
            self.truncated = true;
            return;
        }
        self.fields_left -= 1;
        let _ = write!(
            output,
            "<div><dt>{}</dt><dd>{}</dd></div>",
            escape(&path.chars().take(128).collect::<String>()),
            escape(&scalar(path, value))
        );
    }
}

fn supported(item: &EvidenceObservation, value: &Value) -> bool {
    let schemas: &[u64] = match item.role.as_str() {
        "REQUEST" => &[1, 2, 3],
        "REVIEW" | "MANIFEST" | "GATE" | "CHALLENGE_PLAN" => &[1, 2],
        "CERTIFICATE" | "SOURCE_CERTIFICATE" | "PERMIT_ENVELOPE" | "PERMIT_PAYLOAD"
        | "KNOWLEDGE" | "IMPACT" | "AUTHORITY_PROFILE" | "CHALLENGE_RESULT" | "EVALUATION"
        | "BUNDLE" | "INPUT" | "RESULT_A" | "RESULT_B" | "REPRODUCIBILITY" => &[1],
        _ => return false,
    };
    let declared = value
        .get("schema")
        .or_else(|| value.pointer("/payload/schema"))
        .and_then(Value::as_u64);

    schemas.contains(&u64::from(item.schema)) && declared == Some(u64::from(item.schema))
}

fn title(role: &str) -> &str {
    match role {
        "KNOWLEDGE" => "Asterwyn coverage & blind spots",
        "IMPACT" => "Conservative impact and full-review requirements",
        "REVIEW" => "Greywatch claims, discoveries and contradictions",
        "REQUEST" => "Greywatch package and provider request",
        "CERTIFICATE" | "SOURCE_CERTIFICATE" => "Certificate identity and scope",
        "PERMIT_ENVELOPE" | "PERMIT_PAYLOAD" => "Release Permit identity and bindings",
        "MANIFEST" => "Evidence manifest references",
        "BUNDLE" | "CHALLENGE_RESULT" => "Execution and runtime observations",
        "RESULT_A" | "RESULT_B" => "Independent release attempt",
        "INPUT" => "Frozen release input and recipe",
        "REPRODUCIBILITY" => "Reproducibility comparison",
        "EVALUATION" => "Deterministic policy properties and findings",
        "AUTHORITY_PROFILE" => "Authority policy, profile and limits",
        _ => "Structured retained artifact",
    }
}

/// Display only. Signature, policy and release decisions stay in the query/verifier.
pub(crate) fn render(
    item: &EvidenceObservation,
    bytes: &[u8],
    project: ProjectId,
    page: &Page,
) -> String {
    if !page.valid() {
        return "<section class=panel><h2>INVALID inspection page</h2></section>".into();
    }
    if item.schema == 1 && matches!(item.role.as_str(), "ARTIFACT_A" | "ARTIFACT_B") {
        return "<section class=panel><h2>Release artifact</h2><p>Original binary bytes are retained by digest and size. Artifact authorization requires the exact Release Readiness view.</p></section>".into();
    }

    let value = if bytes.len() <= MAX_BYTES {
        serde_json::from_slice::<Value>(bytes).ok()
    } else {
        None
    };
    let Some(value) = value.filter(|value| supported(item, value)) else {
        return "<section class=panel><h2>UNSUPPORTED structured inspection</h2><p>The schema, role, encoding or size is unsupported for this display. Original registered bytes remain available separately. Unsupported inspection establishes no positive authority result.</p></section>".into();
    };

    let mut view = View {
        item,
        project,
        fields_left: MAX_FIELDS,
        truncated: false,
    };
    let mut result = format!(
        "<section class=panel data-structured-inspection><h2>{}</h2><p>Structured display of retained bytes. Parsing creates no proof. Use the separate backend verification observations and exact release bindings.</p>",
        title(&item.role)
    );
    if item.role == "REVIEW" {
        result.push_str("<div class=callout><strong>SUPPLEMENTAL / NON-AUTHORITATIVE</strong><p>Claims and contradictions remain as recorded. CLEAR contributes zero deterministic proof; unresolved contradictions require authority resolution.</p></div>");
    }

    let mut available = Vec::new();
    collections(&value, "", 0, &mut available);
    result.push_str("<h3>Recorded collections</h3><ul>");
    for (path, items) in &available {
        let _ = write!(
            result,
            "<li><a href=\"{}\">{}</a> · {} recorded items</li>",
            view.url(path, 0),
            escape(path),
            items.len()
        );
    }
    result.push_str("</ul><h3>Identity, provenance and scalar fields</h3><dl class=facts>");
    let mut summary = View {
        item,
        project,
        fields_left: 128,
        truncated: false,
    };
    summary.fields(&value, "", 0, &mut result);
    view.truncated |= summary.truncated;
    result.push_str("</dl>");

    let preferred = match item.role.as_str() {
        "KNOWLEDGE" => "coverage",
        "IMPACT" => "blind_spots",
        "REVIEW" => "normalized.claims",
        _ => "",
    };
    let selected = page
        .collection
        .as_deref()
        .or_else(|| {
            available
                .iter()
                .find(|(path, _)| path == preferred)
                .map(|(path, _)| path.as_str())
        })
        .or_else(|| available.first().map(|(path, _)| path.as_str()));

    if let Some(path) = selected {
        if path
            .split('.')
            .any(|part| sensitive(part) || opaque_array(part))
        {
            result.push_str("<p>Raw byte and sensitive collections are excluded from structured inspection. Original downloads remain a separate explicit private operation.</p>");
        } else if let Some(items) = select(&value, path).and_then(Value::as_array) {
            let start = page.item_offset as usize;
            let end = start.saturating_add(MAX_PAGE_SIZE).min(items.len());
            let _ = write!(
                result,
                "<h3>{}</h3><p>{} recorded items · showing at most {} from offset {}</p>",
                escape(path),
                items.len(),
                MAX_PAGE_SIZE,
                start
            );

            for (index, item) in items.iter().enumerate().take(end).skip(start) {
                let _ = write!(result, "<article><h4>Item {index}</h4><dl class=facts>");
                let mut row = View {
                    item: view.item,
                    project,
                    fields_left: 16,
                    truncated: false,
                };
                row.fields(item, &format!("{path}.{index}"), 0, &mut result);
                view.truncated |= row.truncated;
                result.push_str("</dl></article>");
            }
            if start >= items.len() {
                result.push_str("<p>No items on this collection page.</p>");
            }
            result.push_str("<nav class=pagination aria-label=\"Artifact collection pages\">");
            if page.item_offset > 0 {
                let _ = write!(
                    result,
                    "<a href=\"{}\">Previous items</a>",
                    view.url(path, page.item_offset.saturating_sub(MAX_PAGE_SIZE as u32))
                );
            }
            if end < items.len() && page.item_offset < 100_000 {
                let _ = write!(
                    result,
                    "<a href=\"{}\">Next items</a>",
                    view.url(path, page.item_offset + MAX_PAGE_SIZE as u32)
                );
            } else if end < items.len() {
                result.push_str("<span>Collection offset limit reached; inspect original registered bytes for the remaining items.</span>");
            }
            result.push_str("</nav>");
        } else if let Some(object) = select(&value, path).filter(|value| value.is_object()) {
            let _ = write!(result, "<h3>{}</h3><dl class=facts>", escape(path));
            view.fields(object, path, 0, &mut result);
            result.push_str("</dl>");
        } else {
            result.push_str("<p>NOT AVAILABLE: the selected collection does not exist in this exact artifact.</p>");
        }
    }

    if view.truncated {
        result.push_str("<p class=callout>Display fields/depth are bounded. Some details are omitted from this page; original bytes and collection links retain the complete registered record.</p>");
    }
    result.push_str("</section>");

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use archcert_domain::source::digest_bytes;
    use serde_json::json;

    type R = Result<(), Box<dyn std::error::Error>>;

    fn observe(role: &str, schema: u32, bytes: &[u8]) -> EvidenceObservation {
        EvidenceObservation {
            entity: "owned".into(),
            role: role.into(),
            sha256: digest_bytes(bytes).as_str().into(),
            size: bytes.len() as u64,
            schema,
            producer: "fixture".into(),
            state: "AVAILABLE".into(),
            verification: Vec::new(),
        }
    }

    #[test]
    fn collection_pages_preserve_every_item_and_order() -> R {
        let claims: Vec<_> = (0..105)
            .map(|index| json!({"claim": format!("claim-{index:03}")}))
            .collect();
        let bytes = serde_json::to_vec(&json!({
            "schema": 2,
            "normalized": {"claims": claims},
        }))?;
        let item = observe("REVIEW", 2, &bytes);
        let project = ProjectId::new();

        for (offset, count) in [(0, 50), (50, 50), (100, 5), (150, 0)] {
            let page = Page {
                item_offset: offset,
                collection: Some("normalized.claims".into()),
            };
            let html = render(&item, &bytes, project, &page);
            assert_eq!(html.matches("<article>").count(), count);
            for index in 0..105 {
                let visible = index >= offset && index < offset + 50;
                assert_eq!(html.contains(&format!("claim-{index:03}")), visible);
            }
            assert_eq!(html.contains("Previous items"), offset > 0);
            assert_eq!(html.contains("Next items"), offset < 100);
        }

        Ok(())
    }

    #[test]
    fn collection_ceiling_never_links_to_an_invalid_page() -> R {
        let bytes = serde_json::to_vec(&json!({
            "schema": 2,
            "normalized": {"claims": vec!["retained"; 100_051]},
        }))?;
        let item = observe("REVIEW", 2, &bytes);
        let html = render(
            &item,
            &bytes,
            ProjectId::new(),
            &Page {
                item_offset: 100_000,
                collection: Some("normalized.claims".into()),
            },
        );

        assert_eq!(html.matches("<article>").count(), 50);
        assert!(html.contains("Collection offset limit reached"));
        assert!(!html.contains("Next items"));
        assert!(html.contains("Previous items"));

        Ok(())
    }

    #[test]
    fn hostile_and_sensitive_fields_are_inert_without_creating_authority() -> R {
        let hostile = "<script>alert(1)</script><img src=x onerror=alert(1)>";
        let bytes = serde_json::to_vec(&json!({
            "schema": 2,
            "outcome": "CLEAR",
            "normalized": {
                "claims": [{"finding": hostile, "contradiction": "UNRESOLVED"}],
            },
            "provider_credentials": {"value": "must-stay-private"},
            "provider_token": "also-private",
            "public_key_sha256": "public-identity",
            "message": "postgresql://private-connection",
        }))?;
        let item = observe("REVIEW", 2, &bytes);
        let html = render(&item, &bytes, ProjectId::new(), &Page::default());

        assert!(!html.contains(hostile));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("must-stay-private"));
        assert!(!html.contains("also-private"));
        assert!(!html.contains("private-connection"));
        assert!(html.contains("public-identity"));
        assert!(html.contains("UNRESOLVED"));
        assert!(html.contains("SUPPLEMENTAL / NON-AUTHORITATIVE"));
        assert!(html.contains("CLEAR contributes zero deterministic proof"));
        assert!(!html.contains("data-readiness"));
        assert!(!html.contains("RELEASE_ALLOWED"));

        Ok(())
    }

    #[test]
    fn unsupported_schema_mismatch_and_encoding_never_gain_positive_display() -> R {
        for (role, schema, value) in [
            ("REVIEW", 999, json!({"schema": 999, "outcome": "CLEAR"})),
            ("REVIEW", 2, json!({"schema": 1, "outcome": "CLEAR"})),
            ("UNKNOWN", 1, json!({"schema": 1})),
        ] {
            let bytes = serde_json::to_vec(&value)?;
            let item = observe(role, schema, &bytes);
            let html = render(&item, &bytes, ProjectId::new(), &Page::default());
            assert!(html.contains("UNSUPPORTED"));
            assert!(!html.contains("data-structured-inspection"));
        }
        let item = observe("REVIEW", 2, b"not JSON");
        assert!(
            render(&item, b"not JSON", ProjectId::new(), &Page::default()).contains("UNSUPPORTED")
        );

        Ok(())
    }

    #[test]
    fn forged_collection_cannot_reveal_sensitive_or_opaque_values() -> R {
        let bytes = serde_json::to_vec(&json!({
            "schema": 2,
            "response_bytes": ["opaque-marker"],
            "provider_credentials": {"claims": ["secret-marker"]},
        }))?;
        let item = observe("REVIEW", 2, &bytes);
        for collection in ["response_bytes", "provider_credentials.claims"] {
            let html = render(
                &item,
                &bytes,
                ProjectId::new(),
                &Page {
                    item_offset: 0,
                    collection: Some(collection.into()),
                },
            );
            assert!(!html.contains("opaque-marker"));
            assert!(!html.contains("secret-marker"));
            assert!(html.contains("excluded from structured inspection"));
        }
        for collection in ["", "a..b", "<script>", "claims&item_offset=0"] {
            assert!(
                !Page {
                    item_offset: 0,
                    collection: Some(collection.into())
                }
                .valid()
            );
        }
        assert!(
            !Page {
                item_offset: 100_001,
                collection: None
            }
            .valid()
        );

        Ok(())
    }

    #[test]
    fn large_rows_are_bounded_without_losing_later_items_and_nested_fields_remain_accessible() -> R
    {
        let fields: serde_json::Map<String, Value> = (0..100)
            .map(|index| (format!("field_{index:03}"), Value::String("🚀".repeat(300))))
            .collect();
        let bytes = vec![b' '; MAX_BYTES + 1];
        let item = observe("REVIEW", 2, &bytes);
        let html = render(&item, &bytes, ProjectId::new(), &Page::default());
        // This deliberately exceeds the parse bound; the display must refuse it.
        assert!(bytes.len() > MAX_BYTES);
        assert!(html.contains("UNSUPPORTED"));

        let bytes = serde_json::to_vec(&json!({
            "schema": 2,
            "normalized": {"claims": vec![json!({"details": fields}); 51]},
        }))?;
        let item = observe("REVIEW", 2, &bytes);
        let project = ProjectId::new();
        let html = render(&item, &bytes, project, &Page::default());
        assert_eq!(html.matches("<article>").count(), 50);
        assert!(html.contains("Item 49"));
        assert!(html.contains("display truncated"));
        assert!(html.contains("Display fields/depth are bounded"));
        assert!(html.len() < 2 * 1024 * 1024);
        assert!(html.contains("normalized.claims.49.details"));

        let focused = render(
            &item,
            &bytes,
            project,
            &Page {
                item_offset: 0,
                collection: Some("normalized.claims.49.details".into()),
            },
        );
        assert!(focused.contains("field_031"));
        assert!(!focused.contains("field_032"));

        Ok(())
    }
}
