//! Passive Rust syntax adapter. No compiler, macro expansion, build script,
//! checkout access, network or target execution is involved.
use archcert_application::knowledge::{KnowledgeError, KnowledgeExtractor, StructuralSink};
use archcert_domain::{
    knowledge::{NodeKind, RelationKind},
    source::SourceFile,
};
use quote::ToTokens;

/// Versioned bounded syntactic extractor; deliberately not a resolved call graph.
pub struct RustSyntaxExtractor;
impl KnowledgeExtractor for RustSyntaxExtractor {
    fn identity(&self) -> &'static str {
        "archcert-rust-syntax-v1/1.0.1"
    }
    fn supports(&self, file: &SourceFile) -> bool {
        file.path().as_str().ends_with(".rs")
    }
    fn extract(
        &self,
        file: &SourceFile,
        sink: &mut StructuralSink<'_>,
    ) -> Result<(), KnowledgeError> {
        if file.bytes().len() > sink.file_byte_limit() {
            return sink.blind_spot(
                "RUST_FILE_LIMIT",
                "Rust parser byte budget exceeded; inventory retained, structure incomplete",
            );
        }
        let Ok(text) = std::str::from_utf8(file.bytes()) else {
            return sink.blind_spot(
                "RUST_INVALID_ENCODING",
                "Rust syntax requires UTF-8; inventory retains exact bytes",
            );
        };
        // Conservative preflight includes strings/comments. It may reject valid
        // files rather than expose a recursively parsed arbitrarily deep input.
        // It is a resource bound, not a Rust lexer or parser correctness proof.
        let mut nesting = [0usize; 4];
        let mut punctuation = 0usize;
        let mut run = 0usize;
        for b in text.bytes() {
            if let Some(i) = b"([{<".iter().position(|v| *v == b) {
                nesting[i] += 1;
            }
            if let Some(i) = b")]}>".iter().position(|v| *v == b) {
                nesting[i] = nesting[i].saturating_sub(1);
            }
            if b.is_ascii_punctuation() {
                punctuation += 1;
                run += 1;
            } else if !b.is_ascii_whitespace() {
                run = 0;
            }
            if nesting.iter().any(|d| *d > 48) || punctuation > 8192 || run > 64 {
                return sink.blind_spot(
                    "RUST_COMPLEXITY_LIMIT",
                    "Conservative syntax complexity budget exceeded; structure incomplete",
                );
            }
        }
        let Ok(parsed) = syn::parse_file(text) else {
            return sink.blind_spot(
                "RUST_PARSE_UNSUPPORTED",
                "Rust syntax is invalid or unsupported by the pinned parser; no invented structure",
            );
        };
        items(&parsed.items, "root", 0, sink)?;
        sink.blind_spot("RUST_UNRESOLVED_SEMANTICS",
            "Syntax only: names, calls, dynamic dispatch, cfg activation, generated code, macros, function-local declarations and intended test coverage are unresolved")
    }
}
fn tokens(value: &impl ToTokens) -> String {
    value.to_token_stream().to_string()
}
fn is_test(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|a| a.path().segments.last().is_some_and(|s| s.ident == "test"))
}
fn items(
    declarations: &[syn::Item],
    prefix: &str,
    depth: usize,
    sink: &mut StructuralSink<'_>,
) -> Result<(), KnowledgeError> {
    if depth > 32 {
        return sink.blind_spot(
            "RUST_MODULE_DEPTH",
            "Inline module traversal depth exhausted; full review required",
        );
    }
    for (ordinal, item) in declarations.iter().enumerate() {
        let (kind, name) = match item {
            syn::Item::Struct(i) => (NodeKind::Symbol, format!("struct {}", i.ident)),
            syn::Item::Enum(i) => (NodeKind::Symbol, format!("enum {}", i.ident)),
            syn::Item::Trait(i) => (NodeKind::Symbol, format!("trait {}", i.ident)),
            syn::Item::Fn(i) => (
                if is_test(&i.attrs) {
                    NodeKind::Test
                } else {
                    NodeKind::Symbol
                },
                format!("fn {}", i.sig.ident),
            ),
            syn::Item::Mod(i) => (NodeKind::Module, format!("mod {}", i.ident)),
            syn::Item::Use(i) => (NodeKind::Dependency, format!("use {}", tokens(&i.tree))),
            syn::Item::Impl(i) => (NodeKind::Symbol, format!("impl {}", tokens(&i.self_ty))),
            syn::Item::Const(i) => (NodeKind::Symbol, format!("const {}", i.ident)),
            syn::Item::Static(i) => (NodeKind::Symbol, format!("static {}", i.ident)),
            syn::Item::Type(i) => (NodeKind::Symbol, format!("type {}", i.ident)),
            _ => {
                sink.blind_spot(
                    "RUST_ITEM_UNSUPPORTED",
                    "An item has no supported structural projection; bytes remain inventoried",
                )?;
                continue;
            }
        };
        if name.len() > 4096 {
            sink.blind_spot(
                "RUST_LABEL_LIMIT",
                "Declaration label exceeded the retained syntax bound",
            )?;
            continue;
        }
        let key = format!("{prefix}/{ordinal}/{name}");
        let syntax = tokens(item);
        let id = sink.node(&key, kind, name, syntax.as_bytes())?;
        if matches!(item, syn::Item::Use(_)) {
            sink.edge(sink.file_node(), id.clone(), RelationKind::Imports, true)?;
        }
        if let syn::Item::Mod(i) = item {
            if let Some((_, nested)) = &i.content {
                items(nested, &key, depth + 1, sink)?;
            } else {
                sink.blind_spot(
                    "RUST_EXTERNAL_MODULE_UNRESOLVED",
                    "Module declaration observed; compiler module/path resolution is unavailable",
                )?;
            }
        }
        if let syn::Item::Impl(i) = item {
            for (index, method) in i.items.iter().enumerate() {
                if let syn::ImplItem::Fn(f) = method {
                    let text = tokens(f);
                    let child = sink.node(
                        &format!("{key}/method/{index}/{}", f.sig.ident),
                        if is_test(&f.attrs) {
                            NodeKind::Test
                        } else {
                            NodeKind::Symbol
                        },
                        format!("method {}", f.sig.ident),
                        text.as_bytes(),
                    )?;
                    sink.edge(id.clone(), child, RelationKind::Defines, false)?;
                }
            }
            if let Some((_, path, _)) = &i.trait_ {
                let text = tokens(path);
                let dependency = sink.node(
                    &format!("{key}/trait"),
                    NodeKind::Dependency,
                    text.clone(),
                    text.as_bytes(),
                )?;
                sink.edge(id, dependency, RelationKind::Implements, true)?;
            }
        }
    }
    Ok(())
}
