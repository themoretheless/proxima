//! JSON pretty-print and syntax highlighting via `themoretheless-tokenizer`.
//!
//! Display only: nothing here rewrites capture storage. Pretty text is rebuilt
//! from a valid parse; tokens always cover that text losslessly so the
//! inspector can paint coloured spans with `textContent` (never `innerHTML`).

use serde::Serialize;
use themoretheless_tokenizer::json::{
    SemanticKind, Value, parse, semantic_tokens, tokenize as semantic_tokenize,
};

/// Soft ceiling so a hostile payload cannot force a multi-megabyte pretty tree.
pub const MAX_JSON_VIEW_BYTES: usize = 256 * 1024;

/// One highlighted run of the (possibly pretty-printed) source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonToken {
    /// Highlight class stem: property, string, number, boolean, null,
    /// punctuation, comment, whitespace, invalid.
    pub kind: &'static str,
    pub text: String,
}

/// Formatted JSON plus the tokens that paint it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonView {
    /// Pretty text when the parse was valid; otherwise the original source
    /// (still tokenised for best-effort colour).
    pub text: String,
    pub tokens: Vec<JsonToken>,
    /// True when the input was strict JSON and pretty-print succeeded.
    pub valid: bool,
}

/// Pretty-print and highlight `source` when it is JSON (or best-effort colour
/// when it is not). Returns `None` only when the input is empty.
#[must_use]
pub fn view(source: &str) -> Option<JsonView> {
    let source = source.trim();
    if source.is_empty() {
        return None;
    }
    if source.len() > MAX_JSON_VIEW_BYTES {
        // Still try to colour a truncated prefix rather than refusing entirely.
        let cut = truncate_at_char_boundary(source, MAX_JSON_VIEW_BYTES);
        return Some(highlight_only(cut, false));
    }

    let parsed = parse(source);
    if parsed.is_valid() {
        if let Some(value) = parsed.value() {
            let mut pretty = String::with_capacity(source.len().saturating_mul(2));
            write_value(&mut pretty, value, 0);
            if pretty.len() > MAX_JSON_VIEW_BYTES {
                pretty.truncate(MAX_JSON_VIEW_BYTES);
                while !pretty.is_char_boundary(pretty.len()) {
                    pretty.pop();
                }
                pretty.push_str("\n… truncated");
                return Some(highlight_only(&pretty, true));
            }
            let tokens = tokens_for(&pretty);
            return Some(JsonView {
                text: pretty,
                tokens,
                valid: true,
            });
        }
    }

    // Incomplete or invalid editor input: colour the raw source, do not invent
    // structure. Prefer parser-aware tokens when the recovering parse produced
    // any, else the legacy highlighter.
    Some(highlight_only(source, false))
}

/// Pretty-print only (no tokens). Used by JWT soft views and similar.
#[must_use]
pub fn pretty(source: &str) -> Option<String> {
    view(source).map(|v| v.text)
}

/// Whether `content_type` looks like JSON (mime subtype contains `json`).
#[must_use]
pub fn content_type_is_json(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|raw| raw.split(';').next())
        .map(|s| s.trim().to_ascii_lowercase())
        .is_some_and(|mime| mime.contains("json"))
}

/// Cheap heuristic before calling [`view`]: starts with `{` or `[` after trim.
#[must_use]
pub fn looks_like_json(source: &str) -> bool {
    matches!(
        source.trim_start().as_bytes().first().copied(),
        Some(b'{' | b'[')
    )
}

fn highlight_only(source: &str, valid: bool) -> JsonView {
    let tokens = tokens_for(source);
    JsonView {
        text: source.to_string(),
        tokens,
        valid,
    }
}

fn tokens_for(source: &str) -> Vec<JsonToken> {
    // Parser-aware labels (Property only when proven a key). Falls back to the
    // same path for incomplete text via recovering parse.
    let semantic = semantic_tokenize(source);
    // If the recovering path produced nothing useful, still cover the bytes.
    if semantic.tokens.is_empty() && !source.is_empty() {
        let legacy = themoretheless_tokenizer::tokenize_json(source);
        return legacy
            .tokens
            .into_iter()
            .filter_map(|token| {
                let text = token.text(source)?.to_string();
                Some(JsonToken {
                    kind: legacy_kind_name(token.kind),
                    text,
                })
            })
            .collect();
    }
    // When the parse recovered, re-run semantic_tokens on that parse is already
    // what tokenize() did. Cover every token including whitespace so concat
    // rebuilds source.
    let _ = semantic_tokens; // keep import meaningful if tokenize path changes
    semantic
        .tokens
        .into_iter()
        .filter_map(|token| {
            let text = token.text(source)?.to_string();
            Some(JsonToken {
                kind: semantic_kind_name(token.kind),
                text,
            })
        })
        .collect()
}

fn semantic_kind_name(kind: SemanticKind) -> &'static str {
    match kind {
        SemanticKind::Property => "property",
        SemanticKind::String => "string",
        SemanticKind::Number => "number",
        SemanticKind::Boolean => "boolean",
        SemanticKind::Null => "null",
        SemanticKind::Punctuation => "punctuation",
        SemanticKind::Comment => "comment",
        SemanticKind::Whitespace => "whitespace",
        SemanticKind::Invalid => "invalid",
        // non_exhaustive: new kinds fall back to a safe paint class.
        _ => "invalid",
    }
}

fn legacy_kind_name(kind: themoretheless_tokenizer::TokenKind) -> &'static str {
    use themoretheless_tokenizer::TokenKind;
    match kind {
        TokenKind::Property => "property",
        TokenKind::String => "string",
        TokenKind::Number => "number",
        TokenKind::Boolean => "boolean",
        TokenKind::Null => "null",
        TokenKind::Punctuation => "punctuation",
        TokenKind::Whitespace => "whitespace",
        TokenKind::Invalid => "invalid",
    }
}

fn write_value(out: &mut String, value: &Value<'_>, depth: usize) {
    match value {
        Value::Object(object) => {
            let members = object.members();
            if members.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (i, member) in members.iter().enumerate() {
                write_indent(out, depth + 1);
                out.push_str(member.key().raw());
                out.push_str(": ");
                write_value(out, member.value(), depth + 1);
                if i + 1 < members.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            write_indent(out, depth);
            out.push('}');
        }
        Value::Array(array) => {
            let elements = array.elements();
            if elements.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, element) in elements.iter().enumerate() {
                write_indent(out, depth + 1);
                write_value(out, element, depth + 1);
                if i + 1 < elements.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            write_indent(out, depth);
            out.push(']');
        }
        Value::String(s) => out.push_str(s.raw()),
        Value::Number(n) => out.push_str(n.as_str()),
        Value::Boolean(b) => out.push_str(if b.value() { "true" } else { "false" }),
        Value::Null(_) => out.push_str("null"),
        // SemanticKind / Value are non_exhaustive; unknown variants stay opaque.
        _ => out.push_str("null"),
    }
}

fn write_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn truncate_at_char_boundary(source: &str, max: usize) -> &str {
    if source.len() <= max {
        return source;
    }
    let mut end = max;
    while end > 0 && !source.is_char_boundary(end) {
        end -= 1;
    }
    &source[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_prints_and_colours_object_keys() {
        let view = view(r#"{"name":"Москва","n":1}"#).expect("json");
        assert!(view.valid);
        assert!(view.text.contains("\n"));
        assert!(view.text.contains("  \"name\""));
        assert!(view.tokens.iter().any(|t| t.kind == "property"));
        assert!(view.tokens.iter().any(|t| t.kind == "string"));
        assert!(view.tokens.iter().any(|t| t.kind == "number"));
        let rebuilt: String = view.tokens.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(rebuilt, view.text);
    }

    #[test]
    fn invalid_json_still_highlights() {
        let view = view(r#"{"name":"#).expect("partial");
        assert!(!view.valid);
        assert!(!view.tokens.is_empty());
        let rebuilt: String = view.tokens.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(rebuilt, view.text);
    }

    #[test]
    fn empty_is_none() {
        assert!(view("").is_none());
        assert!(view("   ").is_none());
    }
}
