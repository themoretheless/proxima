//! Soft, schema-free pretty views for captured bodies.
//!
//! These never rewrite the wire or the body store. They only turn opaque bytes
//! into a best-effort text tree for the inspector: protobuf field numbers,
//! gRPC length-prefixed messages, and JWT header/payload JSON. Failures fall
//! back to a short reason plus hex, never an API error.

use base64::Engine as _;

/// Ceiling on soft-view output so a hostile length-delimited field cannot grow
/// the pretty printer unboundedly. Smaller than the content-encoding bomb
/// ceiling: pretty trees are for reading, not archiving.
pub const MAX_PRETTY_BYTES: usize = 256 * 1024;

/// What kind of soft view was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SoftViewKind {
    Protobuf,
    Grpc,
    Jwt,
    Hex,
}

/// A display-only rendering of body (or header) bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftView {
    pub kind: SoftViewKind,
    /// Human-readable tree or pretty JSON.
    pub text: String,
    /// Optional note (compression flag, truncation, parse warning).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Best-effort soft view for body bytes, guided by `content_type` when present.
///
/// Detection order: gRPC content-type, protobuf content-type, protobuf wire
/// heuristic, then hex dump.
pub fn soft_view(bytes: &[u8], content_type: Option<&str>) -> SoftView {
    let mime = content_type
        .and_then(|raw| raw.split(';').next())
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    if mime.starts_with("application/grpc") {
        return soft_grpc(bytes);
    }
    if is_protobuf_mime(&mime) {
        return soft_protobuf(bytes, None);
    }
    // Heuristic: short frames that look like valid protobuf walk.
    if !bytes.is_empty() && looks_like_protobuf(bytes) {
        return soft_protobuf(bytes, Some("detected without content-type".into()));
    }
    soft_hex(bytes, None)
}

/// Soft-decode a JWT string (three base64url parts). Does not verify signatures.
pub fn soft_jwt(token: &str) -> Option<SoftView> {
    let token = token.trim();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    // JWT header always starts with `eyJ` when base64url-encoded `{"`.
    if !parts[0].starts_with("eyJ") {
        return None;
    }
    let header = decode_b64url_json(parts[0])?;
    let payload = decode_b64url_json(parts[1])?;
    let sig_note = if parts[2].is_empty() {
        "empty signature".to_string()
    } else {
        format!("signature {} base64url chars (not verified)", parts[2].len())
    };
    let text = format!(
        "header:\n{}\n\npayload:\n{}\n\n{}",
        pretty_json_or_raw(&header),
        pretty_json_or_raw(&payload),
        sig_note
    );
    Some(SoftView {
        kind: SoftViewKind::Jwt,
        text: truncate_text(text),
        note: Some("JWT soft view; signature not verified".into()),
    })
}

/// True when `Authorization` (or similar) looks like a Bearer JWT.
pub fn bearer_jwt(value: &str) -> Option<SoftView> {
    let value = value.trim();
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value);
    soft_jwt(token)
}

fn is_protobuf_mime(mime: &str) -> bool {
    matches!(
        mime,
        "application/protobuf"
            | "application/x-protobuf"
            | "application/vnd.google.protobuf"
            | "application/x-google-protobuf"
    ) || mime.ends_with("+protobuf")
        || mime.ends_with("+proto")
}

fn soft_grpc(bytes: &[u8]) -> SoftView {
    if bytes.is_empty() {
        return SoftView {
            kind: SoftViewKind::Grpc,
            text: "(empty gRPC body)".into(),
            note: None,
        };
    }
    let mut out = String::new();
    let mut offset = 0usize;
    let mut index = 0usize;
    let mut notes = Vec::new();
    while offset + 5 <= bytes.len() {
        let flag = bytes[offset];
        let len = u32::from_be_bytes([
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
        ]) as usize;
        offset += 5;
        if offset + len > bytes.len() {
            notes.push(format!(
                "message {index}: declared length {len} exceeds remaining {}",
                bytes.len() - offset
            ));
            break;
        }
        let msg = &bytes[offset..offset + len];
        offset += len;
        index += 1;
        if flag != 0 {
            notes.push(format!(
                "message {index}: compress_flag={flag} (message not inflated)"
            ));
            out.push_str(&format!(
                "=== gRPC message {index} (flag={flag}, {len} bytes) ===\n{}\n\n",
                hex_preview(msg, 256)
            ));
        } else {
            let inner = soft_protobuf(msg, None);
            out.push_str(&format!(
                "=== gRPC message {index} ({len} bytes) ===\n{}\n\n",
                inner.text
            ));
        }
        if out.len() > MAX_PRETTY_BYTES {
            notes.push("pretty output truncated".into());
            break;
        }
    }
    if offset < bytes.len() && notes.is_empty() {
        notes.push(format!("{} trailing bytes after messages", bytes.len() - offset));
    }
    if index == 0 {
        // Not framed: try raw protobuf.
        return soft_protobuf(bytes, Some("no gRPC length prefix found".into()));
    }
    SoftView {
        kind: SoftViewKind::Grpc,
        text: truncate_text(out),
        note: if notes.is_empty() {
            None
        } else {
            Some(notes.join("; "))
        },
    }
}

fn soft_protobuf(bytes: &[u8], note: Option<String>) -> SoftView {
    match walk_protobuf(bytes, 0, 8) {
        Ok(tree) if !tree.trim().is_empty() => SoftView {
            kind: SoftViewKind::Protobuf,
            text: truncate_text(tree),
            note,
        },
        Ok(_) => soft_hex(bytes, note.or(Some("empty protobuf walk".into()))),
        Err(err) => soft_hex(bytes, Some(err)),
    }
}

fn soft_hex(bytes: &[u8], note: Option<String>) -> SoftView {
    SoftView {
        kind: SoftViewKind::Hex,
        text: hex_preview(bytes, 512),
        note,
    }
}

fn looks_like_protobuf(bytes: &[u8]) -> bool {
    walk_protobuf(bytes, 0, 4).is_ok()
}

/// Walk protobuf wire format into a pseudo-text tree (field numbers only).
fn walk_protobuf(bytes: &[u8], depth: usize, max_depth: usize) -> Result<String, String> {
    if depth > max_depth {
        return Err("protobuf nesting too deep".into());
    }
    let mut out = String::new();
    let mut i = 0usize;
    let mut fields = 0usize;
    let indent = "  ".repeat(depth);
    while i < bytes.len() {
        let (key, n) = read_varint(bytes, i)?;
        i += n;
        let field = (key >> 3) as u32;
        let wire = (key & 0x7) as u8;
        if field == 0 {
            return Err("protobuf field number 0".into());
        }
        match wire {
            0 => {
                let (val, n) = read_varint(bytes, i)?;
                i += n;
                out.push_str(&format!("{indent}{field}: varint {val}\n"));
            }
            1 => {
                if i + 8 > bytes.len() {
                    return Err("truncated fixed64".into());
                }
                let raw = &bytes[i..i + 8];
                i += 8;
                out.push_str(&format!("{indent}{field}: fixed64 {}\n", hex_preview(raw, 8)));
            }
            2 => {
                let (len, n) = read_varint(bytes, i)?;
                i += n;
                let len = len as usize;
                if i + len > bytes.len() {
                    return Err(format!("truncated length-delimited field {field}"));
                }
                let payload = &bytes[i..i + len];
                i += len;
                if let Ok(s) = std::str::from_utf8(payload) {
                    if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t') {
                        out.push_str(&format!("{indent}{field}: string \"{}\"\n", escape_str(s)));
                        fields += 1;
                        continue;
                    }
                }
                if depth < max_depth {
                    if let Ok(nested) = walk_protobuf(payload, depth + 1, max_depth) {
                        if !nested.trim().is_empty() {
                            out.push_str(&format!("{indent}{field}: message {{\n{nested}{indent}}}\n"));
                            fields += 1;
                            continue;
                        }
                    }
                }
                out.push_str(&format!(
                    "{indent}{field}: bytes ({len}) {}\n",
                    hex_preview(payload, 32)
                ));
            }
            5 => {
                if i + 4 > bytes.len() {
                    return Err("truncated fixed32".into());
                }
                let raw = &bytes[i..i + 4];
                i += 4;
                out.push_str(&format!("{indent}{field}: fixed32 {}\n", hex_preview(raw, 4)));
            }
            other => return Err(format!("unknown protobuf wire type {other}")),
        }
        fields += 1;
        if out.len() > MAX_PRETTY_BYTES {
            out.push_str(&format!("{indent}… truncated\n"));
            break;
        }
        // A well-formed message should have at least one field; limit field
        // count so random binary fails closed quickly.
        if fields > 512 {
            return Err("too many protobuf fields".into());
        }
    }
    if fields == 0 && !bytes.is_empty() {
        return Err("no protobuf fields".into());
    }
    Ok(out)
}

fn read_varint(bytes: &[u8], mut i: usize) -> Result<(u64, usize), String> {
    let start = i;
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        if i >= bytes.len() {
            return Err("truncated varint".into());
        }
        let b = bytes[i];
        i += 1;
        result |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok((result, i - start));
        }
        shift += 7;
        if shift > 63 {
            return Err("varint too long".into());
        }
    }
}

fn hex_preview(bytes: &[u8], max: usize) -> String {
    let take = bytes.len().min(max);
    let mut s = String::with_capacity(take * 3);
    for (i, b) in bytes[..take].iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > max {
        s.push_str(&format!(" … (+{} bytes)", bytes.len() - max));
    }
    if s.is_empty() {
        s.push_str("(empty)");
    }
    s
}

fn escape_str(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\t' => vec!['\\', 't'],
            c => vec![c],
        })
        .collect()
}

fn decode_b64url_json(part: &str) -> Option<Vec<u8>> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let cleaned = part.trim_end_matches('=');
    engine.decode(cleaned).ok()
}

fn pretty_json_or_raw(bytes: &[u8]) -> String {
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| String::from_utf8_lossy(bytes).into()),
        Err(_) => String::from_utf8_lossy(bytes).into(),
    }
}

fn truncate_text(mut text: String) -> String {
    if text.len() > MAX_PRETTY_BYTES {
        text.truncate(MAX_PRETTY_BYTES);
        text.push_str("\n… truncated");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode field 1 as string "hi" (wire type 2).
    fn proto_string_field1(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        // key = (1 << 3) | 2 = 0x0a
        out.push(0x0a);
        out.push(s.len() as u8);
        out.extend_from_slice(s.as_bytes());
        out
    }

    #[test]
    fn protobuf_string_field_pretty() {
        let bytes = proto_string_field1("hello");
        let view = soft_view(&bytes, Some("application/protobuf"));
        assert_eq!(view.kind, SoftViewKind::Protobuf);
        assert!(view.text.contains("1: string \"hello\""), "{}", view.text);
    }

    #[test]
    fn grpc_length_prefixed_message() {
        let inner = proto_string_field1("hi");
        let mut bytes = vec![0u8]; // compress flag
        bytes.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&inner);
        let view = soft_view(&bytes, Some("application/grpc+proto"));
        assert_eq!(view.kind, SoftViewKind::Grpc);
        assert!(view.text.contains("gRPC message 1"), "{}", view.text);
        assert!(view.text.contains("string \"hi\""), "{}", view.text);
    }

    #[test]
    fn jwt_soft_decode() {
        // {"alg":"none"} . {"sub":"user"} . sig
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"sub":"user"}"#);
        let token = format!("{header}.{payload}.fakesig");
        let view = soft_jwt(&token).expect("jwt");
        assert_eq!(view.kind, SoftViewKind::Jwt);
        assert!(view.text.contains("alg"), "{}", view.text);
        assert!(view.text.contains("user"), "{}", view.text);
        let bearer = bearer_jwt(&format!("Bearer {token}")).expect("bearer");
        assert_eq!(bearer.kind, SoftViewKind::Jwt);
    }

    #[test]
    fn random_bytes_fall_back_to_hex() {
        let view = soft_view(&[0xff, 0xfe, 0xfd], None);
        assert_eq!(view.kind, SoftViewKind::Hex);
        assert!(view.text.contains("ff"));
    }
}
