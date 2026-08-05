//! Undoing `Content-Encoding` on captured bodies.
//!
//! Everything here runs on bytes that came off the network from a server we do
//! not trust, so the only real danger is a decompression bomb: a few kilobytes
//! that expand into gigabytes. Every decoder is therefore read through a hard
//! output ceiling rather than being handed a size the stream claims for itself.

use std::io::Read;

use anyhow::{anyhow, Context, Result};

/// Hard ceiling on the output of a single decode. A body that expands past
/// this is treated as hostile rather than merely large: the capture limit is
/// measured in megabytes, so nothing legitimate lands here.
pub const MAX_DECODED_BYTES: u64 = 64 * 1024 * 1024;

/// Decodes `bytes` according to `content_encoding`, which may name several
/// encodings separated by commas.
pub fn decode_body(bytes: &[u8], content_encoding: Option<&str>) -> Result<Vec<u8>> {
    decode_body_with_limit(bytes, content_encoding, MAX_DECODED_BYTES)
}

/// [`decode_body`] with an explicit output ceiling. Exposed mainly so tests can
/// prove the bomb guard without allocating the production ceiling.
pub fn decode_body_with_limit(
    bytes: &[u8],
    content_encoding: Option<&str>,
    max_output: u64,
) -> Result<Vec<u8>> {
    let header = content_encoding.unwrap_or("").trim();
    if header.is_empty() {
        return Ok(bytes.to_vec());
    }

    let layers: Vec<&str> = header
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if layers.is_empty() {
        return Ok(bytes.to_vec());
    }

    let mut current = bytes.to_vec();
    // The header lists transformations in the order the sender applied them,
    // so the rightmost is the outermost and has to come off first.
    for layer in layers.iter().rev() {
        let name = layer.to_ascii_lowercase();
        current = decode_layer(&current, &name, max_output)
            .with_context(|| format!("decoding content-encoding \"{name}\""))?;
    }
    Ok(current)
}

fn decode_layer(bytes: &[u8], name: &str, max_output: u64) -> Result<Vec<u8>> {
    match name {
        "identity" | "none" => Ok(bytes.to_vec()),
        // MultiGzDecoder rather than GzDecoder: a server is allowed to send
        // several concatenated members and GzDecoder stops after the first.
        "gzip" | "x-gzip" => read_capped(flate2::read::MultiGzDecoder::new(bytes), max_output),
        "deflate" | "x-deflate" => decode_deflate(bytes, max_output),
        "br" => read_capped(brotli::Decompressor::new(bytes, BROTLI_BUFFER), max_output),
        "zstd" => {
            let decoder =
                zstd::stream::read::Decoder::new(bytes).context("starting the zstd decoder")?;
            read_capped(decoder, max_output)
        }
        other => Err(anyhow!("unsupported content-encoding \"{other}\"")),
    }
}

const BROTLI_BUFFER: usize = 8192;

fn decode_deflate(bytes: &[u8], max_output: u64) -> Result<Vec<u8>> {
    match read_capped(flate2::read::ZlibDecoder::new(bytes), max_output) {
        Ok(out) => Ok(out),
        Err(zlib_err) => {
            // RFC 9110 says `deflate` means a zlib stream, but a long tail of
            // servers sends a bare deflate stream with no zlib header. Retry
            // before declaring the body undecodable.
            read_capped(flate2::read::DeflateDecoder::new(bytes), max_output).map_err(|raw_err| {
                anyhow!("zlib framing failed ({zlib_err}); raw deflate also failed ({raw_err})")
            })
        }
    }
}

/// Reads a decoder to completion, refusing to keep going past `max_output`.
/// The `+ 1` is what lets us tell "exactly at the ceiling" from "over it".
fn read_capped<R: Read>(reader: R, max_output: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut limited = reader.take(max_output.saturating_add(1));
    limited
        .read_to_end(&mut out)
        .map_err(|e| anyhow!("{e}"))
        .context("reading the decompressed stream")?;
    if out.len() as u64 > max_output {
        return Err(anyhow!(
            "decompressed output exceeded the {max_output} byte ceiling"
        ));
    }
    Ok(out)
}

/// Whether a body with this `Content-Type` can be shown as text rather than
/// hex. Unknown or absent types are treated as binary, which is the safe
/// direction: worst case the UI shows base64 instead of mojibake.
pub fn is_textual(content_type: Option<&str>) -> bool {
    let Some(raw) = content_type else {
        return false;
    };
    let mime = raw
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if mime.is_empty() {
        return false;
    }
    if mime.starts_with("text/") {
        return true;
    }
    if mime.ends_with("+json") || mime.ends_with("+xml") || mime.ends_with("+text") {
        return true;
    }
    matches!(
        mime.as_str(),
        "application/json"
            | "application/ld+json"
            | "application/javascript"
            | "application/x-javascript"
            | "application/ecmascript"
            | "application/xml"
            | "application/x-www-form-urlencoded"
            | "application/graphql"
            | "application/x-ndjson"
            | "application/ndjson"
            | "application/csv"
            | "application/sql"
            | "application/x-sh"
            | "image/svg+xml"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn brotli_compress(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            enc.write_all(data).unwrap();
        }
        out
    }

    #[test]
    fn absent_and_identity_encodings_pass_through() {
        let body = b"{\"ok\":true}";
        assert_eq!(decode_body(body, None).unwrap(), body);
        assert_eq!(decode_body(body, Some("")).unwrap(), body);
        assert_eq!(decode_body(body, Some("  ")).unwrap(), body);
        assert_eq!(decode_body(body, Some("identity")).unwrap(), body);
    }

    #[test]
    fn gzip_round_trip() {
        let body = b"the quick brown fox jumps over the lazy dog".repeat(40);
        let encoded = gzip(&body);
        assert!(encoded.len() < body.len());
        assert_eq!(decode_body(&encoded, Some("gzip")).unwrap(), body);
        assert_eq!(decode_body(&encoded, Some("x-gzip")).unwrap(), body);
        assert_eq!(decode_body(&encoded, Some("GZIP")).unwrap(), body);
    }

    #[test]
    fn brotli_round_trip() {
        let body = b"{\"items\":[1,2,3,4,5,6,7,8,9,10]}".repeat(20);
        let encoded = brotli_compress(&body);
        assert_eq!(decode_body(&encoded, Some("br")).unwrap(), body);
    }

    #[test]
    fn zstd_round_trip() {
        let body = b"zstandard payload".repeat(50);
        let encoded = zstd::encode_all(&body[..], 3).unwrap();
        assert_eq!(decode_body(&encoded, Some("zstd")).unwrap(), body);
    }

    #[test]
    fn deflate_accepts_both_framings() {
        let body = b"deflate me please, twice".repeat(10);
        assert_eq!(decode_body(&zlib(&body), Some("deflate")).unwrap(), body);
        assert_eq!(
            decode_body(&raw_deflate(&body), Some("deflate")).unwrap(),
            body
        );
    }

    #[test]
    fn multiple_encodings_unwind_right_to_left() {
        let body = b"layered payload that compresses well".repeat(30);
        // "gzip, br" means gzip was applied first, then brotli on top.
        let encoded = brotli_compress(&gzip(&body));
        assert_eq!(decode_body(&encoded, Some("gzip, br")).unwrap(), body);
        assert_eq!(decode_body(&encoded, Some(" gzip , br ")).unwrap(), body);

        // Unwinding in the wrong order has to fail rather than return garbage.
        let wrong = gzip(&brotli_compress(&body));
        assert!(decode_body(&wrong, Some("gzip, br")).is_err());
        assert_eq!(decode_body(&wrong, Some("br, gzip")).unwrap(), body);
    }

    #[test]
    fn identity_layer_inside_a_list_is_skipped() {
        let body = b"mixed list".repeat(5);
        let encoded = gzip(&body);
        assert_eq!(decode_body(&encoded, Some("gzip, identity")).unwrap(), body);
    }

    #[test]
    fn unknown_encoding_is_named_in_the_error() {
        let err = decode_body(b"whatever", Some("magic")).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("magic"), "{text}");
    }

    #[test]
    fn failure_names_the_encoding_that_failed() {
        let err = decode_body(b"this is not a gzip stream", Some("gzip")).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("\"gzip\""), "{text}");

        // The failing layer is named even when it sits inside a list: brotli
        // succeeds here and hands plain text to the gzip decoder, which cannot
        // take it.
        let encoded = brotli_compress(b"still not a gzip stream");
        let err = decode_body(&encoded, Some("gzip, br")).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("\"gzip\""), "{text}");
    }

    #[test]
    fn decompression_bomb_is_rejected() {
        let bomb = gzip(&vec![0u8; 8 * 1024 * 1024]);
        assert!(bomb.len() < 64 * 1024, "bomb should be tiny on the wire");

        let err = decode_body_with_limit(&bomb, Some("gzip"), 1024 * 1024).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("ceiling"), "{text}");
        assert!(text.contains("gzip"), "{text}");

        // Just under the ceiling still decodes.
        let modest = gzip(&vec![7u8; 4096]);
        let out = decode_body_with_limit(&modest, Some("gzip"), 1024 * 1024).unwrap();
        assert_eq!(out.len(), 4096);
    }

    #[test]
    fn output_exactly_at_the_ceiling_is_allowed() {
        let encoded = gzip(&vec![1u8; 1000]);
        assert_eq!(
            decode_body_with_limit(&encoded, Some("gzip"), 1000)
                .unwrap()
                .len(),
            1000
        );
        assert!(decode_body_with_limit(&encoded, Some("gzip"), 999).is_err());
    }

    #[test]
    fn textual_types() {
        assert!(is_textual(Some("text/html")));
        assert!(is_textual(Some("text/plain; charset=utf-8")));
        assert!(is_textual(Some("application/json")));
        assert!(is_textual(Some("Application/JSON; charset=UTF-8")));
        assert!(is_textual(Some("application/vnd.api+json")));
        assert!(is_textual(Some("image/svg+xml")));
        assert!(is_textual(Some("application/x-www-form-urlencoded")));

        assert!(!is_textual(None));
        assert!(!is_textual(Some("")));
        assert!(!is_textual(Some("image/png")));
        assert!(!is_textual(Some("application/octet-stream")));
        assert!(!is_textual(Some("application/protobuf")));
    }
}
