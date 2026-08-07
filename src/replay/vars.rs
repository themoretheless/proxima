//! Environment variable substitution for composed and replayed requests.
//!
//! Placeholders use `{{name}}` (Postman-style). Unknown names are left as-is so
//! a typo stays visible in the wire capture rather than becoming an empty
//! string that is hard to debug. Matching is case-sensitive on the name.

use std::collections::HashMap;

/// Replaces every `{{name}}` whose name is present in `vars`.
///
/// Nested braces are not supported. A lone `{{` without a closing `}}` is left
/// unchanged. Names may contain letters, digits, `_`, `-` and `.`.
pub fn interpolate(input: &str, vars: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if let Some(end) = find_close(bytes, i + 2) {
                let name = &input[i + 2..end];
                let key = name.trim();
                if let Some(value) = vars.get(key) {
                    out.push_str(value);
                    i = end + 2;
                    continue;
                }
                // Unknown: keep the original placeholder text.
                out.push_str(&input[i..end + 2]);
                i = end + 2;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn find_close(bytes: &[u8], from: usize) -> Option<usize> {
    let mut j = from;
    while j + 1 < bytes.len() {
        if bytes[j] == b'}' && bytes[j + 1] == b'}' {
            return Some(j);
        }
        j += 1;
    }
    None
}

/// Applies [`interpolate`] to a URL, header values, and an optional UTF-8 body.
pub fn interpolate_headers(
    headers: &[(String, String)],
    vars: &HashMap<String, String>,
) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(n, v)| (n.clone(), interpolate(v, vars)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn replaces_known_placeholders() {
        let v = vars(&[("host", "api.staging.test"), ("token", "abc")]);
        assert_eq!(
            interpolate("https://{{host}}/v1?t={{token}}", &v),
            "https://api.staging.test/v1?t=abc"
        );
    }

    #[test]
    fn unknown_placeholders_stay() {
        let v = vars(&[]);
        assert_eq!(interpolate("{{missing}}/x", &v), "{{missing}}/x");
    }

    #[test]
    fn trims_name_whitespace() {
        let v = vars(&[("a", "1")]);
        assert_eq!(interpolate("{{ a }}", &v), "1");
    }
}
