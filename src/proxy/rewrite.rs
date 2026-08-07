//! Applying the configured rewrite rules to traffic on the way through, and the
//! live rule hub the inspector mutates without restarting the process.
//!
//! The rules themselves live in [`crate::config`], which is where the decision
//! of what to change belongs. This module is the part that touches a
//! [`HeaderMap`], path/query strings, and request/response bodies, because
//! manipulating those on the wire is the proxy's job and pulling `http` types
//! into the configuration to do it would be backwards.
//!
//! Surfaces covered here:
//!
//! - **Headers** via [`apply`]: set/remove on a [`HeaderMap`].
//! - **Path** via [`apply_path`]: literal find/replace on the full path-and-query.
//! - **Query** via [`apply_query`]: literal find/replace on the query only
//!   (everything after the first `?`).
//! - **Body** via [`apply_body`]: literal find/replace on a collected body for
//!   one [`Half`], with a per-rule size gate and a UTF-8 check.
//!
//! All text replacements are literal (not regex): every non-overlapping
//! left-to-right occurrence of `find` becomes `replace`. An empty `find` is a
//! no-op so we never interpret it as "insert between every character".
//!
//! Two things are deliberate about *when* this runs.
//!
//! Request edits are applied before the flow is recorded, so the inspector shows
//! what was actually sent rather than what the client handed over. A capture
//! that disagrees with the wire is worse than no capture: it is a debugging tool
//! lying about the thing being debugged.
//!
//! Response edits are applied before the response is recorded, for the same
//! reason from the other direction. What the inspector shows is what the client
//! received.
//!
//! Each change leaves a note on the flow, so a header, path segment, or body
//! token nobody typed is traceable to the rule that put it there.

use std::sync::Arc;

use http::header::{HeaderMap, HeaderName, HeaderValue};
use parking_lot::Mutex;

use crate::config::{HeaderEdit, RewriteRules, RewriteRulesBody, TextReplace};

/// Which half of the exchange is being edited. Only used to word the note left
/// on the flow, but a note that does not say which half is nearly useless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Half {
    Request,
    Response,
}

impl Half {
    fn name(self) -> &'static str {
        match self {
            Half::Request => "request",
            Half::Response => "response",
        }
    }
}

/// Applies every matching rule's edits for `half`, in order, and returns one
/// note per change made.
///
/// A rule that names a header the map does not have is not a failure and leaves
/// no note: removing something that was never there changed nothing, and saying
/// otherwise would fill the flow with noise on every request.
///
/// A header name or value that `http` refuses is skipped with a note saying so.
/// It cannot be put on the wire, and silently dropping it would leave someone
/// staring at a rule that does nothing.
pub fn apply(
    rules: &RewriteRules,
    half: Half,
    host: &str,
    method: &str,
    path: &str,
    headers: &mut HeaderMap,
) -> Vec<String> {
    let mut notes = Vec::new();
    for rule in rules.matching(host, method, path) {
        let edits = match half {
            Half::Request => &rule.request_headers,
            Half::Response => &rule.response_headers,
        };
        for edit in edits {
            if let Some(note) = apply_one(half, edit, headers) {
                notes.push(note);
            }
        }
    }
    notes
}

fn apply_one(half: Half, edit: &HeaderEdit, headers: &mut HeaderMap) -> Option<String> {
    let Ok(name) = HeaderName::from_bytes(edit.name().as_bytes()) else {
        return Some(format!(
            "{} header {:?} was not applied: that is not a legal header name",
            half.name(),
            edit.name()
        ));
    };

    match edit {
        HeaderEdit::Set { value, .. } => {
            let Ok(value) = HeaderValue::from_str(value) else {
                return Some(format!(
                    "{} header {} was not set: the value is not legal in a header",
                    half.name(),
                    name
                ));
            };
            // insert, not append: an override that leaves the original next to
            // it has overridden nothing, and which one an origin honours is
            // exactly the confusion this is meant to remove.
            match headers.insert(&name, value) {
                Some(_) => Some(format!("{} header {} replaced", half.name(), name)),
                None => Some(format!("{} header {} added", half.name(), name)),
            }
        }
        HeaderEdit::Remove { .. } => {
            // remove() takes every value under the name, not just the first,
            // which matters for the headers that repeat: Set-Cookie, Via.
            headers
                .remove(&name)
                .map(|_| format!("{} header {} removed", half.name(), name))
        }
    }
}

/* ------------------------------------------------------------------ */
/* path / query / body text rewrites                                   */
/* ------------------------------------------------------------------ */

/// Apply path+query replacements to `path` (the path-and-query string as sent).
///
/// Matching uses the path value at call time. Every matching rule's
/// `path_replacements` run in order; later rules see earlier edits. Returns one
/// note per replacement that actually changed the string.
pub fn apply_path(
    rules: &RewriteRules,
    host: &str,
    method: &str,
    path: &mut String,
) -> Vec<String> {
    // Indices so matching can borrow `path` without locking it for the later
    // mutable rewrites (matching ties its lifetime to the path string).
    let indices = matching_indices(rules, host, method, path.as_str());
    let mut notes = Vec::new();
    for i in indices {
        apply_text_replacements(
            path,
            &rules.rules[i].path_replacements,
            "path",
            &mut notes,
        );
    }
    notes
}

/// Apply query-only replacements: when `path` contains `?`, only the substring
/// after the first `?` is rewritten. The path segment and the `?` itself are
/// left alone. No query means no work and no notes.
pub fn apply_query(
    rules: &RewriteRules,
    host: &str,
    method: &str,
    path: &mut String,
) -> Vec<String> {
    let Some(qpos) = path.find('?') else {
        return Vec::new();
    };
    let indices = matching_indices(rules, host, method, path.as_str());
    if indices.is_empty() {
        return Vec::new();
    }

    let mut query = path[qpos + 1..].to_string();
    let mut notes = Vec::new();
    for i in indices {
        apply_text_replacements(
            &mut query,
            &rules.rules[i].query_replacements,
            "query",
            &mut notes,
        );
    }
    path.replace_range(qpos + 1.., &query);
    notes
}

/// True when any matching rule wants a non-empty body rewrite for `half`.
///
/// Used by the forwarder to decide whether to collect a body that would
/// otherwise stream. Empty rule lists keep the zero-buffer path.
pub fn needs_body_rewrite(
    rules: &RewriteRules,
    half: Half,
    host: &str,
    method: &str,
    path: &str,
) -> bool {
    rules.matching(host, method, path).any(|rule| {
        let br = match half {
            Half::Request => rule.request_body.as_ref(),
            Half::Response => rule.response_body.as_ref(),
        };
        br.is_some_and(|b| !b.is_noop())
    })
}

/// Apply body text replacements for `half`.
///
/// The body is treated as UTF-8 text. If the bytes are not valid UTF-8 and at
/// least one matching rule wants a body rewrite, the body is left unchanged and
/// a single skip note is returned. If `body.len()` is over a rule's effective
/// `max_bytes` gate, that rule is skipped with a note and later rules still run.
pub fn apply_body(
    rules: &RewriteRules,
    half: Half,
    host: &str,
    method: &str,
    path: &str,
    body: &mut Vec<u8>,
) -> Vec<String> {
    let indices = matching_indices(rules, host, method, path);
    let rewrites: Vec<_> = indices
        .into_iter()
        .filter_map(|i| {
            let br = match half {
                Half::Request => rules.rules[i].request_body.as_ref(),
                Half::Response => rules.rules[i].response_body.as_ref(),
            }?;
            if br.is_noop() {
                None
            } else {
                Some(br)
            }
        })
        .collect();
    if rewrites.is_empty() {
        return Vec::new();
    }

    let Ok(mut text) = std::str::from_utf8(body).map(|s| s.to_string()) else {
        return vec![format!(
            "{} body rewrite skipped: not valid UTF-8",
            half.name()
        )];
    };

    let body_len = body.len() as u64;
    let note_prefix = format!("{} body", half.name());
    let mut notes = Vec::new();
    for br in rewrites {
        if body_len > br.effective_max_bytes() {
            notes.push(format!(
                "{} body rewrite skipped: over size gate",
                half.name()
            ));
            continue;
        }
        apply_text_replacements(&mut text, &br.replacements, &note_prefix, &mut notes);
    }

    *body = text.into_bytes();
    notes
}

/// Indices of rules that match, so callers can re-borrow `rules` after releasing
/// the path string used for matching.
fn matching_indices(rules: &RewriteRules, host: &str, method: &str, path: &str) -> Vec<usize> {
    rules
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.matches(host, method, path))
        .map(|(i, _)| i)
        .collect()
}

/// Literal find/replace: every non-overlapping left-to-right match of `find`
/// becomes `replace`. Empty `find` is skipped. A note is recorded only when the
/// text actually changes.
fn apply_text_replacements(
    text: &mut String,
    replacements: &[TextReplace],
    surface: &str,
    notes: &mut Vec<String>,
) {
    for rep in replacements {
        if rep.find.is_empty() {
            continue;
        }
        let next = text.replace(&rep.find, &rep.replace);
        if next != *text {
            *text = next;
            notes.push(format!(
                "{} replaced '{}' → '{}'",
                surface, rep.find, rep.replace
            ));
        }
    }
}

/* ------------------------------------------------------------------ */
/* live rule hub                                                       */
/* ------------------------------------------------------------------ */

/// Mutable rewrite rules (headers, map-host, map-local) for the running proxy.
///
/// Seeded from the startup config; the inspector and REST replace the list
/// without restarting. Lookups clone the current rules under a short lock.
#[derive(Debug, Default)]
pub struct RewriteHub {
    inner: Mutex<RewriteRules>,
}

impl RewriteHub {
    pub fn new(rules: RewriteRules) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(rules),
        })
    }

    pub fn empty() -> Arc<Self> {
        Self::new(RewriteRules::default())
    }

    pub fn snapshot(&self) -> RewriteRules {
        self.inner.lock().clone()
    }

    pub fn rules_body(&self) -> RewriteRulesBody {
        self.snapshot().into()
    }

    pub fn set_rules(&self, body: RewriteRulesBody) {
        *self.inner.lock() = body.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BodyRewrite, DialTarget, RewriteRule, TextReplace};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn rules(rules: Vec<RewriteRule>) -> RewriteRules {
        RewriteRules { rules }
    }

    fn set(name: &str, value: &str) -> HeaderEdit {
        HeaderEdit::Set {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    fn remove(name: &str) -> HeaderEdit {
        HeaderEdit::Remove {
            name: name.to_string(),
        }
    }

    fn text(find: &str, replace: &str) -> TextReplace {
        TextReplace {
            find: find.to_string(),
            replace: replace.to_string(),
        }
    }

    #[test]
    fn a_rule_with_no_conditions_applies_to_everything() {
        let rules = rules(vec![RewriteRule {
            request_headers: vec![set("authorization", "Bearer test")],
            ..RewriteRule::default()
        }]);

        let mut map = headers(&[("accept", "*/*")]);
        let notes = apply(
            &rules,
            Half::Request,
            "api.example.com",
            "GET",
            "/v1/users",
            &mut map,
        );
        assert_eq!(map.get("authorization").unwrap(), "Bearer test");
        assert_eq!(notes.len(), 1, "the change was not recorded: {notes:?}");
        assert!(notes[0].contains("authorization"));

        // A different host, method and path, and it still applies.
        let mut other = headers(&[]);
        apply(&rules, Half::Request, "cdn.other.net", "POST", "/", &mut other);
        assert!(other.contains_key("authorization"));
    }

    #[test]
    fn setting_replaces_every_copy_rather_than_appending() {
        let rules = rules(vec![RewriteRule {
            request_headers: vec![set("authorization", "Bearer new")],
            ..RewriteRule::default()
        }]);
        let mut map = headers(&[
            ("authorization", "Bearer old"),
            ("authorization", "Bearer older"),
        ]);

        apply(&rules, Half::Request, "api.example.com", "GET", "/", &mut map);
        assert_eq!(
            map.get_all("authorization").iter().count(),
            1,
            "an override that leaves the original beside it has overridden nothing"
        );
        assert_eq!(map.get("authorization").unwrap(), "Bearer new");
    }

    #[test]
    fn removing_takes_every_copy() {
        let rules = rules(vec![RewriteRule {
            response_headers: vec![remove("set-cookie")],
            ..RewriteRule::default()
        }]);
        let mut map = headers(&[
            ("set-cookie", "a=1"),
            ("set-cookie", "b=2"),
            ("content-type", "text/html"),
        ]);

        let notes = apply(&rules, Half::Response, "api.example.com", "GET", "/", &mut map);
        assert!(
            !map.contains_key("set-cookie"),
            "a repeated header was only partly removed"
        );
        assert!(map.contains_key("content-type"));
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn removing_a_header_that_was_not_there_says_nothing() {
        let rules = rules(vec![RewriteRule {
            request_headers: vec![remove("authorization")],
            ..RewriteRule::default()
        }]);
        let mut map = headers(&[("accept", "*/*")]);

        let notes = apply(&rules, Half::Request, "api.example.com", "GET", "/", &mut map);
        assert!(
            notes.is_empty(),
            "a rule that changed nothing must not leave a note on every request: {notes:?}"
        );
    }

    #[test]
    fn the_two_halves_do_not_borrow_each_others_edits() {
        let rules = rules(vec![RewriteRule {
            request_headers: vec![set("x-request", "1")],
            response_headers: vec![set("x-response", "2")],
            ..RewriteRule::default()
        }]);

        let mut request = headers(&[]);
        apply(&rules, Half::Request, "h", "GET", "/", &mut request);
        assert!(request.contains_key("x-request"));
        assert!(!request.contains_key("x-response"));

        let mut response = headers(&[]);
        apply(&rules, Half::Response, "h", "GET", "/", &mut response);
        assert!(response.contains_key("x-response"));
        assert!(!response.contains_key("x-request"));
    }

    #[test]
    fn conditions_narrow_a_rule_to_what_it_names() {
        let rules = rules(vec![RewriteRule {
            hosts: vec!["*.example.com".into()],
            methods: vec!["POST".into()],
            path_prefix: Some("/v1/".into()),
            request_headers: vec![set("x-marked", "yes")],
            ..RewriteRule::default()
        }]);

        let hit = |host: &str, method: &str, path: &str| {
            let mut map = headers(&[]);
            apply(&rules, Half::Request, host, method, path, &mut map);
            map.contains_key("x-marked")
        };

        assert!(hit("api.example.com", "POST", "/v1/users"));
        assert!(hit("api.example.com", "post", "/v1/users"), "case of the method");
        assert!(!hit("api.other.net", "POST", "/v1/users"), "host");
        assert!(!hit("api.example.com", "GET", "/v1/users"), "method");
        assert!(!hit("api.example.com", "POST", "/v2/users"), "path");
    }

    #[test]
    fn later_rules_win() {
        let rules = rules(vec![
            RewriteRule {
                request_headers: vec![set("user-agent", "first")],
                ..RewriteRule::default()
            },
            RewriteRule {
                hosts: vec!["api.example.com".into()],
                request_headers: vec![set("user-agent", "second")],
                ..RewriteRule::default()
            },
        ]);

        let mut map = headers(&[]);
        apply(&rules, Half::Request, "api.example.com", "GET", "/", &mut map);
        assert_eq!(
            map.get("user-agent").unwrap(),
            "second",
            "a list of overrides has to read top to bottom"
        );

        // The narrower rule does not match here, so the broad one stands.
        let mut other = headers(&[]);
        apply(&rules, Half::Request, "other.net", "GET", "/", &mut other);
        assert_eq!(other.get("user-agent").unwrap(), "first");
    }

    #[test]
    fn an_illegal_header_is_reported_rather_than_dropped_in_silence() {
        let rules = rules(vec![RewriteRule {
            request_headers: vec![
                set("bad name", "x"),
                set("x-fine", "line\nbreak"),
                set("x-ok", "value"),
            ],
            ..RewriteRule::default()
        }]);
        let mut map = headers(&[]);

        let notes = apply(&rules, Half::Request, "h", "GET", "/", &mut map);
        assert!(map.contains_key("x-ok"), "one bad rule stopped the good ones");
        assert!(!map.contains_key("x-fine"));
        assert_eq!(notes.len(), 3);
        assert!(
            notes.iter().any(|note| note.contains("legal header name")),
            "nothing said why the rule did nothing: {notes:?}"
        );
        assert!(notes.iter().any(|note| note.contains("not legal in a header")));
    }

    #[test]
    fn the_last_matching_target_decides_where_a_request_goes() {
        let rules = rules(vec![
            RewriteRule {
                to: Some(DialTarget {
                    host: "127.0.0.1".into(),
                    port: Some(3000),
                }),
                ..RewriteRule::default()
            },
            RewriteRule {
                hosts: vec!["api.example.com".into()],
                to: Some(DialTarget {
                    host: "127.0.0.1".into(),
                    port: Some(4000),
                }),
                ..RewriteRule::default()
            },
        ]);

        let target = rules
            .dial_target("api.example.com", "GET", "/")
            .expect("a target");
        assert_eq!(target.port, Some(4000));

        let broad = rules.dial_target("other.net", "GET", "/").expect("a target");
        assert_eq!(broad.port, Some(3000));
    }

    #[test]
    fn rules_that_change_nothing_are_recognised_as_such() {
        assert!(RewriteRules::default().is_empty());
        assert!(rules(vec![RewriteRule {
            hosts: vec!["api.example.com".into()],
            ..RewriteRule::default()
        }])
        .is_empty());
        assert!(!rules(vec![RewriteRule {
            request_headers: vec![remove("cookie")],
            ..RewriteRule::default()
        }])
        .is_empty());
    }

    #[test]
    fn path_replacements_rewrite_the_full_path_and_query() {
        let rules = rules(vec![RewriteRule {
            path_replacements: vec![text("/v1/", "/v2/"), text("old", "new")],
            ..RewriteRule::default()
        }]);
        let mut path = "/v1/users?token=old".to_string();
        let notes = apply_path(&rules, "api.example.com", "GET", &mut path);
        assert_eq!(path, "/v2/users?token=new");
        assert_eq!(notes.len(), 2);
        assert!(notes[0].contains("path replaced '/v1/' → '/v2/'"));
        assert!(notes[1].contains("path replaced 'old' → 'new'"));
    }

    #[test]
    fn path_empty_find_is_a_noop_and_misses_leave_no_note() {
        let rules = rules(vec![RewriteRule {
            path_replacements: vec![text("", "x"), text("missing", "y")],
            ..RewriteRule::default()
        }]);
        let mut path = "/keep".to_string();
        let notes = apply_path(&rules, "h", "GET", &mut path);
        assert_eq!(path, "/keep");
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn path_replacements_are_non_overlapping_left_to_right() {
        let rules = rules(vec![RewriteRule {
            // "aa" in "aaa" matches once at the start, leaving a trailing "a".
            path_replacements: vec![text("aa", "b")],
            ..RewriteRule::default()
        }]);
        let mut path = "/aaa".to_string();
        apply_path(&rules, "h", "GET", &mut path);
        assert_eq!(path, "/ba");
    }

    #[test]
    fn query_replacements_touch_only_after_the_question_mark() {
        let rules = rules(vec![RewriteRule {
            query_replacements: vec![text("user", "admin"), text("/v1", "/nope")],
            ..RewriteRule::default()
        }]);
        let mut path = "/v1/user?name=user&role=user".to_string();
        let notes = apply_query(&rules, "api.example.com", "GET", &mut path);
        assert_eq!(path, "/v1/user?name=admin&role=admin");
        assert!(
            !path.contains("/nope"),
            "path segment must not be rewritten by query rules: {path}"
        );
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("query replaced 'user' → 'admin'"));
    }

    #[test]
    fn query_without_question_mark_is_untouched() {
        let rules = rules(vec![RewriteRule {
            query_replacements: vec![text("user", "admin")],
            ..RewriteRule::default()
        }]);
        let mut path = "/v1/user".to_string();
        let notes = apply_query(&rules, "h", "GET", &mut path);
        assert_eq!(path, "/v1/user");
        assert!(notes.is_empty());
    }

    #[test]
    fn request_body_replacements_rewrite_utf8_bytes() {
        let rules = rules(vec![RewriteRule {
            request_body: Some(BodyRewrite {
                replacements: vec![text("foo", "bar"), text("x", "y")],
                max_bytes: 0,
            }),
            ..RewriteRule::default()
        }]);
        let mut body = b"foo and x".to_vec();
        let notes = apply_body(
            &rules,
            Half::Request,
            "api.example.com",
            "POST",
            "/v1",
            &mut body,
        );
        assert_eq!(body, b"bar and y");
        assert_eq!(notes.len(), 2);
        assert!(notes[0].contains("request body replaced 'foo' → 'bar'"));
        assert!(notes[1].contains("request body replaced 'x' → 'y'"));
    }

    #[test]
    fn response_body_does_not_use_request_body_rules() {
        let rules = rules(vec![RewriteRule {
            request_body: Some(BodyRewrite {
                replacements: vec![text("a", "b")],
                max_bytes: 0,
            }),
            response_body: Some(BodyRewrite {
                replacements: vec![text("c", "d")],
                max_bytes: 0,
            }),
            ..RewriteRule::default()
        }]);
        let mut body = b"a c".to_vec();
        let notes = apply_body(&rules, Half::Response, "h", "GET", "/", &mut body);
        assert_eq!(body, b"a d");
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("response body replaced 'c' → 'd'"));
    }

    #[test]
    fn body_over_size_gate_is_skipped_with_a_note() {
        let rules = rules(vec![RewriteRule {
            request_body: Some(BodyRewrite {
                replacements: vec![text("secret", "redacted")],
                max_bytes: 4,
            }),
            ..RewriteRule::default()
        }]);
        let mut body = b"secret-token".to_vec();
        let notes = apply_body(&rules, Half::Request, "h", "POST", "/", &mut body);
        assert_eq!(body, b"secret-token", "oversize body must not be rewritten");
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].contains("request body rewrite skipped: over size gate"),
            "{notes:?}"
        );
    }

    #[test]
    fn body_at_size_gate_is_still_rewritten() {
        let payload = b"abcd";
        let rules = rules(vec![RewriteRule {
            request_body: Some(BodyRewrite {
                replacements: vec![text("ab", "xy")],
                max_bytes: payload.len() as u64,
            }),
            ..RewriteRule::default()
        }]);
        let mut body = payload.to_vec();
        let notes = apply_body(&rules, Half::Request, "h", "POST", "/", &mut body);
        assert_eq!(body, b"xycd");
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn non_utf8_body_is_skipped_with_a_note() {
        let rules = rules(vec![RewriteRule {
            request_body: Some(BodyRewrite {
                replacements: vec![text("a", "b")],
                max_bytes: 0,
            }),
            ..RewriteRule::default()
        }]);
        let mut body = vec![0xff, 0xfe, 0xfd];
        let notes = apply_body(&rules, Half::Request, "h", "POST", "/", &mut body);
        assert_eq!(body, vec![0xff, 0xfe, 0xfd]);
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].contains("request body rewrite skipped: not valid UTF-8"),
            "{notes:?}"
        );
    }

    #[test]
    fn body_rules_respect_match_conditions() {
        let rules = rules(vec![RewriteRule {
            hosts: vec!["api.example.com".into()],
            request_body: Some(BodyRewrite {
                replacements: vec![text("a", "b")],
                max_bytes: 0,
            }),
            ..RewriteRule::default()
        }]);
        let mut body = b"a".to_vec();
        let notes = apply_body(&rules, Half::Request, "other.net", "POST", "/", &mut body);
        assert_eq!(body, b"a");
        assert!(notes.is_empty());
    }

    #[test]
    fn later_path_rules_see_earlier_edits() {
        let rules = rules(vec![
            RewriteRule {
                path_replacements: vec![text("/old", "/mid")],
                ..RewriteRule::default()
            },
            RewriteRule {
                path_replacements: vec![text("/mid", "/new")],
                ..RewriteRule::default()
            },
        ]);
        let mut path = "/old/x".to_string();
        apply_path(&rules, "h", "GET", &mut path);
        assert_eq!(path, "/new/x");
    }
}
