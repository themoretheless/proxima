//! Applying the configured rewrite rules to traffic on the way through.
//!
//! The rules themselves live in [`crate::config`], which is where the decision
//! of what to change belongs. This module is only the part that touches a
//! [`HeaderMap`], because manipulating headers on the wire is the proxy's job
//! and pulling `http` types into the configuration to do it would be backwards.
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
//! Both record a note per change on the flow, so a header nobody typed is
//! traceable to the rule that put it there.

use http::header::{HeaderMap, HeaderName, HeaderValue};

use crate::config::{HeaderEdit, RewriteRules};

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
            let count = headers.get_all(&name).iter().count();
            if count == 0 {
                return None;
            }
            headers.remove(&name);
            // remove() takes one copy at a time, and a header can repeat.
            while headers.remove(&name).is_some() {}
            Some(format!("{} header {} removed", half.name(), name))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DialTarget, RewriteRule};

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
}
