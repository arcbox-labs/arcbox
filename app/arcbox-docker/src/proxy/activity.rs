//! Idle-accounting classification of proxied Docker API requests.
//!
//! The System VM's idle tracking treats proxied Docker traffic as activity:
//! each request resets the idle clock and holds an [`super::ActivityLease`]
//! for the response's lifetime. That is right for operations that *use* the
//! VM, but wrong for unbounded read-only streams that merely *watch* it —
//! the ArcBox desktop UI keeps a `GET /events` subscription open for its
//! entire lifetime, and counting that stream as activity pins the lease
//! counter and disables idle reclaim outright (2026-07-15 follow-up to the
//! idle-balloon incident).

use axum::http::{Method, Uri};

/// How a proxied Docker API request counts toward System VM idle tracking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityClass {
    /// Uses the VM: resets the idle clock and holds the VM out of idle for
    /// the response's full lifetime (pulls, builds, exec, one-shot reads).
    Active,
    /// Watches the VM: an unbounded read-only stream (`/events`, log
    /// follow, streaming stats). Records no activity and takes no lease —
    /// the idle balloon is transparent to readers, so a subscriber loses
    /// nothing when the VM idles underneath it.
    PassiveObservation,
}

/// Classifies a request by method and path (version prefix already stripped
/// by the router middleware — see `api::strip_api_version_prefix`).
///
/// Only GET endpoints that stream observations indefinitely are passive.
/// One-shot reads stay active: they are bounded, so the idle clock simply
/// restarts when they finish; only unbounded streams can block idle forever.
pub fn classify(method: &Method, uri: &Uri) -> ActivityClass {
    if method != Method::GET {
        return ActivityClass::Active;
    }
    let path = uri.path();
    let query = uri.query().unwrap_or("");

    // The event stream stays open for the subscriber's lifetime (with
    // `until` it is bounded, but it is still pure observation).
    if path == "/events" {
        return ActivityClass::PassiveObservation;
    }

    // `/containers/{id}/logs?follow=…` and `/containers/{id}/stats`, which
    // streams unless the client opts out.
    let mut segments = path.trim_start_matches('/').split('/');
    if let (Some("containers"), Some(_id), Some(op), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        let streaming = match op {
            "logs" => query_flag(query, "follow", false),
            "stats" => query_flag(query, "stream", true),
            _ => false,
        };
        if streaming {
            return ActivityClass::PassiveObservation;
        }
    }

    ActivityClass::Active
}

/// Reads a boolean query parameter with dockerd's semantics
/// (`httputils.BoolValue`): missing → `default`; present with a value in
/// {"", "0", "no", "false", "none"} (case-insensitive) → false; anything
/// else → true. Values are compared literally — Docker clients never
/// percent-encode these flags.
fn query_flag(query: &str, key: &str, default: bool) -> bool {
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            let v = v.to_ascii_lowercase();
            return !matches!(v.as_str(), "" | "0" | "no" | "false" | "none");
        }
    }
    default
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(method: Method, uri: &str) -> ActivityClass {
        classify(&method, &uri.parse::<Uri>().unwrap())
    }

    #[test]
    fn events_subscription_is_passive() {
        assert_eq!(
            class(Method::GET, "/events"),
            ActivityClass::PassiveObservation
        );
        assert_eq!(
            class(Method::GET, "/events?since=123&filters=%7B%7D"),
            ActivityClass::PassiveObservation
        );
    }

    #[test]
    fn non_get_methods_are_active() {
        assert_eq!(class(Method::POST, "/events"), ActivityClass::Active);
        assert_eq!(
            class(Method::POST, "/containers/abc/logs?follow=1"),
            ActivityClass::Active
        );
    }

    #[test]
    fn log_follow_is_passive_one_shot_logs_are_active() {
        for uri in [
            "/containers/abc/logs?follow=1&stdout=1",
            "/containers/abc/logs?follow=true",
            "/containers/abc/logs?follow=TRUE",
        ] {
            assert_eq!(class(Method::GET, uri), ActivityClass::PassiveObservation);
        }
        for uri in [
            "/containers/abc/logs?stdout=1",
            "/containers/abc/logs?follow=0",
            "/containers/abc/logs?follow=false",
            "/containers/abc/logs?follow=",
        ] {
            assert_eq!(class(Method::GET, uri), ActivityClass::Active);
        }
    }

    #[test]
    fn stats_stream_by_default_one_shot_on_opt_out() {
        for uri in [
            "/containers/abc/stats",
            "/containers/abc/stats?stream=1",
            "/containers/abc/stats?stream=true",
        ] {
            assert_eq!(class(Method::GET, uri), ActivityClass::PassiveObservation);
        }
        for uri in [
            "/containers/abc/stats?stream=0",
            "/containers/abc/stats?stream=false&one-shot=true",
            "/containers/abc/stats?stream=",
        ] {
            assert_eq!(class(Method::GET, uri), ActivityClass::Active);
        }
    }

    #[test]
    fn bounded_reads_and_other_paths_stay_active() {
        for uri in [
            "/containers/json?all=true",
            "/containers/abc/json",
            "/images/json",
            "/version",
            "/_ping",
            "/containers/abc/export",
            "/containers/abc/nested/logs?follow=1",
        ] {
            assert_eq!(class(Method::GET, uri), ActivityClass::Active);
        }
    }
}
