use crate::api::AppState;
use crate::error::{DockerError, Result};
use arcbox_core::event::Event;
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::Response;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio_stream::wrappers::ReceiverStream;

// ============================================================================
// Events Handler — host-only (streams from EventBus)
// ============================================================================

/// Events query parameters.
#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    /// Show events since this timestamp (Unix seconds or RFC3339).
    pub since: Option<String>,
    /// Show events until this timestamp (Unix seconds or RFC3339).
    pub until: Option<String>,
    /// Filters (JSON encoded).
    pub filters: Option<String>,
}

#[derive(Default, Debug, Clone)]
struct EventFilters {
    fields: HashMap<String, HashSet<String>>,
}

impl EventFilters {
    fn add(&mut self, key: &str, value: String) {
        self.fields
            .entry(key.to_string())
            .or_default()
            .insert(value);
    }

    fn get(&self, key: &str) -> Vec<String> {
        self.fields
            .get(key)
            .map(|values| values.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn exact_match(&self, key: &str, source: &str) -> bool {
        let Some(values) = self.fields.get(key) else {
            return true;
        };
        if values.is_empty() {
            return true;
        }
        values.contains(source)
    }

    fn fuzzy_match(&self, key: &str, source: &str) -> bool {
        if self.exact_match(key, source) {
            return true;
        }
        let Some(values) = self.fields.get(key) else {
            return true;
        };
        for prefix in values {
            if source.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    fn match_kv_list(&self, key: &str, attributes: &HashMap<String, String>) -> bool {
        let Some(values) = self.fields.get(key) else {
            return true;
        };
        if values.is_empty() {
            return true;
        }
        if attributes.is_empty() {
            return false;
        }
        for value in values {
            let (attr_key, attr_value) = match value.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (value.as_str(), None),
            };
            let Some(found) = attributes.get(attr_key) else {
                return false;
            };
            if let Some(expected) = attr_value {
                if found != expected {
                    return false;
                }
            }
        }
        true
    }
}

#[derive(Serialize)]
struct EventMessage {
    #[serde(rename = "Type")]
    event_type: String,
    #[serde(rename = "Action")]
    action: String,
    #[serde(rename = "Actor")]
    actor: EventActor,
    #[serde(rename = "scope")]
    scope: String,
    #[serde(rename = "time")]
    time: i64,
    #[serde(rename = "timeNano")]
    time_nano: i64,
}

#[derive(Serialize)]
struct EventActor {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Attributes")]
    attributes: HashMap<String, String>,
}

struct EventMapping {
    event_type: &'static str,
    action: &'static str,
    actor_id: String,
    attributes: HashMap<String, String>,
    legacy_from: Option<String>,
}

/// Stream Docker-style events.
pub async fn events(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<EventsQuery>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response> {
    let filters = parse_event_filters(params.filters)?;
    let since = parse_event_timestamp(params.since.as_deref())?;
    let until = parse_event_timestamp(params.until.as_deref())?;
    let api_version = api_version_from_uri(&uri).unwrap_or_else(|| crate::API_VERSION.to_string());
    let include_legacy_fields = version_lt(&api_version, "1.52");
    let skip_image_create = version_lt(&api_version, "1.46");
    let content_type = negotiate_event_content_type(&headers);

    if let Some(until) = until {
        let now = chrono::Utc::now().timestamp();
        if until < now {
            let (tx, rx) =
                tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(1);
            drop(tx);
            let body = Body::from_stream(ReceiverStream::new(rx));
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .body(body)
                .unwrap());
        }
    }

    let mut event_rx = state.runtime.event_bus().subscribe();
    let (tx, rx) = tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(64);

    let scope = "local";
    tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    let now = chrono::Utc::now();
                    let time = now.timestamp();
                    if let Some(since) = since {
                        if time < since {
                            continue;
                        }
                    }
                    if let Some(until) = until {
                        if time > until {
                            break;
                        }
                    }

                    let mapping = match map_event(&event) {
                        Some(mapping) => mapping,
                        None => continue,
                    };

                    if skip_image_create
                        && mapping.event_type == "image"
                        && mapping.action == "create"
                    {
                        continue;
                    }

                    if !event_matches_filters(
                        &filters,
                        mapping.event_type,
                        mapping.action,
                        &mapping.actor_id,
                        &mapping.attributes,
                        scope,
                    ) {
                        continue;
                    }

                    let event_message = EventMessage {
                        event_type: mapping.event_type.to_string(),
                        action: mapping.action.to_string(),
                        actor: EventActor {
                            id: mapping.actor_id.clone(),
                            attributes: mapping.attributes.clone(),
                        },
                        scope: scope.to_string(),
                        time,
                        time_nano: now.timestamp_nanos_opt().unwrap_or(time * 1_000_000_000),
                    };
                    let mut event_value = match serde_json::to_value(event_message) {
                        Ok(value) => value,
                        Err(e) => {
                            tracing::warn!("Failed to serialize event: {}", e);
                            continue;
                        }
                    };

                    if include_legacy_fields {
                        if let serde_json::Value::Object(ref mut map) = event_value {
                            if mapping.event_type == "container" {
                                map.insert(
                                    "id".to_string(),
                                    serde_json::Value::String(mapping.actor_id.clone()),
                                );
                                map.insert(
                                    "status".to_string(),
                                    serde_json::Value::String(mapping.action.to_string()),
                                );
                                if let Some(from) = &mapping.legacy_from {
                                    map.insert(
                                        "from".to_string(),
                                        serde_json::Value::String(from.clone()),
                                    );
                                }
                            } else if mapping.event_type == "image" {
                                map.insert(
                                    "id".to_string(),
                                    serde_json::Value::String(mapping.actor_id.clone()),
                                );
                                map.insert(
                                    "status".to_string(),
                                    serde_json::Value::String(mapping.action.to_string()),
                                );
                            }
                        }
                    }

                    let line = match encode_event_line(&event_value, content_type) {
                        Ok(line) => line,
                        Err(e) => {
                            tracing::warn!("Failed to encode event: {}", e);
                            continue;
                        }
                    };

                    if tx.send(Ok(line)).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    });

    let body = Body::from_stream(ReceiverStream::new(rx));

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(body)
        .unwrap())
}

// ============================================================================
// Event helpers (unchanged)
// ============================================================================

fn parse_event_timestamp(value: Option<&str>) -> Result<Option<i64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if let Ok(ts) = trimmed.parse::<i64>() {
        return Ok(Some(ts));
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Ok(Some(dt.timestamp()));
    }

    Err(DockerError::BadRequest(format!(
        "invalid timestamp: {trimmed}"
    )))
}

fn parse_event_filters(filters: Option<String>) -> Result<EventFilters> {
    let raw = match filters {
        Some(raw) if !raw.trim().is_empty() => raw,
        _ => return Ok(EventFilters::default()),
    };

    if let Ok(parsed) = serde_json::from_str::<HashMap<String, HashMap<String, bool>>>(&raw) {
        let mut filters = EventFilters::default();
        for (key, values) in parsed {
            for value in values.keys() {
                filters.add(&key, value.to_string());
            }
        }
        return Ok(filters);
    }

    if let Ok(parsed) = serde_json::from_str::<HashMap<String, Vec<String>>>(&raw) {
        let mut filters = EventFilters::default();
        for (key, values) in parsed {
            for value in values {
                filters.add(&key, value);
            }
        }
        return Ok(filters);
    }

    Err(DockerError::BadRequest(
        "invalid filters parameter".to_string(),
    ))
}

fn event_matches_filters(
    filters: &EventFilters,
    event_type: &str,
    action: &str,
    actor_id: &str,
    attributes: &HashMap<String, String>,
    scope: &str,
) -> bool {
    if !match_event_action(filters, action) {
        return false;
    }
    if !filters.exact_match("type", event_type) {
        return false;
    }
    if !filters.exact_match("scope", scope) {
        return false;
    }
    if !fuzzy_match_name(filters, "daemon", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "container", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "plugin", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "volume", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "network", actor_id, attributes.get("name")) {
        return false;
    }
    if !match_image(filters, event_type, actor_id, attributes) {
        return false;
    }
    if !fuzzy_match_name(filters, "node", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "service", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "secret", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "config", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "machine", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "vm", actor_id, attributes.get("id")) {
        return false;
    }
    if !filters.match_kv_list("label", attributes) {
        return false;
    }

    true
}

fn match_event_action(filters: &EventFilters, action: &str) -> bool {
    if filter_contains(
        filters,
        "event",
        &["health_status", "exec_create", "exec_start"],
    ) {
        return filters.fuzzy_match("event", action);
    }
    filters.exact_match("event", action)
}

fn filter_contains(filters: &EventFilters, key: &str, values: &[&str]) -> bool {
    for value in filters.get(key) {
        if values.iter().any(|candidate| candidate == &value) {
            return true;
        }
    }
    false
}

fn fuzzy_match_name(
    filters: &EventFilters,
    key: &str,
    actor_id: &str,
    name: Option<&String>,
) -> bool {
    if filters.fuzzy_match(key, actor_id) {
        return true;
    }
    name.map(|value| filters.fuzzy_match(key, value))
        .unwrap_or(false)
}

fn match_image(
    filters: &EventFilters,
    event_type: &str,
    actor_id: &str,
    attributes: &HashMap<String, String>,
) -> bool {
    let name_attr = if event_type == "image" {
        "name"
    } else {
        "image"
    };
    let image_name = attributes
        .get(name_attr)
        .map(|value| value.as_str())
        .unwrap_or("");
    let stripped_id = strip_tag(actor_id);
    let stripped_name = strip_tag(image_name);

    filters.exact_match("image", actor_id)
        || filters.exact_match("image", image_name)
        || filters.exact_match("image", stripped_id.as_str())
        || filters.exact_match("image", stripped_name.as_str())
}

fn strip_tag(image: &str) -> String {
    let mut name = match image.split_once('@') {
        Some((prefix, _)) => prefix.to_string(),
        None => image.to_string(),
    };

    let last_slash = name.rfind('/');
    if let Some(colon) = name.rfind(':') {
        if last_slash.map_or(true, |slash| colon > slash) {
            name.truncate(colon);
        }
    }

    if let Some(stripped) = name.strip_prefix("docker.io/") {
        name = stripped.to_string();
        if let Some(stripped) = name.strip_prefix("library/") {
            name = stripped.to_string();
        }
    }

    name
}

fn normalize_container_name(name: &str) -> String {
    name.trim_start_matches('/').to_string()
}

fn normalize_signal(signal: &str) -> String {
    if !signal.is_empty() && signal.chars().all(|c| c.is_ascii_digit()) {
        return signal.to_string();
    }

    let upper = signal.trim().trim_start_matches("SIG").to_uppercase();
    let number = match upper.as_str() {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" => 6,
        "BUS" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "CHLD" => 17,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        "TTIN" => 21,
        "TTOU" => 22,
        "URG" => 23,
        "XCPU" => 24,
        "XFSZ" => 25,
        "VTALRM" => 26,
        "PROF" => 27,
        "WINCH" => 28,
        "IO" => 29,
        "SYS" => 31,
        _ => return signal.to_string(),
    };
    number.to_string()
}

const MEDIA_TYPE_JSON: &str = "application/json";
const MEDIA_TYPE_JSON_LINES: &str = "application/jsonl";
const MEDIA_TYPE_NDJSON: &str = "application/x-ndjson";
const MEDIA_TYPE_JSON_SEQ: &str = "application/json-seq";
const JSON_SEQ_RS: u8 = 0x1e;

fn negotiate_event_content_type(headers: &HeaderMap) -> &'static str {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    for part in accept.split(',') {
        let media = part.trim().split(';').next().unwrap_or("").trim();
        match media {
            MEDIA_TYPE_JSON_SEQ => return MEDIA_TYPE_JSON_SEQ,
            MEDIA_TYPE_JSON_LINES => return MEDIA_TYPE_JSON_LINES,
            MEDIA_TYPE_NDJSON => return MEDIA_TYPE_NDJSON,
            MEDIA_TYPE_JSON => return MEDIA_TYPE_JSON,
            _ => {}
        }
    }

    MEDIA_TYPE_JSON
}

fn encode_event_line(event: &serde_json::Value, content_type: &str) -> std::io::Result<Bytes> {
    let mut payload = serde_json::to_vec(event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    if content_type == MEDIA_TYPE_JSON_SEQ {
        let mut buf = Vec::with_capacity(payload.len() + 2);
        buf.push(JSON_SEQ_RS);
        buf.append(&mut payload);
        buf.push(b'\n');
        return Ok(Bytes::from(buf));
    }

    payload.push(b'\n');
    Ok(Bytes::from(payload))
}

fn api_version_from_uri(uri: &Uri) -> Option<String> {
    let path = uri.path().trim_start_matches('/');
    let mut segments = path.split('/');
    let first = segments.next()?;
    if let Some(version) = first.strip_prefix('v') {
        if !version.is_empty() {
            return Some(version.to_string());
        }
    }
    None
}

fn version_lt(version: &str, other: &str) -> bool {
    let Some(left) = parse_version(version) else {
        return true;
    };
    let Some(right) = parse_version(other) else {
        return false;
    };
    left < right
}

fn parse_version(version: &str) -> Option<(u64, u64)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn merge_labels(
    mut attributes: HashMap<String, String>,
    labels: &HashMap<String, String>,
) -> HashMap<String, String> {
    for (key, value) in labels {
        attributes
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
    attributes
}

fn container_mapping<I>(
    action: &'static str,
    id: &str,
    name: &str,
    image: &str,
    labels: &HashMap<String, String>,
    extra_attrs: I,
) -> EventMapping
where
    I: IntoIterator<Item = (&'static str, String)>,
{
    let mut attributes = HashMap::new();
    if !image.is_empty() {
        attributes.insert("image".to_string(), image.to_string());
    }
    attributes.insert("name".to_string(), normalize_container_name(name));
    for (key, value) in extra_attrs {
        attributes.insert(key.to_string(), value);
    }

    EventMapping {
        event_type: "container",
        action,
        actor_id: id.to_string(),
        attributes: merge_labels(attributes, labels),
        legacy_from: if image.is_empty() {
            None
        } else {
            Some(image.to_string())
        },
    }
}

fn map_event(event: &Event) -> Option<EventMapping> {
    match event {
        Event::ContainerCreated {
            id,
            name,
            image,
            labels,
        } => Some(container_mapping(
            "create",
            id,
            name,
            image,
            labels,
            std::iter::empty::<(&'static str, String)>(),
        )),
        Event::ContainerStarted {
            id,
            name,
            image,
            labels,
        } => Some(container_mapping(
            "start",
            id,
            name,
            image,
            labels,
            std::iter::empty::<(&'static str, String)>(),
        )),
        Event::ContainerStopped {
            id,
            name,
            image,
            labels,
            exit_code: _,
        } => Some(container_mapping(
            "stop",
            id,
            name,
            image,
            labels,
            std::iter::empty::<(&'static str, String)>(),
        )),
        Event::ContainerKilled {
            id,
            name,
            image,
            labels,
            signal,
            exit_code: _,
        } => Some(container_mapping(
            "kill",
            id,
            name,
            image,
            labels,
            [("signal", normalize_signal(signal))],
        )),
        Event::ContainerDied {
            id,
            name,
            image,
            labels,
            exit_code,
        } => Some(container_mapping(
            "die",
            id,
            name,
            image,
            labels,
            exit_code
                .map(|code| ("exitCode", code.to_string()))
                .into_iter(),
        )),
        Event::ContainerRemoved {
            id,
            name,
            image,
            labels,
        } => Some(container_mapping(
            "destroy",
            id,
            name,
            image,
            labels,
            std::iter::empty::<(&'static str, String)>(),
        )),
        Event::ImagePulled { id, reference } => Some(EventMapping {
            event_type: "image",
            action: "pull",
            actor_id: id.clone(),
            attributes: HashMap::from([("name".to_string(), reference.clone())]),
            legacy_from: None,
        }),
        Event::ImageRemoved { id, reference } => Some(EventMapping {
            event_type: "image",
            action: "delete",
            actor_id: id.clone(),
            attributes: HashMap::from([("name".to_string(), reference.clone())]),
            legacy_from: None,
        }),
        Event::NetworkCreated {
            id,
            name,
            driver,
            labels: _,
        } => Some(EventMapping {
            event_type: "network",
            action: "create",
            actor_id: id.clone(),
            attributes: HashMap::from([
                ("name".to_string(), name.clone()),
                ("type".to_string(), driver.clone()),
            ]),
            legacy_from: None,
        }),
        Event::NetworkRemoved {
            id,
            name,
            driver,
            labels: _,
        } => Some(EventMapping {
            event_type: "network",
            action: "destroy",
            actor_id: id.clone(),
            attributes: HashMap::from([
                ("name".to_string(), name.clone()),
                ("type".to_string(), driver.clone()),
            ]),
            legacy_from: None,
        }),
        Event::VolumeCreated {
            name,
            driver,
            labels: _,
        } => Some(EventMapping {
            event_type: "volume",
            action: "create",
            actor_id: name.clone(),
            attributes: HashMap::from([("driver".to_string(), driver.clone())]),
            legacy_from: None,
        }),
        Event::VolumeRemoved {
            name,
            driver,
            labels: _,
        } => Some(EventMapping {
            event_type: "volume",
            action: "destroy",
            actor_id: name.clone(),
            attributes: HashMap::from([("driver".to_string(), driver.clone())]),
            legacy_from: None,
        }),
        Event::MachineCreated { name } => Some(EventMapping {
            event_type: "machine",
            action: "create",
            actor_id: name.clone(),
            attributes: HashMap::from([("name".to_string(), name.clone())]),
            legacy_from: None,
        }),
        Event::MachineStarted { name } => Some(EventMapping {
            event_type: "machine",
            action: "start",
            actor_id: name.clone(),
            attributes: HashMap::from([("name".to_string(), name.clone())]),
            legacy_from: None,
        }),
        Event::MachineStopped { name } => Some(EventMapping {
            event_type: "machine",
            action: "stop",
            actor_id: name.clone(),
            attributes: HashMap::from([("name".to_string(), name.clone())]),
            legacy_from: None,
        }),
        Event::VmStarted { id } => Some(EventMapping {
            event_type: "vm",
            action: "start",
            actor_id: id.clone(),
            attributes: HashMap::from([("id".to_string(), id.clone())]),
            legacy_from: None,
        }),
        Event::VmStopped { id } => Some(EventMapping {
            event_type: "vm",
            action: "stop",
            actor_id: id.clone(),
            attributes: HashMap::from([("id".to_string(), id.clone())]),
            legacy_from: None,
        }),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod events_tests {
    use super::{EventFilters, event_matches_filters, map_event, parse_event_filters};
    use arcbox_core::event::Event;
    use std::collections::HashMap;

    #[test]
    fn parse_filters_with_type_and_container() {
        let raw =
            r#"{"type":{"container":true},"container":{"abc123":true},"event":{"start":true}}"#;
        let filters = parse_event_filters(Some(raw.to_string())).unwrap();

        assert!(filters.get("type").contains(&"container".to_string()));
        assert!(filters.get("container").contains(&"abc123".to_string()));
        assert!(filters.get("event").contains(&"start".to_string()));
    }

    #[test]
    fn parse_filters_with_list_values() {
        let raw = r#"{"type":["container"],"container":["abc123"],"event":["start"]}"#;
        let filters = parse_event_filters(Some(raw.to_string())).unwrap();

        assert!(filters.get("type").contains(&"container".to_string()));
        assert!(filters.get("container").contains(&"abc123".to_string()));
        assert!(filters.get("event").contains(&"start".to_string()));
    }

    #[test]
    fn event_matches_respects_type_and_event_filters() {
        let mut filters = EventFilters::default();
        filters.add("type", "container".to_string());
        filters.add("container", "abc123".to_string());
        filters.add("event", "start".to_string());

        let attributes = HashMap::from([("name".to_string(), "abc123".to_string())]);
        assert!(event_matches_filters(
            &filters,
            "container",
            "start",
            "abc123",
            &attributes,
            "local"
        ));
        assert!(!event_matches_filters(
            &filters,
            "container",
            "stop",
            "abc123",
            &attributes,
            "local"
        ));
        assert!(!event_matches_filters(
            &filters,
            "image",
            "pull",
            "abc123",
            &attributes,
            "local"
        ));
    }

    #[test]
    fn event_filter_exec_start_uses_fuzzy_match() {
        let mut filters = EventFilters::default();
        filters.add("event", "exec_start".to_string());

        let attributes = HashMap::new();
        assert!(event_matches_filters(
            &filters,
            "container",
            "exec_start: /bin/sh -c echo hello",
            "abc123",
            &attributes,
            "local"
        ));
    }

    #[test]
    fn map_event_container_die_has_exit_code() {
        let event = Event::ContainerDied {
            id: "abc123".to_string(),
            name: "/demo".to_string(),
            image: "alpine:latest".to_string(),
            labels: HashMap::new(),
            exit_code: Some(42),
        };

        let mapping = map_event(&event).unwrap();
        assert_eq!(mapping.event_type, "container");
        assert_eq!(mapping.action, "die");
        assert_eq!(mapping.actor_id, "abc123");
        assert_eq!(mapping.attributes.get("name"), Some(&"demo".to_string()));
        assert_eq!(
            mapping.attributes.get("image"),
            Some(&"alpine:latest".to_string())
        );
        assert_eq!(mapping.attributes.get("exitCode"), Some(&"42".to_string()));
        assert_eq!(mapping.legacy_from.as_deref(), Some("alpine:latest"));
    }

    #[test]
    fn map_event_container_kill_has_signal_only() {
        let event = Event::ContainerKilled {
            id: "abc123".to_string(),
            name: "demo".to_string(),
            image: "alpine:latest".to_string(),
            labels: HashMap::new(),
            signal: "SIGKILL".to_string(),
            exit_code: Some(137),
        };

        let mapping = map_event(&event).unwrap();
        assert_eq!(mapping.event_type, "container");
        assert_eq!(mapping.action, "kill");
        assert_eq!(mapping.attributes.get("signal"), Some(&"9".to_string()));
        assert!(mapping.attributes.get("exitCode").is_none());
    }

    #[test]
    fn map_event_network_attributes_match_moby() {
        let event = Event::NetworkCreated {
            id: "net123".to_string(),
            name: "demo".to_string(),
            driver: "bridge".to_string(),
            labels: HashMap::from([("env".to_string(), "dev".to_string())]),
        };

        let mapping = map_event(&event).unwrap();
        assert_eq!(mapping.event_type, "network");
        assert_eq!(mapping.action, "create");
        assert_eq!(mapping.attributes.get("name"), Some(&"demo".to_string()));
        assert_eq!(mapping.attributes.get("type"), Some(&"bridge".to_string()));
        assert!(mapping.attributes.get("driver").is_none());
        assert!(mapping.attributes.get("env").is_none());
    }

    #[test]
    fn map_event_volume_attributes_match_moby() {
        let event = Event::VolumeCreated {
            name: "vol1".to_string(),
            driver: "local".to_string(),
            labels: HashMap::from([("env".to_string(), "dev".to_string())]),
        };

        let mapping = map_event(&event).unwrap();
        assert_eq!(mapping.event_type, "volume");
        assert_eq!(mapping.action, "create");
        assert_eq!(mapping.attributes.get("driver"), Some(&"local".to_string()));
        assert!(mapping.attributes.get("name").is_none());
        assert!(mapping.attributes.get("env").is_none());
    }
}
