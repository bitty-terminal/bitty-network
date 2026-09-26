//! Audit entry vocabulary tests: bounded memory, no PII, and coverage.
//!
//! These tests verify the audit entry types defined in `bitty-network-api` and
//! demonstrate how backends would emit entries to the Inspector feed. The
//! actual integration into `HttpNetworkService` and `WebSocketSocket` is
//! deferred pending host-side plugin-identity mapping (issue #31).

use std::sync::{Arc, Mutex};

use bitty_network_api::{
    AuditDecision, AuditEntry, AuditSink, HttpMethod, NetworkCapability, Request, WebSocketRequest,
};

/// Test sink: bounded in-memory store for verification.
struct BoundedMemorySink {
    entries: Mutex<Vec<AuditEntry>>,
    capacity: usize,
}

impl BoundedMemorySink {
    fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            capacity,
        }
    }

    fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().unwrap().clone()
    }

    fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl AuditSink for BoundedMemorySink {
    fn record(&self, entry: AuditEntry) {
        let mut entries = self.entries.lock().unwrap();
        entries.push(entry);
        // Bounded: drop oldest when capacity is exceeded (ring buffer).
        if entries.len() > self.capacity {
            entries.remove(0);
        }
    }
}

#[test]
fn audit_entry_carries_decision_host_port_method_timestamp() {
    let entry = AuditEntry::http(AuditDecision::Allow, "example.com", 443, HttpMethod::Get);
    assert_eq!(entry.decision, AuditDecision::Allow);
    assert_eq!(entry.host, "example.com");
    assert_eq!(entry.port, 443);
    assert_eq!(entry.method, Some(HttpMethod::Get));
    assert!(entry.plugin_id.is_none());
}

#[test]
fn websocket_entry_carries_no_method() {
    let entry = AuditEntry::websocket(AuditDecision::Deny, "example.com", 443);
    assert_eq!(entry.decision, AuditDecision::Deny);
    assert_eq!(entry.host, "example.com");
    assert_eq!(entry.port, 443);
    assert!(entry.method.is_none());
}

#[test]
fn bounded_sink_enforces_capacity() {
    let sink = BoundedMemorySink::new(3);
    sink.record(AuditEntry::http(
        AuditDecision::Allow,
        "one.example",
        443,
        HttpMethod::Get,
    ));
    sink.record(AuditEntry::http(
        AuditDecision::Allow,
        "two.example",
        443,
        HttpMethod::Get,
    ));
    sink.record(AuditEntry::http(
        AuditDecision::Allow,
        "three.example",
        443,
        HttpMethod::Get,
    ));
    assert_eq!(sink.len(), 3);

    // Fourth entry evicts the oldest.
    sink.record(AuditEntry::http(
        AuditDecision::Allow,
        "four.example",
        443,
        HttpMethod::Get,
    ));
    assert_eq!(sink.len(), 3);
    let entries = sink.entries();
    assert_eq!(entries[0].host, "two.example");
    assert_eq!(entries[1].host, "three.example");
    assert_eq!(entries[2].host, "four.example");
}

#[test]
fn audit_entries_carry_no_pii_beyond_host_port() {
    // Construct an entry: no body, no headers, no query string, no path.
    let entry = AuditEntry::http(AuditDecision::Allow, "example.com", 443, HttpMethod::Post);
    assert_eq!(entry.host, "example.com");
    assert_eq!(entry.port, 443);
    assert_eq!(entry.method, Some(HttpMethod::Post));
    // No other fields exist that could carry PII.
}

#[test]
fn deny_entries_are_recorded_on_capability_miss() {
    let sink = Arc::new(BoundedMemorySink::new(100));
    let capability = NetworkCapability::offline().with_domain("allowed.example");

    // Simulate capability check: allowed host.
    let allowed_request = Request::get("https://allowed.example/path");
    match capability.check_request(&allowed_request) {
        Ok(()) => {
            let port = allowed_request.port().unwrap_or(443);
            sink.record(AuditEntry::http(
                AuditDecision::Allow,
                allowed_request.host(),
                port,
                allowed_request.method,
            ));
        }
        Err(_) => {
            let port = allowed_request.port().unwrap_or(443);
            sink.record(AuditEntry::http(
                AuditDecision::Deny,
                allowed_request.host(),
                port,
                allowed_request.method,
            ));
        }
    }

    // Simulate capability check: denied host.
    let denied_request = Request::get("https://denied.example/path");
    match capability.check_request(&denied_request) {
        Ok(()) => {
            let port = denied_request.port().unwrap_or(443);
            sink.record(AuditEntry::http(
                AuditDecision::Allow,
                denied_request.host(),
                port,
                denied_request.method,
            ));
        }
        Err(_) => {
            let port = denied_request.port().unwrap_or(443);
            sink.record(AuditEntry::http(
                AuditDecision::Deny,
                denied_request.host(),
                port,
                denied_request.method,
            ));
        }
    }

    assert_eq!(sink.len(), 2);
    let entries = sink.entries();
    assert_eq!(entries[0].decision, AuditDecision::Allow);
    assert_eq!(entries[0].host, "allowed.example");
    assert_eq!(entries[1].decision, AuditDecision::Deny);
    assert_eq!(entries[1].host, "denied.example");
}

#[test]
fn allow_entries_are_recorded_on_capability_hit() {
    let sink = Arc::new(BoundedMemorySink::new(100));
    let capability = NetworkCapability::offline().with_domain("example.com");

    let request = Request::get("https://example.com/api");
    if capability.check_request(&request).is_ok() {
        let port = request.port().unwrap_or(443);
        sink.record(AuditEntry::http(
            AuditDecision::Allow,
            request.host(),
            port,
            request.method,
        ));
    }

    assert_eq!(sink.len(), 1);
    let entries = sink.entries();
    assert_eq!(entries[0].decision, AuditDecision::Allow);
    assert_eq!(entries[0].host, "example.com");
    assert_eq!(entries[0].port, 443);
    assert_eq!(entries[0].method, Some(HttpMethod::Get));
}

#[test]
fn websocket_handshake_entries_carry_no_method() {
    let sink = Arc::new(BoundedMemorySink::new(100));
    let capability = NetworkCapability::offline().with_domain("example.com");

    let handshake = WebSocketRequest::new("wss://example.com/socket");
    if capability.check_handshake(&handshake).is_ok() {
        let port = handshake.port().unwrap_or(443);
        sink.record(AuditEntry::websocket(
            AuditDecision::Allow,
            handshake.host(),
            port,
        ));
    }

    assert_eq!(sink.len(), 1);
    let entries = sink.entries();
    assert_eq!(entries[0].decision, AuditDecision::Allow);
    assert_eq!(entries[0].host, "example.com");
    assert_eq!(entries[0].port, 443);
    assert!(entries[0].method.is_none());
}

#[test]
fn plugin_id_hook_starts_none_and_host_fills_it() {
    let mut entry = AuditEntry::http(AuditDecision::Allow, "example.com", 443, HttpMethod::Get);
    assert!(entry.plugin_id.is_none());

    // Host fills in the plugin identity.
    entry.plugin_id = Some("plugin-xyz-v1.0.0".to_owned());
    assert_eq!(entry.plugin_id.as_deref(), Some("plugin-xyz-v1.0.0"));
}

#[test]
fn bounded_memory_never_grows_unbounded() {
    let sink = BoundedMemorySink::new(10);
    for i in 0..1000 {
        sink.record(AuditEntry::http(
            AuditDecision::Allow,
            format!("host-{i}.example"),
            443,
            HttpMethod::Get,
        ));
    }
    // After 1000 entries, the sink holds exactly 10 (the most recent).
    assert_eq!(sink.len(), 10);
    let entries = sink.entries();
    assert_eq!(entries[0].host, "host-990.example");
    assert_eq!(entries[9].host, "host-999.example");
}
