// ============================================================================
// File: siem_export.rs
// Description: SIEM integration — export audit events to Syslog, Elasticsearch,
//              Splunk HEC, and generic webhook destinations
// ============================================================================
//! SIEM Export — forwards audit chain events to external security information
//! and event management systems in real-time.
//!
//! Supported destinations:
//! - **Syslog** (RFC 5424) — UDP or TCP to any syslog collector
//! - **Elasticsearch** — Direct HTTP indexing to any ES cluster
//! - **Splunk HEC** — Splunk HTTP Event Collector
//! - **Webhook** — Generic HTTP POST to any URL (JSON payload)
//!
//! Events are formatted as structured JSON with Common Event Format (CEF)
//! compatible fields for maximum SIEM compatibility.

use crate::audit_chain::AuditEvent;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

// =============================================================================
// Configuration
// =============================================================================

/// SIEM export destination type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SiemDestination {
    /// Syslog over UDP (host:port).
    SyslogUdp { host: String, port: u16 },
    /// Syslog over TCP (host:port).
    SyslogTcp { host: String, port: u16 },
    /// Elasticsearch (base URL, index name).
    Elasticsearch { url: String, index: String, api_key: Option<String> },
    /// Splunk HTTP Event Collector.
    SplunkHec { url: String, token: String, index: Option<String>, source: Option<String> },
    /// Generic webhook (POST JSON).
    Webhook { url: String, headers: Vec<(String, String)> },
}

/// Configuration for SIEM export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    /// Whether SIEM export is enabled.
    pub enabled: bool,
    /// Export destinations (can forward to multiple SIEMs simultaneously).
    pub destinations: Vec<SiemDestination>,
    /// Minimum severity to export (events below this are not forwarded).
    /// Maps to threat_score: 0.0=all, 0.3=low+, 0.5=medium+, 0.7=high+, 0.9=critical
    pub min_threat_score: f64,
    /// Batch size for buffered sending (1 = real-time).
    pub batch_size: usize,
    /// Flush interval in milliseconds (for batched mode).
    pub flush_interval_ms: u64,
    /// Include full event details (if false, only summary fields).
    pub include_details: bool,
    /// Custom source identifier for this NexusShield instance.
    pub source_name: String,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            destinations: Vec::new(),
            min_threat_score: 0.0,
            batch_size: 1,
            flush_interval_ms: 5000,
            include_details: true,
            source_name: "nexus-shield".to_string(),
        }
    }
}

// =============================================================================
// Event Formatting
// =============================================================================

/// Structured event payload for SIEM ingestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Source application.
    pub source: String,
    /// Event category.
    pub event_type: String,
    /// Severity label (info, low, medium, high, critical).
    pub severity: String,
    /// CEF-compatible severity integer (0-10).
    pub severity_id: u8,
    /// Source IP address.
    pub source_ip: String,
    /// Threat score (0.0-1.0).
    pub threat_score: f64,
    /// Event description.
    pub description: String,
    /// Event unique ID.
    pub event_id: String,
    /// Hash chain integrity hash.
    pub chain_hash: String,
    /// Additional details (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl SiemEvent {
    /// Convert an AuditEvent to a SIEM-exportable event.
    pub fn from_audit_event(event: &AuditEvent, source_name: &str, include_details: bool) -> Self {
        let severity = threat_score_to_severity(event.threat_score);
        let severity_id = threat_score_to_cef_severity(event.threat_score);

        Self {
            timestamp: event.timestamp.to_rfc3339(),
            source: source_name.to_string(),
            event_type: format!("{:?}", event.event_type),
            severity,
            severity_id,
            source_ip: event.source_ip.clone(),
            threat_score: event.threat_score,
            description: if include_details {
                event.details.clone()
            } else {
                format!("{:?} from {}", event.event_type, event.source_ip)
            },
            event_id: event.id.clone(),
            chain_hash: event.hash.clone(),
            details: if include_details {
                Some(event.details.clone())
            } else {
                None
            },
        }
    }

    /// Format as a syslog RFC 5424 message.
    pub fn to_syslog(&self) -> String {
        // RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        let facility = 10; // security/auth
        let pri = facility * 8 + syslog_severity(self.severity_id);
        format!(
            "<{}>1 {} {} {} - - [nexus-shield@49681 eventType=\"{}\" severity=\"{}\" threatScore=\"{:.3}\" sourceIp=\"{}\" chainHash=\"{}\"] {}",
            pri,
            self.timestamp,
            gethostname(),
            self.source,
            self.event_type,
            self.severity,
            self.threat_score,
            self.source_ip,
            self.chain_hash,
            self.description,
        )
    }

    /// Format as a Splunk HEC JSON event.
    pub fn to_splunk_hec(&self, index: &Option<String>, source: &Option<String>) -> String {
        let mut hec = serde_json::json!({
            "event": self,
            "sourcetype": "nexus-shield:security",
            "host": gethostname(),
        });
        if let Some(idx) = index {
            hec["index"] = serde_json::Value::String(idx.clone());
        }
        if let Some(src) = source {
            hec["source"] = serde_json::Value::String(src.clone());
        }
        serde_json::to_string(&hec).unwrap_or_default()
    }

    /// Format as an Elasticsearch bulk index action + document.
    pub fn to_es_bulk(&self, index: &str) -> String {
        let action = serde_json::json!({"index": {"_index": index}});
        let doc = serde_json::to_string(self).unwrap_or_default();
        format!("{}\n{}\n", action, doc)
    }
}

/// Map threat score to human-readable severity.
fn threat_score_to_severity(score: f64) -> String {
    match score {
        s if s >= 0.9 => "critical".to_string(),
        s if s >= 0.7 => "high".to_string(),
        s if s >= 0.5 => "medium".to_string(),
        s if s >= 0.3 => "low".to_string(),
        _ => "info".to_string(),
    }
}

/// Map threat score to CEF severity integer (0-10).
fn threat_score_to_cef_severity(score: f64) -> u8 {
    (score * 10.0).round() as u8
}

/// Map CEF severity to syslog severity (0=emergency..7=debug).
fn syslog_severity(cef: u8) -> u8 {
    match cef {
        9..=10 => 1, // alert
        7..=8 => 2,  // critical
        5..=6 => 3,  // error
        3..=4 => 4,  // warning
        1..=2 => 5,  // notice
        _ => 6,       // informational
    }
}

/// Get the system hostname.
fn gethostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "nexus-shield-host".to_string())
        .trim()
        .to_string()
}

// =============================================================================
// SIEM Exporter
// =============================================================================

/// Runtime statistics for the SIEM exporter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemExportStats {
    pub events_exported: u64,
    pub events_failed: u64,
    pub events_filtered: u64,
    pub destinations_active: usize,
}

/// SIEM exporter that forwards audit events to configured destinations.
pub struct SiemExporter {
    config: SiemConfig,
    /// Event buffer for batched sending.
    buffer: RwLock<Vec<SiemEvent>>,
    /// Counters.
    exported: AtomicU64,
    failed: AtomicU64,
    filtered: AtomicU64,
    /// Shutdown flag.
    running: Arc<AtomicBool>,
}

impl SiemExporter {
    pub fn new(config: SiemConfig) -> Self {
        Self {
            config,
            buffer: RwLock::new(Vec::new()),
            exported: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            filtered: AtomicU64::new(0),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Process an audit event: filter, format, and export.
    pub async fn export_event(&self, event: &AuditEvent) {
        // Filter by minimum threat score
        if event.threat_score < self.config.min_threat_score {
            self.filtered.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let siem_event = SiemEvent::from_audit_event(
            event,
            &self.config.source_name,
            self.config.include_details,
        );

        if self.config.batch_size <= 1 {
            // Real-time mode: send immediately
            self.send_event(&siem_event).await;
        } else {
            // Batched mode: buffer then flush
            let mut buf = self.buffer.write();
            buf.push(siem_event);
            if buf.len() >= self.config.batch_size {
                let batch: Vec<SiemEvent> = buf.drain(..).collect();
                drop(buf);
                for ev in &batch {
                    self.send_event(ev).await;
                }
            }
        }
    }

    /// Flush any buffered events.
    pub async fn flush(&self) {
        let events: Vec<SiemEvent> = {
            let mut buf = self.buffer.write();
            buf.drain(..).collect()
        };
        for ev in &events {
            self.send_event(ev).await;
        }
    }

    /// Send a single event to all configured destinations.
    async fn send_event(&self, event: &SiemEvent) {
        for dest in &self.config.destinations {
            let success = match dest {
                SiemDestination::SyslogUdp { host, port } => {
                    self.send_syslog_udp(event, host, *port).await
                }
                SiemDestination::SyslogTcp { host, port } => {
                    self.send_syslog_tcp(event, host, *port).await
                }
                SiemDestination::Elasticsearch { url, index, api_key } => {
                    self.send_elasticsearch(event, url, index, api_key.as_deref()).await
                }
                SiemDestination::SplunkHec { url, token, index, source } => {
                    self.send_splunk_hec(event, url, token, index, source).await
                }
                SiemDestination::Webhook { url, headers } => {
                    self.send_webhook(event, url, headers).await
                }
            };

            if success {
                self.exported.fetch_add(1, Ordering::Relaxed);
            } else {
                self.failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Send event via syslog UDP.
    async fn send_syslog_udp(&self, event: &SiemEvent, host: &str, port: u16) -> bool {
        let msg = event.to_syslog();
        let addr = format!("{}:{}", host, port);
        match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket.send_to(msg.as_bytes(), &addr).await.is_ok(),
            Err(_) => false,
        }
    }

    /// Send event via syslog TCP.
    async fn send_syslog_tcp(&self, event: &SiemEvent, host: &str, port: u16) -> bool {
        let msg = format!("{}\n", event.to_syslog());
        let addr = format!("{}:{}", host, port);
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(mut stream) => {
                use tokio::io::AsyncWriteExt;
                stream.write_all(msg.as_bytes()).await.is_ok()
            }
            Err(_) => false,
        }
    }

    /// Send event to Elasticsearch.
    async fn send_elasticsearch(
        &self,
        event: &SiemEvent,
        url: &str,
        index: &str,
        api_key: Option<&str>,
    ) -> bool {
        let bulk_url = format!("{}/_bulk", url.trim_end_matches('/'));
        let body = event.to_es_bulk(index);

        let client = match reqwest_client() {
            Some(c) => c,
            None => return false,
        };

        let mut req = client
            .post(&bulk_url)
            .header("Content-Type", "application/x-ndjson")
            .body(body);

        if let Some(key) = api_key {
            req = req.header("Authorization", format!("ApiKey {}", key));
        }

        match req.send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// Send event to Splunk HEC.
    async fn send_splunk_hec(
        &self,
        event: &SiemEvent,
        url: &str,
        token: &str,
        index: &Option<String>,
        source: &Option<String>,
    ) -> bool {
        let body = event.to_splunk_hec(index, source);

        let client = match reqwest_client() {
            Some(c) => c,
            None => return false,
        };

        match client
            .post(url)
            .header("Authorization", format!("Splunk {}", token))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// Send event to a generic webhook.
    async fn send_webhook(
        &self,
        event: &SiemEvent,
        url: &str,
        headers: &[(String, String)],
    ) -> bool {
        let body = serde_json::to_string(event).unwrap_or_default();

        let client = match reqwest_client() {
            Some(c) => c,
            None => return false,
        };

        let mut req = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body);

        for (key, value) in headers {
            req = req.header(key.as_str(), value.as_str());
        }

        match req.send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// Get export statistics.
    pub fn stats(&self) -> SiemExportStats {
        SiemExportStats {
            events_exported: self.exported.load(Ordering::Relaxed),
            events_failed: self.failed.load(Ordering::Relaxed),
            events_filtered: self.filtered.load(Ordering::Relaxed),
            destinations_active: self.config.destinations.len(),
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.destinations.is_empty()
    }
}

/// Create an HTTP client. Returns None if reqwest is unavailable.
/// Uses a minimal hyper-based client to avoid adding reqwest dependency.
fn reqwest_client() -> Option<SimpleHttpClient> {
    Some(SimpleHttpClient)
}

/// Minimal async HTTP client using hyper (already a dependency).
pub struct SimpleHttpClient;

impl SimpleHttpClient {
    pub fn post(&self, url: &str) -> SimpleHttpRequestBuilder {
        SimpleHttpRequestBuilder {
            url: url.to_string(),
            method: "POST".to_string(),
            headers: Vec::new(),
            body: None,
        }
    }
}

pub struct SimpleHttpRequestBuilder {
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

impl SimpleHttpRequestBuilder {
    pub fn header(mut self, key: &str, value: impl Into<String>) -> Self {
        self.headers.push((key.to_string(), value.into()));
        self
    }

    pub fn body(mut self, body: String) -> Self {
        self.body = Some(body);
        self
    }

    pub async fn send(self) -> Result<SimpleHttpResponse, String> {
        use hyper::body::Bytes;
        use hyper_util::client::legacy::Client;
        use hyper_util::rt::TokioExecutor;

        let uri: hyper::Uri = self
            .url
            .parse()
            .map_err(|e| format!("invalid URI: {}", e))?;

        let client = Client::builder(TokioExecutor::new()).build_http::<axum::body::Body>();

        let body_bytes = self.body.unwrap_or_default();
        let mut builder = hyper::Request::builder().method(self.method.as_str()).uri(uri);

        for (k, v) in &self.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }

        let req = builder
            .body(axum::body::Body::from(Bytes::from(body_bytes)))
            .map_err(|e| format!("request build error: {}", e))?;

        match client.request(req).await {
            Ok(resp) => Ok(SimpleHttpResponse {
                status: resp.status().as_u16(),
            }),
            Err(e) => Err(format!("request failed: {}", e)),
        }
    }
}

pub struct SimpleHttpResponse {
    status: u16,
}

impl SimpleHttpResponse {
    pub fn status(&self) -> SimpleStatus {
        SimpleStatus(self.status)
    }
}

pub struct SimpleStatus(u16);

impl SimpleStatus {
    pub fn is_success(&self) -> bool {
        self.0 >= 200 && self.0 < 300
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_chain::{AuditEvent, SecurityEventType};
    use chrono::Utc;

    fn test_event() -> AuditEvent {
        AuditEvent {
            id: "test-001".to_string(),
            timestamp: Utc::now(),
            event_type: SecurityEventType::SqlInjectionAttempt,
            source_ip: "192.168.1.100".to_string(),
            details: "UNION SELECT attack detected".to_string(),
            threat_score: 0.85,
            previous_hash: "0000".to_string(),
            hash: "abcd1234".to_string(),
        }
    }

    #[test]
    fn siem_event_from_audit() {
        let event = test_event();
        let siem = SiemEvent::from_audit_event(&event, "test-shield", true);
        assert_eq!(siem.source, "test-shield");
        assert_eq!(siem.severity, "high");
        assert_eq!(siem.severity_id, 9); // 0.85 * 10 rounded
        assert_eq!(siem.source_ip, "192.168.1.100");
        assert!(siem.description.contains("UNION"));
    }

    #[test]
    fn siem_event_without_details() {
        let event = test_event();
        let siem = SiemEvent::from_audit_event(&event, "test", false);
        assert!(siem.details.is_none());
        assert!(siem.description.contains("SqlInjectionAttempt"));
    }

    #[test]
    fn syslog_format() {
        let event = test_event();
        let siem = SiemEvent::from_audit_event(&event, "nexus-shield", true);
        let syslog = siem.to_syslog();
        assert!(syslog.starts_with('<'));
        assert!(syslog.contains("nexus-shield"));
        assert!(syslog.contains("eventType="));
        assert!(syslog.contains("threatScore="));
        assert!(syslog.contains("sourceIp="));
    }

    #[test]
    fn splunk_hec_format() {
        let event = test_event();
        let siem = SiemEvent::from_audit_event(&event, "nexus-shield", true);
        let hec = siem.to_splunk_hec(&Some("security".to_string()), &None);
        let parsed: serde_json::Value = serde_json::from_str(&hec).unwrap();
        assert!(parsed["event"].is_object());
        assert_eq!(parsed["sourcetype"], "nexus-shield:security");
        assert_eq!(parsed["index"], "security");
    }

    #[test]
    fn splunk_hec_no_index() {
        let event = test_event();
        let siem = SiemEvent::from_audit_event(&event, "nexus-shield", true);
        let hec = siem.to_splunk_hec(&None, &None);
        let parsed: serde_json::Value = serde_json::from_str(&hec).unwrap();
        assert!(parsed.get("index").is_none());
    }

    #[test]
    fn elasticsearch_bulk_format() {
        let event = test_event();
        let siem = SiemEvent::from_audit_event(&event, "nexus-shield", true);
        let bulk = siem.to_es_bulk("nexus-shield-events");
        let lines: Vec<&str> = bulk.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);
        let action: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(action["index"]["_index"], "nexus-shield-events");
        let doc: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert!(doc["event_type"].is_string());
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(threat_score_to_severity(0.0), "info");
        assert_eq!(threat_score_to_severity(0.15), "info");
        assert_eq!(threat_score_to_severity(0.3), "low");
        assert_eq!(threat_score_to_severity(0.5), "medium");
        assert_eq!(threat_score_to_severity(0.7), "high");
        assert_eq!(threat_score_to_severity(0.9), "critical");
        assert_eq!(threat_score_to_severity(1.0), "critical");
    }

    #[test]
    fn cef_severity_mapping() {
        assert_eq!(threat_score_to_cef_severity(0.0), 0);
        assert_eq!(threat_score_to_cef_severity(0.5), 5);
        assert_eq!(threat_score_to_cef_severity(1.0), 10);
    }

    #[test]
    fn config_defaults() {
        let config = SiemConfig::default();
        assert!(!config.enabled);
        assert!(config.destinations.is_empty());
        assert_eq!(config.batch_size, 1);
        assert_eq!(config.source_name, "nexus-shield");
    }

    #[test]
    fn exporter_stats_initial() {
        let config = SiemConfig::default();
        let exporter = SiemExporter::new(config);
        let stats = exporter.stats();
        assert_eq!(stats.events_exported, 0);
        assert_eq!(stats.events_failed, 0);
        assert_eq!(stats.events_filtered, 0);
        assert_eq!(stats.destinations_active, 0);
    }

    #[test]
    fn exporter_not_enabled_without_destinations() {
        let config = SiemConfig::default();
        let exporter = SiemExporter::new(config);
        assert!(!exporter.is_enabled());
    }

    #[test]
    fn exporter_enabled_with_destination() {
        let mut config = SiemConfig::default();
        config.enabled = true;
        config.destinations.push(SiemDestination::SyslogUdp {
            host: "127.0.0.1".to_string(),
            port: 514,
        });
        let exporter = SiemExporter::new(config);
        assert!(exporter.is_enabled());
    }

    #[tokio::test]
    async fn filter_low_score_events() {
        let mut config = SiemConfig::default();
        config.min_threat_score = 0.5;
        let exporter = SiemExporter::new(config);

        let mut event = test_event();
        event.threat_score = 0.1; // Below threshold
        exporter.export_event(&event).await;

        assert_eq!(exporter.stats().events_filtered, 1);
        assert_eq!(exporter.stats().events_exported, 0);
    }

    #[test]
    fn syslog_severity_mapping() {
        assert_eq!(syslog_severity(10), 1); // critical -> alert
        assert_eq!(syslog_severity(7), 2);  // high -> critical
        assert_eq!(syslog_severity(5), 3);  // medium -> error
        assert_eq!(syslog_severity(3), 4);  // low -> warning
        assert_eq!(syslog_severity(1), 5);  // info -> notice
        assert_eq!(syslog_severity(0), 6);  // none -> info
    }

    #[test]
    fn serialization_roundtrip() {
        let event = test_event();
        let siem = SiemEvent::from_audit_event(&event, "test", true);
        let json = serde_json::to_string(&siem).unwrap();
        let parsed: SiemEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.source, "test");
        assert_eq!(parsed.event_id, "test-001");
    }
}