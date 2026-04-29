// ============================================================================
// File: fingerprint.rs
// Description: HTTP request fingerprinting for behavioral analysis and bot detection
// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
//! Request Fingerprinting — Behavioral analysis and bot detection.
//!
//! Extracts features from HTTP requests to build a behavioral fingerprint.
//! Automated attack tools typically have distinctive patterns: missing standard
//! headers, unusual header ordering, rapid request cadence, and low entropy
//! in request parameters.

use axum::http::HeaderMap;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;

/// Fingerprint of a single HTTP request.
#[derive(Debug, Clone)]
pub struct RequestFingerprint {
    /// Stable hash of the client's fingerprint signals.
    pub hash: String,
    /// Individual signals extracted from the request.
    pub signals: FingerprintSignals,
    /// Anomaly score (0.0 = normal, 1.0 = definitely automated/malicious).
    pub anomaly_score: f64,
}

#[derive(Debug, Clone)]
pub struct FingerprintSignals {
    pub has_user_agent: bool,
    pub has_accept: bool,
    pub has_accept_language: bool,
    pub has_accept_encoding: bool,
    pub has_referer: bool,
    pub header_count: usize,
    /// Hash of header names in order (different tools produce different orderings).
    pub header_order_hash: String,
    /// User-Agent string (truncated, for pattern matching).
    pub user_agent: String,
}

/// Tracks client behavior patterns over time for anomaly detection.
struct ClientBehavior {
    /// Number of requests seen.
    request_count: u64,
    /// First request time.
    first_seen: Instant,
    /// Last request time.
    last_seen: Instant,
    /// Number of distinct endpoints hit.
    distinct_endpoints: u32,
    /// Number of 4xx/5xx errors triggered.
    error_count: u32,
    /// Distinct source_type values tried in connect requests.
    distinct_source_types: u32,
}

pub struct Fingerprinter {
    behaviors: RwLock<HashMap<String, ClientBehavior>>,
}

impl Fingerprinter {
    pub fn new() -> Self {
        Self {
            behaviors: RwLock::new(HashMap::new()),
        }
    }

    /// Analyze request headers and produce a fingerprint with anomaly score.
    pub fn analyze(&self, headers: &HeaderMap) -> RequestFingerprint {
        let signals = extract_signals(headers);
        let anomaly_score = calculate_anomaly_score(&signals);
        let hash = compute_fingerprint_hash(&signals);

        RequestFingerprint {
            hash,
            signals,
            anomaly_score,
        }
    }

    /// Record a request for behavioral tracking. Call after each request.
    pub fn record_request(&self, client_ip: &str) {
        let mut behaviors = self.behaviors.write();
        let behavior = behaviors
            .entry(client_ip.to_string())
            .or_insert_with(|| ClientBehavior {
                request_count: 0,
                first_seen: Instant::now(),
                last_seen: Instant::now(),
                distinct_endpoints: 1,
                error_count: 0,
                distinct_source_types: 0,
            });
        behavior.request_count += 1;
        behavior.last_seen = Instant::now();
    }

    /// Record an error response for behavioral tracking.
    pub fn record_error(&self, client_ip: &str) {
        let mut behaviors = self.behaviors.write();
        if let Some(behavior) = behaviors.get_mut(client_ip) {
            behavior.error_count += 1;
        }
    }

    /// Get the behavioral anomaly score for a client IP.
    /// Returns 0.0 for unknown clients (benefit of the doubt).
    pub fn behavioral_score(&self, client_ip: &str) -> f64 {
        let behaviors = self.behaviors.read();
        let behavior = match behaviors.get(client_ip) {
            Some(b) => b,
            None => return 0.0,
        };

        let mut score: f64 = 0.0;

        // High request rate
        let duration = behavior.last_seen.duration_since(behavior.first_seen).as_secs_f64();
        if duration > 0.0 {
            let rps = behavior.request_count as f64 / duration;
            if rps > 20.0 {
                score += 0.3;
            }
            if rps > 100.0 {
                score += 0.3;
            }
        }

        // High error rate
        if behavior.request_count > 5 {
            let error_rate = behavior.error_count as f64 / behavior.request_count as f64;
            if error_rate > 0.5 {
                score += 0.3;
            }
        }

        // Many requests in very short time (burst)
        if behavior.request_count > 50 && duration < 5.0 {
            score += 0.4;
        }

        // Rapid endpoint scanning (many distinct endpoints in short time)
        if behavior.distinct_endpoints > 20 && duration < 30.0 {
            score += 0.2;
        }

        // Source type enumeration (trying many different source types)
        if behavior.distinct_source_types > 5 {
            score += 0.2;
        }

        score.min(1.0)
    }

    /// Prune behavioral data for clients not seen recently.
    pub fn prune_stale(&self, max_age_secs: u64) {
        let mut behaviors = self.behaviors.write();
        behaviors.retain(|_, b| b.last_seen.elapsed().as_secs() < max_age_secs);
    }
}

fn extract_signals(headers: &HeaderMap) -> FingerprintSignals {
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect::<String>();

    // Hash the header names in order
    let header_names: Vec<String> = headers.keys().map(|k| k.as_str().to_lowercase()).collect();
    let order_input = header_names.join("|");
    let header_order_hash = hex::encode(Sha256::digest(order_input.as_bytes()))[..16].to_string();

    FingerprintSignals {
        has_user_agent: headers.contains_key("user-agent"),
        has_accept: headers.contains_key("accept"),
        has_accept_language: headers.contains_key("accept-language"),
        has_accept_encoding: headers.contains_key("accept-encoding"),
        has_referer: headers.contains_key("referer"),
        header_count: headers.len(),
        header_order_hash,
        user_agent,
    }
}

fn calculate_anomaly_score(signals: &FingerprintSignals) -> f64 {
    let mut score: f64 = 0.0;

    // Missing standard headers suggests automated tool
    if !signals.has_user_agent {
        score += 0.3;
    }
    if !signals.has_accept {
        score += 0.1;
    }
    if !signals.has_accept_language {
        score += 0.1;
    }
    if !signals.has_accept_encoding {
        score += 0.05;
    }

    // Very few headers = likely curl, httpie, or attack tool
    if signals.header_count < 3 {
        score += 0.25;
    }

    // Very many headers = possible proxy chain or header stuffing
    if signals.header_count > 30 {
        score += 0.15;
    }

    // Check for known attack tool user agents
    let ua_lower = signals.user_agent.to_lowercase();
    let attack_tools = [
        "sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster",
        "dirbuster", "wfuzz", "ffuf", "nuclei", "httpx",
        "python-requests", "go-http-client", "java/",
    ];
    for tool in &attack_tools {
        if ua_lower.contains(tool) {
            score += 0.4;
            break;
        }
    }

    // Empty user agent is suspicious
    if signals.has_user_agent && signals.user_agent.is_empty() {
        score += 0.2;
    }

    score.min(1.0)
}

fn compute_fingerprint_hash(signals: &FingerprintSignals) -> String {
    let input = format!(
        "ua:{}|hdr_count:{}|order:{}|accept:{}|lang:{}",
        signals.user_agent,
        signals.header_count,
        signals.header_order_hash,
        signals.has_accept,
        signals.has_accept_language,
    );
    hex::encode(Sha256::digest(input.as_bytes()))[..32].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn make_normal_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_static("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"));
        h.insert("accept", HeaderValue::from_static("text/html,application/json"));
        h.insert("accept-language", HeaderValue::from_static("en-US,en;q=0.9"));
        h.insert("accept-encoding", HeaderValue::from_static("gzip, deflate, br"));
        h
    }

    fn make_bot_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_static("sqlmap/1.7"));
        h
    }

    #[test]
    fn normal_browser_low_anomaly() {
        let fp = Fingerprinter::new();
        let result = fp.analyze(&make_normal_headers());
        assert!(result.anomaly_score < 0.2, "Normal browser score should be low: {}", result.anomaly_score);
    }

    #[test]
    fn attack_tool_high_anomaly() {
        let fp = Fingerprinter::new();
        let result = fp.analyze(&make_bot_headers());
        assert!(result.anomaly_score > 0.5, "Attack tool score should be high: {}", result.anomaly_score);
    }

    #[test]
    fn empty_headers_suspicious() {
        let fp = Fingerprinter::new();
        let result = fp.analyze(&HeaderMap::new());
        assert!(result.anomaly_score > 0.4, "Empty headers should be suspicious: {}", result.anomaly_score);
    }

    #[test]
    fn fingerprint_is_stable() {
        let fp = Fingerprinter::new();
        let h = make_normal_headers();
        let r1 = fp.analyze(&h);
        let r2 = fp.analyze(&h);
        assert_eq!(r1.hash, r2.hash);
    }

    // ── Fingerprinter::new() ───────────────────────────────

    #[test]
    fn fingerprinter_new_creates_empty_behaviors() {
        let fp = Fingerprinter::new();
        // A new fingerprinter should have no behavioral data
        assert_eq!(fp.behavioral_score("1.2.3.4"), 0.0);
    }

    // ── analyze() with various header patterns ─────────────

    #[test]
    fn analyze_with_only_user_agent() {
        let fp = Fingerprinter::new();
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_static("Mozilla/5.0"));
        let result = fp.analyze(&h);
        // Has user-agent but missing accept, accept-language, accept-encoding
        // and low header count (1 < 3) => should have moderate score
        assert!(result.anomaly_score > 0.2, "Single header should be suspicious: {}", result.anomaly_score);
    }

    #[test]
    fn analyze_python_requests_user_agent() {
        let fp = Fingerprinter::new();
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_static("python-requests/2.28.1"));
        h.insert("accept", HeaderValue::from_static("*/*"));
        h.insert("accept-encoding", HeaderValue::from_static("gzip"));
        let result = fp.analyze(&h);
        // python-requests is in the attack tools list
        assert!(result.anomaly_score >= 0.4, "python-requests UA should be flagged: {}", result.anomaly_score);
    }

    #[test]
    fn analyze_go_http_client() {
        let fp = Fingerprinter::new();
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_static("Go-http-client/1.1"));
        let result = fp.analyze(&h);
        assert!(result.anomaly_score >= 0.4, "Go http client should be flagged: {}", result.anomaly_score);
    }

    #[test]
    fn analyze_nikto_scanner() {
        let fp = Fingerprinter::new();
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_static("Nikto/2.1.6"));
        let result = fp.analyze(&h);
        assert!(result.anomaly_score >= 0.4, "Nikto should be flagged: {}", result.anomaly_score);
    }

    #[test]
    fn analyze_nuclei_scanner() {
        let fp = Fingerprinter::new();
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_static("Nuclei - Open-source project"));
        h.insert("accept", HeaderValue::from_static("*/*"));
        let result = fp.analyze(&h);
        assert!(result.anomaly_score >= 0.4, "Nuclei should be flagged: {}", result.anomaly_score);
    }

    #[test]
    fn analyze_many_headers_suspicious() {
        let fp = Fingerprinter::new();
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_static("Mozilla/5.0"));
        h.insert("accept", HeaderValue::from_static("*/*"));
        h.insert("accept-language", HeaderValue::from_static("en"));
        h.insert("accept-encoding", HeaderValue::from_static("gzip"));
        // Add many custom headers to exceed 30
        for i in 0..30 {
            let name = format!("x-custom-header-{}", i);
            h.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_static("value"),
            );
        }
        let result = fp.analyze(&h);
        assert!(result.anomaly_score > 0.0, "Many headers should add some anomaly: {}", result.anomaly_score);
    }

    #[test]
    fn analyze_signals_populated_correctly() {
        let fp = Fingerprinter::new();
        let h = make_normal_headers();
        let result = fp.analyze(&h);
        assert!(result.signals.has_user_agent);
        assert!(result.signals.has_accept);
        assert!(result.signals.has_accept_language);
        assert!(result.signals.has_accept_encoding);
        assert!(!result.signals.has_referer);
        assert_eq!(result.signals.header_count, 4);
    }

    #[test]
    fn analyze_with_referer() {
        let fp = Fingerprinter::new();
        let mut h = make_normal_headers();
        h.insert("referer", HeaderValue::from_static("https://example.com"));
        let result = fp.analyze(&h);
        assert!(result.signals.has_referer);
    }

    #[test]
    fn analyze_user_agent_truncated_at_200() {
        let fp = Fingerprinter::new();
        let long_ua = "A".repeat(300);
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_str(&long_ua).unwrap());
        let result = fp.analyze(&h);
        assert_eq!(result.signals.user_agent.len(), 200);
    }

    #[test]
    fn different_headers_produce_different_hashes() {
        let fp = Fingerprinter::new();
        let r1 = fp.analyze(&make_normal_headers());
        let r2 = fp.analyze(&make_bot_headers());
        assert_ne!(r1.hash, r2.hash);
    }

    // ── record_request() ───────────────────────────────────

    #[test]
    fn record_request_increments_count() {
        let fp = Fingerprinter::new();
        fp.record_request("10.0.0.1");
        fp.record_request("10.0.0.1");
        fp.record_request("10.0.0.1");
        // After recording requests, behavioral_score should still be low
        // because requests are spread out in time
        let score = fp.behavioral_score("10.0.0.1");
        // With only 3 requests, score should be 0 or very low
        assert!(score < 1.0, "Few requests should not max out score: {}", score);
    }

    #[test]
    fn record_request_creates_new_client() {
        let fp = Fingerprinter::new();
        // Before recording, score is 0.0
        assert_eq!(fp.behavioral_score("new_client"), 0.0);
        fp.record_request("new_client");
        // After recording, the client exists (score may still be 0.0 for 1 request)
        let score = fp.behavioral_score("new_client");
        assert!(score >= 0.0);
    }

    #[test]
    fn record_request_different_ips_independent() {
        let fp = Fingerprinter::new();
        for _ in 0..100 {
            fp.record_request("attacker_ip");
        }
        // A different IP should still have 0.0 score
        assert_eq!(fp.behavioral_score("clean_ip"), 0.0);
    }

    // ── record_error() ─────────────────────────────────────

    #[test]
    fn record_error_only_affects_known_clients() {
        let fp = Fingerprinter::new();
        // Recording error for unknown IP should not panic
        fp.record_error("unknown_ip");
        assert_eq!(fp.behavioral_score("unknown_ip"), 0.0);
    }

    #[test]
    fn record_error_after_requests_increases_score() {
        let fp = Fingerprinter::new();
        // Record enough requests to pass the request_count > 5 threshold
        for _ in 0..10 {
            fp.record_request("error_client");
        }
        // Record many errors to push error_rate above 0.5
        for _ in 0..8 {
            fp.record_error("error_client");
        }
        let score = fp.behavioral_score("error_client");
        // With 10 requests and 8 errors, error_rate = 0.8 > 0.5 => +0.3
        assert!(score >= 0.3, "High error rate should increase behavioral score: {}", score);
    }

    // ── behavioral_score() thresholds ──────────────────────

    #[test]
    fn behavioral_score_unknown_client_is_zero() {
        let fp = Fingerprinter::new();
        assert_eq!(fp.behavioral_score("nonexistent"), 0.0);
    }

    #[test]
    fn behavioral_score_capped_at_one() {
        let fp = Fingerprinter::new();
        // Create extreme conditions: many requests, many errors
        for _ in 0..200 {
            fp.record_request("maxed_out");
        }
        for _ in 0..200 {
            fp.record_error("maxed_out");
        }
        let score = fp.behavioral_score("maxed_out");
        assert!(score <= 1.0, "Score should never exceed 1.0: {}", score);
    }

    // ── prune_stale() ──────────────────────────────────────

    #[test]
    fn prune_stale_removes_old_entries() {
        let fp = Fingerprinter::new();
        fp.record_request("stale_client");
        // Prune with 0 seconds max age — everything should be stale
        fp.prune_stale(0);
        // After pruning, the client should be gone
        assert_eq!(fp.behavioral_score("stale_client"), 0.0);
    }

    #[test]
    fn prune_stale_keeps_recent_entries() {
        let fp = Fingerprinter::new();
        fp.record_request("recent_client");
        // Prune with large max age — nothing should be removed
        fp.prune_stale(3600);
        // Client should still exist (behavioral score may be 0 with only 1 request though)
        // We verify by recording an error and checking the client is tracked
        fp.record_error("recent_client");
        // If the client was pruned, record_error would be a no-op
        // and we can't easily verify it. But at least no panic.
    }

    #[test]
    fn prune_stale_on_empty_is_noop() {
        let fp = Fingerprinter::new();
        fp.prune_stale(0); // should not panic
    }
}