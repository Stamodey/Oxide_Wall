// ============================================================================
// File: metrics.rs
// Description: Prometheus-compatible /metrics endpoint
// ============================================================================
//! Metrics — exposes NexusShield counters in Prometheus text exposition format
//! at the `/metrics` endpoint.
//!
//! ```text
//! # HELP nexus_shield_requests_blocked_total Total requests blocked
//! # TYPE nexus_shield_requests_blocked_total counter
//! nexus_shield_requests_blocked_total 42
//! ```

use crate::audit_chain::{AuditChain, SecurityEventType};
use std::sync::Arc;

/// Generate Prometheus text exposition format from the audit chain.
pub fn render_metrics(audit: &Arc<AuditChain>, uptime_secs: u64) -> String {
    let now = chrono::Utc::now();
    let last_hour = now - chrono::Duration::hours(1);
    let last_5min = now - chrono::Duration::minutes(5);

    let total_events = audit.len() as u64;
    let blocked_hour = audit.count_since(&SecurityEventType::RequestBlocked, last_hour) as u64;
    let blocked_5min = audit.count_since(&SecurityEventType::RequestBlocked, last_5min) as u64;
    let rate_limited_hour = audit.count_since(&SecurityEventType::RateLimitHit, last_hour) as u64;
    let sql_injection_hour = audit.count_since(&SecurityEventType::SqlInjectionAttempt, last_hour) as u64;
    let ssrf_hour = audit.count_since(&SecurityEventType::SsrfAttempt, last_hour) as u64;
    let malware_hour = audit.count_since(&SecurityEventType::MalwareDetected, last_hour) as u64;
    let chain_valid = if audit.verify_chain().valid { 1 } else { 0 };

    format!(
        r#"# HELP nexus_shield_audit_events_total Total audit chain events
# TYPE nexus_shield_audit_events_total counter
nexus_shield_audit_events_total {total_events}
# HELP nexus_shield_requests_blocked_total Requests blocked (last hour)
# TYPE nexus_shield_requests_blocked_total gauge
nexus_shield_requests_blocked_total {blocked_hour}
# HELP nexus_shield_requests_blocked_5min Requests blocked (last 5 minutes)
# TYPE nexus_shield_requests_blocked_5min gauge
nexus_shield_requests_blocked_5min {blocked_5min}
# HELP nexus_shield_rate_limited_total Requests rate limited (last hour)
# TYPE nexus_shield_rate_limited_total gauge
nexus_shield_rate_limited_total {rate_limited_hour}
# HELP nexus_shield_sql_injection_total SQL injection attempts (last hour)
# TYPE nexus_shield_sql_injection_total gauge
nexus_shield_sql_injection_total {sql_injection_hour}
# HELP nexus_shield_ssrf_total SSRF attempts (last hour)
# TYPE nexus_shield_ssrf_total gauge
nexus_shield_ssrf_total {ssrf_hour}
# HELP nexus_shield_malware_detected_total Malware detections (last hour)
# TYPE nexus_shield_malware_detected_total gauge
nexus_shield_malware_detected_total {malware_hour}
# HELP nexus_shield_chain_valid Audit chain integrity (1=valid, 0=tampered)
# TYPE nexus_shield_chain_valid gauge
nexus_shield_chain_valid {chain_valid}
# HELP nexus_shield_uptime_seconds Shield uptime in seconds
# TYPE nexus_shield_uptime_seconds counter
nexus_shield_uptime_seconds {uptime_secs}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_chain::AuditChain;

    #[test]
    fn empty_metrics() {
        let audit = Arc::new(AuditChain::new());
        let output = render_metrics(&audit, 60);
        assert!(output.contains("nexus_shield_audit_events_total 0"));
        assert!(output.contains("nexus_shield_chain_valid 1"));
        assert!(output.contains("nexus_shield_uptime_seconds 60"));
    }

    #[test]
    fn metrics_with_events() {
        let audit = Arc::new(AuditChain::new());
        audit.record(SecurityEventType::RequestBlocked, "1.2.3.4", "test", 0.8);
        audit.record(SecurityEventType::SqlInjectionAttempt, "1.2.3.4", "union", 0.9);
        let output = render_metrics(&audit, 120);
        assert!(output.contains("nexus_shield_audit_events_total 2"));
        assert!(output.contains("nexus_shield_requests_blocked_5min 1"));
    }

    #[test]
    fn metrics_format_valid() {
        let audit = Arc::new(AuditChain::new());
        let output = render_metrics(&audit, 0);
        // Every non-comment line should be "metric_name value"
        for line in output.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(parts.len(), 2, "Invalid metric line: {}", line);
            assert!(parts[1].parse::<u64>().is_ok(), "Non-numeric value: {}", line);
        }
    }
}