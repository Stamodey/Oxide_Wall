// ============================================================================
// File: nexuspulse_integration.rs
// Description: NexusPulse SMS alert integration — send security alerts via
//              the NexusPulse notification platform
// ============================================================================
//! NexusPulse Integration — sends SMS security alerts to configured phone
//! numbers when critical or high-severity events are detected.
//!
//! Uses NexusPulse's built-in "alert" template for formatted messages with
//! severity and event details. Supports idempotency keys to prevent duplicate
//! alerts for the same event.
//!
//! Configure in config.toml:
//! ```toml
//! [nexus_pulse]
//! api_url = "http://localhost:8100"
//! api_key = "your-nexuspulse-api-key"
//! alert_recipients = ["+12345678900", "+19876543210"]
//! min_severity = "critical"
//! use_template = true
//! ```

use crate::audit_chain::AuditEvent;
use crate::config::NexusPulseConfig;

/// Send an SMS alert via NexusPulse for a security event.
pub async fn send_sms_alert(event: &AuditEvent, config: &NexusPulseConfig) {
    if !meets_severity(event.threat_score, &config.min_severity) {
        return;
    }

    let severity = score_label(event.threat_score);

    for recipient in &config.alert_recipients {
        let payload = if config.use_template {
            // Use the built-in "alert" template
            serde_json::json!({
                "to": recipient,
                "template": "alert",
                "vars": {
                    "severity": severity,
                    "message": format!(
                        "{:?} from {} (score: {:.2}) — {}",
                        event.event_type, event.source_ip, event.threat_score, event.details
                    )
                },
                "priority": if event.threat_score >= 0.9 { "high" } else { "normal" },
                "idempotency_key": format!("nexus-shield-{}", event.id),
                "metadata": {
                    "source": "nexus-shield",
                    "event_id": event.id,
                    "event_type": format!("{:?}", event.event_type),
                    "source_ip": event.source_ip,
                }
            })
        } else {
            // Plain SMS body
            let body = format!(
                "[NexusShield {}] {:?} from {} — {} (score: {:.3})",
                severity, event.event_type, event.source_ip,
                truncate(&event.details, 120), event.threat_score
            );
            let mut msg = serde_json::json!({
                "to": recipient,
                "body": body,
                "priority": if event.threat_score >= 0.9 { "high" } else { "normal" },
                "idempotency_key": format!("nexus-shield-{}", event.id),
                "metadata": {
                    "source": "nexus-shield",
                    "event_id": event.id,
                }
            });
            if let Some(ref from) = config.from_number {
                msg["from"] = serde_json::Value::String(from.clone());
            }
            msg
        };

        let url = format!("{}/api/v1/sms/send", config.api_url.trim_end_matches('/'));

        let client = hyper_util::client::legacy::Client::builder(
            hyper_util::rt::TokioExecutor::new(),
        ).build_http::<axum::body::Body>();

        let body = serde_json::to_string(&payload).unwrap_or_default();

        let req = match hyper::Request::builder()
            .method("POST")
            .uri(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", config.api_key))
            .body(axum::body::Body::from(body))
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "Failed to build NexusPulse request");
                continue;
            }
        };

        match client.request(req).await {
            Ok(resp) => {
                if resp.status().is_success() {
                    tracing::info!(
                        recipient = %recipient,
                        event_type = ?event.event_type,
                        severity = %severity,
                        "SMS alert sent via NexusPulse"
                    );
                } else {
                    tracing::warn!(
                        status = %resp.status(),
                        recipient = %recipient,
                        "NexusPulse returned non-success status"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    recipient = %recipient,
                    "Failed to send SMS alert via NexusPulse"
                );
            }
        }
    }
}

/// Send alerts for an event to NexusPulse if configured.
pub async fn maybe_send_sms(event: &AuditEvent, config: &Option<NexusPulseConfig>) {
    if let Some(pulse_config) = config {
        send_sms_alert(event, pulse_config).await;
    }
}

fn meets_severity(score: f64, min: &str) -> bool {
    let threshold = match min {
        "critical" => 0.9,
        "high" => 0.7,
        "medium" => 0.5,
        "low" => 0.3,
        _ => 0.0,
    };
    score >= threshold
}

fn score_label(score: f64) -> &'static str {
    match score {
        s if s >= 0.9 => "CRITICAL",
        s if s >= 0.7 => "HIGH",
        s if s >= 0.5 => "MEDIUM",
        s if s >= 0.3 => "LOW",
        _ => "INFO",
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_chain::SecurityEventType;
    use chrono::Utc;

    fn test_event(score: f64) -> AuditEvent {
        AuditEvent {
            id: "pulse-test-001".to_string(),
            timestamp: Utc::now(),
            event_type: SecurityEventType::RequestBlocked,
            source_ip: "10.0.0.1".to_string(),
            details: "SQL injection UNION SELECT attack".to_string(),
            threat_score: score,
            previous_hash: "0".to_string(),
            hash: "abcdef".to_string(),
        }
    }

    #[test]
    fn severity_matching() {
        assert!(meets_severity(0.95, "critical"));
        assert!(!meets_severity(0.8, "critical"));
        assert!(meets_severity(0.7, "high"));
        assert!(!meets_severity(0.5, "high"));
        assert!(meets_severity(0.5, "medium"));
        assert!(meets_severity(0.0, "info"));
    }

    #[test]
    fn score_labels() {
        assert_eq!(score_label(1.0), "CRITICAL");
        assert_eq!(score_label(0.9), "CRITICAL");
        assert_eq!(score_label(0.7), "HIGH");
        assert_eq!(score_label(0.5), "MEDIUM");
        assert_eq!(score_label(0.3), "LOW");
        assert_eq!(score_label(0.1), "INFO");
    }

    #[test]
    fn truncate_works() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("this is longer", 7), "this is...");
    }

    #[tokio::test]
    async fn maybe_send_with_none_config() {
        let event = test_event(0.95);
        maybe_send_sms(&event, &None).await;
    }

    #[tokio::test]
    async fn below_threshold_skips() {
        let event = test_event(0.5); // Below "critical" threshold
        let config = NexusPulseConfig {
            api_url: "http://localhost:99999".to_string(), // Won't connect
            api_key: "test".to_string(),
            alert_recipients: vec!["+10000000000".to_string()],
            from_number: None,
            min_severity: "critical".to_string(),
            use_template: true,
        };
        // Should not attempt to send (score below threshold)
        send_sms_alert(&event, &config).await;
    }

    #[test]
    fn idempotency_key_format() {
        let event = test_event(0.9);
        let key = format!("nexus-shield-{}", event.id);
        assert_eq!(key, "nexus-shield-pulse-test-001");
    }
}