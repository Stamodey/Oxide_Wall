// ============================================================================
// File: ferrum_integration.rs
// Description: Ferrum-Mail integration — send security alert emails via
//              the Ferrum email platform
// ============================================================================
//! Ferrum-Mail Integration — sends formatted HTML security alert emails
//! when critical/high severity events are detected.
//!
//! Integrates with the Ferrum-Mail platform via its HTTP API. Requires
//! `ferrum_mail` configuration in config.toml:
//!
//! ```toml
//! [ferrum_mail]
//! api_url = "http://localhost:3030"
//! api_key = "fm-key-123"
//! from_address = "shield@company.com"
//! alert_recipients = ["admin@company.com"]
//! min_severity = "high"
//! ```

use crate::audit_chain::AuditEvent;
use crate::config::FerrumMailConfig;

/// Send a security alert email via Ferrum-Mail.
pub async fn send_alert_email(event: &AuditEvent, config: &FerrumMailConfig) {
    if !meets_severity(event.threat_score, &config.min_severity) {
        return;
    }

    let severity = score_label(event.threat_score);
    let subject = format!("[NexusShield] {} Alert — {:?}", severity, event.event_type);
    let html_body = format_alert_html(event, severity);

    let payload = serde_json::json!({
        "from": config.from_address,
        "to": config.alert_recipients,
        "subject": subject,
        "html": html_body,
        "text": format!(
            "NexusShield {} Alert\n\nEvent: {:?}\nSource: {}\nScore: {:.3}\nDetails: {}\nTime: {}\nEvent ID: {}",
            severity, event.event_type, event.source_ip, event.threat_score,
            event.details, event.timestamp.to_rfc3339(), event.id
        ),
    });

    let url = format!("{}/api/v1/send", config.api_url.trim_end_matches('/'));

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
            tracing::error!(error = %e, "Failed to build Ferrum-Mail request");
            return;
        }
    };

    match client.request(req).await {
        Ok(resp) => {
            if resp.status().is_success() {
                tracing::info!(
                    event_type = ?event.event_type,
                    recipients = ?config.alert_recipients,
                    "Alert email sent via Ferrum-Mail"
                );
            } else {
                tracing::warn!(
                    status = %resp.status(),
                    "Ferrum-Mail returned non-success status"
                );
            }
        }
        Err(e) => {
            tracing::error!(error = %e, url = %url, "Failed to send alert via Ferrum-Mail");
        }
    }
}

/// Send alerts for an event to Ferrum-Mail if configured.
pub async fn maybe_send_alert(event: &AuditEvent, config: &Option<FerrumMailConfig>) {
    if let Some(fm_config) = config {
        send_alert_email(event, fm_config).await;
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

fn format_alert_html(event: &AuditEvent, severity: &str) -> String {
    let color = match severity {
        "CRITICAL" => "#ef4444",
        "HIGH" => "#f97316",
        "MEDIUM" => "#f59e0b",
        _ => "#10b981",
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: -apple-system, system-ui, sans-serif; background: #faf9f6; padding: 24px;">
<div style="max-width: 600px; margin: 0 auto; background: #fff; border-radius: 12px; border: 1px solid #e5e7eb; overflow: hidden;">
  <div style="background: {color}; padding: 16px 24px;">
    <h1 style="color: #fff; margin: 0; font-size: 20px;">NexusShield — {severity} Alert</h1>
  </div>
  <div style="padding: 24px;">
    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
      <tr><td style="padding: 8px 0; color: #6b7280; width: 120px;">Event Type</td><td style="padding: 8px 0; font-weight: 600;">{event_type:?}</td></tr>
      <tr><td style="padding: 8px 0; color: #6b7280;">Source IP</td><td style="padding: 8px 0; font-family: monospace;">{source_ip}</td></tr>
      <tr><td style="padding: 8px 0; color: #6b7280;">Threat Score</td><td style="padding: 8px 0; font-weight: 600; color: {color};">{score:.3}</td></tr>
      <tr><td style="padding: 8px 0; color: #6b7280;">Timestamp</td><td style="padding: 8px 0;">{timestamp}</td></tr>
      <tr><td style="padding: 8px 0; color: #6b7280;">Event ID</td><td style="padding: 8px 0; font-family: monospace; font-size: 12px;">{event_id}</td></tr>
    </table>
    <div style="margin-top: 16px; padding: 12px; background: #f3f4f6; border-radius: 8px; font-size: 13px; font-family: monospace; word-break: break-all;">
      {details}
    </div>
    <div style="margin-top: 16px; padding: 12px; background: #f0fdfa; border-radius: 8px; border: 1px solid #99f6e4; font-size: 12px; color: #0d9488;">
      Chain Hash: {chain_hash}
    </div>
  </div>
  <div style="padding: 12px 24px; background: #f9fafb; border-top: 1px solid #e5e7eb; font-size: 11px; color: #9ca3af; text-align: center;">
    NexusShield Adaptive Security Gateway — AutomataNexus Engineering
  </div>
</div>
</body>
</html>"#,
        color = color,
        severity = severity,
        event_type = event.event_type,
        source_ip = html_escape(&event.source_ip),
        score = event.threat_score,
        timestamp = event.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        event_id = html_escape(&event.id),
        details = html_escape(&event.details),
        chain_hash = html_escape(&event.hash),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_chain::SecurityEventType;
    use chrono::Utc;

    fn test_event(score: f64) -> AuditEvent {
        AuditEvent {
            id: "test-001".to_string(),
            timestamp: Utc::now(),
            event_type: SecurityEventType::RequestBlocked,
            source_ip: "10.0.0.1".to_string(),
            details: "test detection".to_string(),
            threat_score: score,
            previous_hash: "0".to_string(),
            hash: "abcdef123456".to_string(),
        }
    }

    #[test]
    fn severity_matching() {
        assert!(meets_severity(0.95, "critical"));
        assert!(!meets_severity(0.8, "critical"));
        assert!(meets_severity(0.7, "high"));
        assert!(meets_severity(0.0, "info"));
    }

    #[test]
    fn html_alert_format() {
        let event = test_event(0.9);
        let html = format_alert_html(&event, "CRITICAL");
        assert!(html.contains("NexusShield"));
        assert!(html.contains("CRITICAL"));
        assert!(html.contains("10.0.0.1"));
        assert!(html.contains("abcdef123456"));
    }

    #[test]
    fn html_escapes_xss() {
        let mut event = test_event(0.9);
        event.details = "<script>alert('xss')</script>".to_string();
        let html = format_alert_html(&event, "HIGH");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn score_labels() {
        assert_eq!(score_label(1.0), "CRITICAL");
        assert_eq!(score_label(0.7), "HIGH");
        assert_eq!(score_label(0.5), "MEDIUM");
        assert_eq!(score_label(0.3), "LOW");
        assert_eq!(score_label(0.1), "INFO");
    }

    #[tokio::test]
    async fn maybe_send_with_none_config() {
        let event = test_event(0.95);
        // Should not panic with None config
        maybe_send_alert(&event, &None).await;
    }
}