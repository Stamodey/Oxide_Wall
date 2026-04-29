// ============================================================================
// File: compliance_report.rs
// Description: Compliance report generator — HTML export of security posture,
//              detections, audit trail, and configuration for auditors
// ============================================================================
//! Compliance Report — generates HTML security posture reports for auditors,
//! compliance teams, and management.
//!
//! Report includes:
//! - Executive summary (threat counts, chain integrity, uptime)
//! - Active module inventory
//! - Configuration audit (thresholds, rate limits)
//! - Recent detections with severity breakdown
//! - Audit chain verification status
//! - Top threat sources
//! - Endpoint protection status (if enabled)

use crate::audit_chain::{AuditChain, SecurityEventType};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for report generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Organization name for the report header.
    pub organization: String,
    /// Report title.
    pub title: String,
    /// Include full event details in the report.
    pub include_event_details: bool,
    /// Maximum events to include.
    pub max_events: usize,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            organization: "Organization".to_string(),
            title: "NexusShield Security Compliance Report".to_string(),
            include_event_details: true,
            max_events: 500,
        }
    }
}

/// Summary statistics for the report.
#[derive(Debug, Clone, Serialize)]
pub struct ReportSummary {
    pub generated_at: String,
    pub report_period: String,
    pub total_events: usize,
    pub chain_valid: bool,
    pub events_by_type: HashMap<String, usize>,
    pub events_by_severity: HashMap<String, usize>,
    pub top_source_ips: Vec<(String, usize)>,
    pub blocked_count: usize,
    pub rate_limited_count: usize,
    pub sql_injection_count: usize,
    pub ssrf_count: usize,
    pub malware_count: usize,
}

/// Generate a compliance report summary from the audit chain.
pub fn generate_summary(audit: &AuditChain) -> ReportSummary {
    let events = audit.recent(10000);
    let chain_valid = audit.verify_chain().valid;

    let mut by_type: HashMap<String, usize> = HashMap::new();
    let mut by_severity: HashMap<String, usize> = HashMap::new();
    let mut by_ip: HashMap<String, usize> = HashMap::new();
    let mut blocked = 0;
    let mut rate_limited = 0;
    let mut sql_injection = 0;
    let mut ssrf = 0;
    let mut malware = 0;

    for event in &events {
        let type_name = format!("{:?}", event.event_type);
        *by_type.entry(type_name).or_insert(0) += 1;

        let severity = score_to_severity(event.threat_score);
        *by_severity.entry(severity).or_insert(0) += 1;

        *by_ip.entry(event.source_ip.clone()).or_insert(0) += 1;

        match event.event_type {
            SecurityEventType::RequestBlocked => blocked += 1,
            SecurityEventType::RateLimitHit => rate_limited += 1,
            SecurityEventType::SqlInjectionAttempt => sql_injection += 1,
            SecurityEventType::SsrfAttempt => ssrf += 1,
            SecurityEventType::MalwareDetected => malware += 1,
            _ => {}
        }
    }

    let mut top_ips: Vec<(String, usize)> = by_ip.into_iter().collect();
    top_ips.sort_by(|a, b| b.1.cmp(&a.1));
    top_ips.truncate(10);

    ReportSummary {
        generated_at: Utc::now().to_rfc3339(),
        report_period: format!("Last {} events", events.len()),
        total_events: events.len(),
        chain_valid,
        events_by_type: by_type,
        events_by_severity: by_severity,
        top_source_ips: top_ips,
        blocked_count: blocked,
        rate_limited_count: rate_limited,
        sql_injection_count: sql_injection,
        ssrf_count: ssrf,
        malware_count: malware,
    }
}

fn score_to_severity(score: f64) -> String {
    match score {
        s if s >= 0.9 => "Critical".to_string(),
        s if s >= 0.7 => "High".to_string(),
        s if s >= 0.5 => "Medium".to_string(),
        s if s >= 0.3 => "Low".to_string(),
        _ => "Info".to_string(),
    }
}

/// Generate a full HTML compliance report.
pub fn generate_html_report(
    audit: &AuditChain,
    config: &ReportConfig,
    modules: &[String],
    shield_config: &serde_json::Value,
) -> String {
    let summary = generate_summary(audit);
    let events = audit.recent(config.max_events);

    let events_html = if config.include_event_details {
        events
            .iter()
            .map(|e| {
                let severity = score_to_severity(e.threat_score);
                let severity_class = severity.to_lowercase();
                format!(
                    r#"<tr class="{}"><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td><td>{:.3}</td><td>{}</td></tr>"#,
                    severity_class,
                    e.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                    e.event_type,
                    severity,
                    e.source_ip,
                    e.threat_score,
                    html_escape(&e.details),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        String::new()
    };

    let modules_html = modules
        .iter()
        .map(|m| format!("<li>{}</li>", html_escape(m)))
        .collect::<Vec<_>>()
        .join("\n");

    let top_ips_html = summary
        .top_source_ips
        .iter()
        .map(|(ip, count)| format!("<tr><td>{}</td><td>{}</td></tr>", html_escape(ip), count))
        .collect::<Vec<_>>()
        .join("\n");

    let severity_html = ["Critical", "High", "Medium", "Low", "Info"]
        .iter()
        .map(|sev| {
            let count = summary.events_by_severity.get(*sev).unwrap_or(&0);
            let class = sev.to_lowercase();
            format!(
                r#"<div class="severity-bar {}"><span class="label">{}</span><span class="count">{}</span></div>"#,
                class, sev, count
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #faf9f6; color: #111827; padding: 40px; max-width: 1200px; margin: 0 auto; }}
  h1 {{ font-size: 28px; margin-bottom: 4px; color: #0d9488; }}
  h2 {{ font-size: 20px; margin: 32px 0 16px; color: #111827; border-bottom: 2px solid #14b8a6; padding-bottom: 8px; }}
  h3 {{ font-size: 16px; margin: 20px 0 10px; color: #6b7280; }}
  .header {{ border-bottom: 3px solid #14b8a6; padding-bottom: 16px; margin-bottom: 32px; }}
  .header .org {{ font-size: 14px; color: #6b7280; }}
  .header .date {{ font-size: 12px; color: #9ca3af; margin-top: 4px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 20px 0; }}
  .stat-card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 20px; text-align: center; }}
  .stat-card .value {{ font-size: 36px; font-weight: 800; color: #0d9488; }}
  .stat-card .label {{ font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; }}
  .stat-card.danger .value {{ color: #ef4444; }}
  .stat-card.warning .value {{ color: #f59e0b; }}
  .stat-card.success .value {{ color: #10b981; }}
  .chain-status {{ padding: 12px 20px; border-radius: 8px; font-weight: 600; margin: 16px 0; }}
  .chain-valid {{ background: #f0fdf4; color: #065f46; border: 1px solid #bbf7d0; }}
  .chain-invalid {{ background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }}
  .severity-bar {{ display: flex; justify-content: space-between; padding: 8px 16px; margin: 4px 0; border-radius: 6px; font-weight: 500; }}
  .severity-bar.critical {{ background: #fef2f2; color: #991b1b; }}
  .severity-bar.high {{ background: #fff7ed; color: #9a3412; }}
  .severity-bar.medium {{ background: #fffbeb; color: #92400e; }}
  .severity-bar.low {{ background: #f0fdf4; color: #166534; }}
  .severity-bar.info {{ background: #eff6ff; color: #1e40af; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
  th {{ background: #f3f4f6; padding: 10px 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #e5e7eb; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #f3f4f6; }}
  tr.critical td {{ background: #fef2f2; }}
  tr.high td {{ background: #fff7ed; }}
  tr.medium td {{ background: #fffbeb; }}
  ul {{ padding-left: 24px; }}
  li {{ margin: 4px 0; }}
  .footer {{ margin-top: 48px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 11px; color: #9ca3af; text-align: center; }}
  @media print {{ body {{ padding: 20px; }} .stat-card {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>{title}</h1>
  <div class="org">{org}</div>
  <div class="date">Generated: {generated} | Period: {period}</div>
</div>

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="stat-card"><div class="value">{total}</div><div class="label">Total Events</div></div>
  <div class="stat-card danger"><div class="value">{blocked}</div><div class="label">Blocked</div></div>
  <div class="stat-card warning"><div class="value">{rate_limited}</div><div class="label">Rate Limited</div></div>
  <div class="stat-card danger"><div class="value">{sql_inj}</div><div class="label">SQL Injection</div></div>
  <div class="stat-card warning"><div class="value">{ssrf}</div><div class="label">SSRF Attempts</div></div>
  <div class="stat-card danger"><div class="value">{malware}</div><div class="label">Malware Detected</div></div>
</div>

<div class="chain-status {chain_class}">
  Audit Chain Integrity: {chain_status}
</div>

<h2>Severity Breakdown</h2>
{severity_html}

<h2>Active Security Modules</h2>
<ul>
{modules_html}
</ul>

<h2>Configuration</h2>
<pre style="background:#f3f4f6;padding:16px;border-radius:8px;font-size:12px;overflow-x:auto;">{config_json}</pre>

<h2>Top Threat Sources</h2>
<table>
<tr><th>Source IP</th><th>Event Count</th></tr>
{top_ips_html}
</table>

{events_section}

<div class="footer">
  NexusShield Compliance Report | AutomataNexus Engineering | Generated by NexusShield v0.3.x
</div>
</body>
</html>"#,
        title = html_escape(&config.title),
        org = html_escape(&config.organization),
        generated = summary.generated_at,
        period = summary.report_period,
        total = summary.total_events,
        blocked = summary.blocked_count,
        rate_limited = summary.rate_limited_count,
        sql_inj = summary.sql_injection_count,
        ssrf = summary.ssrf_count,
        malware = summary.malware_count,
        chain_class = if summary.chain_valid { "chain-valid" } else { "chain-invalid" },
        chain_status = if summary.chain_valid { "VERIFIED — SHA-256 hash chain is intact" } else { "FAILED — Chain tampering detected!" },
        severity_html = severity_html,
        modules_html = modules_html,
        config_json = html_escape(&serde_json::to_string_pretty(shield_config).unwrap_or_default()),
        top_ips_html = top_ips_html,
        events_section = if config.include_event_details {
            format!(
                r#"<h2>Event Log (Last {} Events)</h2>
<table>
<tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Source IP</th><th>Score</th><th>Details</th></tr>
{}
</table>"#,
                events.len(),
                events_html
            )
        } else {
            String::new()
        },
    )
}

/// HTML-escape a string.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Generate a JSON report (machine-readable alternative).
pub fn generate_json_report(
    audit: &AuditChain,
    modules: &[String],
    shield_config: &serde_json::Value,
) -> String {
    let summary = generate_summary(audit);
    let report = serde_json::json!({
        "report_type": "compliance",
        "generated_at": summary.generated_at,
        "summary": summary,
        "modules": modules,
        "configuration": shield_config,
    });
    serde_json::to_string_pretty(&report).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_chain::AuditChain;

    #[test]
    fn config_defaults() {
        let config = ReportConfig::default();
        assert_eq!(config.max_events, 500);
        assert!(config.include_event_details);
    }

    #[test]
    fn empty_audit_chain_report() {
        let audit = AuditChain::new();
        let summary = generate_summary(&audit);
        assert_eq!(summary.total_events, 0);
        assert!(summary.chain_valid);
        assert_eq!(summary.blocked_count, 0);
    }

    #[test]
    fn summary_with_events() {
        let audit = AuditChain::new();
        audit.record(SecurityEventType::RequestBlocked, "1.2.3.4", "test blocked", 0.85);
        audit.record(SecurityEventType::SqlInjectionAttempt, "1.2.3.4", "UNION attack", 0.95);
        audit.record(SecurityEventType::RateLimitHit, "5.6.7.8", "rate limit", 0.8);

        let summary = generate_summary(&audit);
        assert_eq!(summary.total_events, 3);
        assert_eq!(summary.blocked_count, 1);
        assert_eq!(summary.sql_injection_count, 1);
        assert_eq!(summary.rate_limited_count, 1);
        assert!(summary.chain_valid);
    }

    #[test]
    fn top_ips_sorted() {
        let audit = AuditChain::new();
        for _ in 0..5 {
            audit.record(SecurityEventType::RequestBlocked, "10.0.0.1", "block", 0.8);
        }
        for _ in 0..3 {
            audit.record(SecurityEventType::RequestBlocked, "10.0.0.2", "block", 0.8);
        }

        let summary = generate_summary(&audit);
        assert_eq!(summary.top_source_ips[0].0, "10.0.0.1");
        assert_eq!(summary.top_source_ips[0].1, 5);
    }

    #[test]
    fn severity_breakdown() {
        let audit = AuditChain::new();
        audit.record(SecurityEventType::RequestBlocked, "x", "test", 0.95); // Critical
        audit.record(SecurityEventType::RequestBlocked, "x", "test", 0.75); // High
        audit.record(SecurityEventType::RequestBlocked, "x", "test", 0.5);  // Medium

        let summary = generate_summary(&audit);
        assert_eq!(summary.events_by_severity.get("Critical"), Some(&1));
        assert_eq!(summary.events_by_severity.get("High"), Some(&1));
        assert_eq!(summary.events_by_severity.get("Medium"), Some(&1));
    }

    #[test]
    fn html_report_generation() {
        let audit = AuditChain::new();
        audit.record(SecurityEventType::RequestBlocked, "1.2.3.4", "test", 0.85);

        let config = ReportConfig::default();
        let modules = vec!["sql_firewall".to_string(), "ssrf_guard".to_string()];
        let shield_config = serde_json::json!({"block_threshold": 0.7});

        let html = generate_html_report(&audit, &config, &modules, &shield_config);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("NexusShield"));
        assert!(html.contains("sql_firewall"));
        assert!(html.contains("VERIFIED"));
        assert!(html.contains("1.2.3.4"));
    }

    #[test]
    fn html_report_without_details() {
        let audit = AuditChain::new();
        let config = ReportConfig {
            include_event_details: false,
            ..Default::default()
        };
        let html = generate_html_report(&audit, &config, &[], &serde_json::json!({}));
        assert!(!html.contains("Event Log"));
    }

    #[test]
    fn json_report_generation() {
        let audit = AuditChain::new();
        audit.record(SecurityEventType::MalwareDetected, "scanner", "eicar", 0.99);

        let modules = vec!["endpoint".to_string()];
        let json = generate_json_report(&audit, &modules, &serde_json::json!({}));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["report_type"], "compliance");
        assert!(parsed["summary"]["chain_valid"].as_bool().unwrap());
    }

    #[test]
    fn html_escape_works() {
        assert_eq!(html_escape("<script>alert('xss')</script>"), "&lt;script&gt;alert('xss')&lt;/script&gt;");
        assert_eq!(html_escape("normal text"), "normal text");
        assert_eq!(html_escape("a & b"), "a &amp; b");
    }

    #[test]
    fn score_to_severity_mapping() {
        assert_eq!(score_to_severity(1.0), "Critical");
        assert_eq!(score_to_severity(0.9), "Critical");
        assert_eq!(score_to_severity(0.7), "High");
        assert_eq!(score_to_severity(0.5), "Medium");
        assert_eq!(score_to_severity(0.3), "Low");
        assert_eq!(score_to_severity(0.0), "Info");
    }
}