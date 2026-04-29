// ============================================================================
// File: config.rs
// Description: Shield security engine configuration for all defense layers
// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
use std::collections::HashSet;
use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::email_guard::EmailGuardConfig;

/// Complete configuration for the Shield security engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldConfig {
    /// Threat score threshold above which requests are blocked (0.0–1.0).
    #[serde(default = "default_block_threshold")]
    pub block_threshold: f64,
    /// Threat score threshold for logging warnings (0.0–1.0).
    #[serde(default = "default_warn_threshold")]
    pub warn_threshold: f64,
    /// SQL firewall configuration.
    #[serde(default)]
    pub sql: SqlFirewallConfig,
    /// SSRF guard configuration.
    #[serde(default)]
    pub ssrf: SsrfConfig,
    /// Rate limiting configuration.
    #[serde(default)]
    pub rate: RateConfig,
    /// Data quarantine configuration.
    #[serde(default)]
    pub quarantine: QuarantineConfig,
    /// Maximum audit chain events to keep in memory before pruning.
    #[serde(default = "default_audit_max")]
    pub audit_max_events: usize,
    /// Email guard configuration.
    #[serde(default)]
    pub email: EmailGuardConfig,
    /// API authentication token (if set, all sensitive endpoints require Bearer auth).
    #[serde(default)]
    pub api_token: Option<String>,
    /// TLS certificate path.
    #[serde(default)]
    pub tls_cert: Option<String>,
    /// TLS private key path.
    #[serde(default)]
    pub tls_key: Option<String>,
    /// Webhook alert URLs for critical/high detections.
    #[serde(default)]
    pub webhook_urls: Vec<WebhookConfig>,
    /// Ferrum-Mail integration.
    #[serde(default)]
    pub ferrum_mail: Option<FerrumMailConfig>,
    /// Signature auto-update configuration.
    #[serde(default)]
    pub signature_update: Option<SignatureUpdateConfig>,
    /// NexusPulse SMS alert integration.
    #[serde(default)]
    pub nexus_pulse: Option<NexusPulseConfig>,
}

/// NexusPulse SMS alert configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NexusPulseConfig {
    /// NexusPulse API base URL (e.g., http://localhost:8100).
    pub api_url: String,
    /// API key for NexusPulse authentication.
    pub api_key: String,
    /// Phone numbers to receive SMS alerts (E.164 format).
    pub alert_recipients: Vec<String>,
    /// Sender phone number (optional, uses NexusPulse default if omitted).
    #[serde(default)]
    pub from_number: Option<String>,
    /// Minimum severity to trigger SMS (default: critical).
    #[serde(default = "default_pulse_min_severity")]
    pub min_severity: String,
    /// Use the built-in "alert" template for formatted messages.
    #[serde(default = "default_true")]
    pub use_template: bool,
}

fn default_block_threshold() -> f64 { 0.7 }
fn default_warn_threshold() -> f64 { 0.4 }
fn default_audit_max() -> usize { 100_000 }

/// Webhook alert configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL (Slack, Discord, PagerDuty, generic).
    pub url: String,
    /// Minimum severity to trigger (info, low, medium, high, critical).
    #[serde(default = "default_webhook_min_severity")]
    pub min_severity: String,
    /// Optional custom headers.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Webhook type hint for formatting (slack, discord, telegram, generic).
    #[serde(default = "default_webhook_type")]
    pub webhook_type: String,
    /// Telegram chat ID (required for Telegram webhooks).
    #[serde(default)]
    pub telegram_chat_id: Option<String>,
}

fn default_webhook_min_severity() -> String { "high".to_string() }
fn default_webhook_type() -> String { "generic".to_string() }

/// Ferrum-Mail integration for email alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FerrumMailConfig {
    /// Ferrum-Mail API base URL.
    pub api_url: String,
    /// API key for Ferrum-Mail authentication.
    pub api_key: String,
    /// Sender address for alert emails.
    pub from_address: String,
    /// Recipient addresses for alerts.
    pub alert_recipients: Vec<String>,
    /// Minimum severity to send email (default: high).
    #[serde(default = "default_webhook_min_severity")]
    pub min_severity: String,
    /// Include full event details in email body.
    #[serde(default = "default_true")]
    pub include_details: bool,
}

fn default_true() -> bool { true }

/// Automatic signature update configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureUpdateConfig {
    /// URL to fetch NDJSON signatures from.
    pub feed_url: String,
    /// Update interval in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_sig_interval")]
    pub interval_secs: u64,
    /// Optional authentication header for the feed.
    #[serde(default)]
    pub auth_header: Option<String>,
}

fn default_sig_interval() -> u64 { 3600 }
fn default_pulse_min_severity() -> String { "critical".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlFirewallConfig {
    #[serde(default)]
    pub allow_comments: bool,
    #[serde(default = "default_max_query_length")]
    pub max_query_length: usize,
    #[serde(default = "default_max_subquery_depth")]
    pub max_subquery_depth: u32,
    #[serde(default)]
    pub blocked_functions: Vec<String>,
    #[serde(default)]
    pub blocked_schemas: Vec<String>,
}

fn default_max_query_length() -> usize { 10_000 }
fn default_max_subquery_depth() -> u32 { 3 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfConfig {
    #[serde(default = "default_true")]
    pub block_private_ips: bool,
    #[serde(default = "default_true")]
    pub block_loopback: bool,
    #[serde(default = "default_true")]
    pub block_link_local: bool,
    #[serde(default = "default_true")]
    pub block_metadata_endpoints: bool,
    #[serde(default = "default_allowed_schemes")]
    pub allowed_schemes: Vec<String>,
    #[serde(default)]
    pub allowlist: HashSet<String>,
    #[serde(default)]
    pub blocklist: HashSet<String>,
    #[serde(default = "default_blocked_ports")]
    pub blocked_ports: Vec<u16>,
}

fn default_allowed_schemes() -> Vec<String> { vec!["http".into(), "https".into()] }
fn default_blocked_ports() -> Vec<u16> {
    vec![22, 23, 25, 53, 111, 135, 139, 445, 514, 873, 2049, 3306, 5432, 6379, 6380, 9200, 9300, 11211, 27017, 27018, 50070]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateConfig {
    #[serde(default = "default_rps")]
    pub requests_per_second: f64,
    #[serde(default = "default_burst")]
    pub burst_capacity: f64,
    #[serde(default = "default_warn_after")]
    pub warn_after: u32,
    #[serde(default = "default_throttle_after")]
    pub throttle_after: u32,
    #[serde(default = "default_block_after")]
    pub block_after: u32,
    #[serde(default = "default_ban_after")]
    pub ban_after: u32,
    #[serde(default = "default_ban_duration")]
    pub ban_duration_secs: u64,
    #[serde(default = "default_decay")]
    pub violation_decay_secs: u64,
}

fn default_rps() -> f64 { 50.0 }
fn default_burst() -> f64 { 100.0 }
fn default_warn_after() -> u32 { 3 }
fn default_throttle_after() -> u32 { 8 }
fn default_block_after() -> u32 { 15 }
fn default_ban_after() -> u32 { 30 }
fn default_ban_duration() -> u64 { 300 }
fn default_decay() -> u64 { 60 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    #[serde(default = "default_max_rows")]
    pub max_rows: usize,
    #[serde(default = "default_max_size")]
    pub max_size_bytes: usize,
    #[serde(default = "default_max_cols")]
    pub max_columns: usize,
    #[serde(default = "default_true")]
    pub check_formula_injection: bool,
    #[serde(default = "default_true")]
    pub check_embedded_scripts: bool,
}

fn default_max_rows() -> usize { 5_000_000 }
fn default_max_size() -> usize { 500 * 1024 * 1024 }
fn default_max_cols() -> usize { 500 }

// === Default implementations ===

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            block_threshold: 0.7,
            warn_threshold: 0.4,
            sql: SqlFirewallConfig::default(),
            ssrf: SsrfConfig::default(),
            rate: RateConfig::default(),
            quarantine: QuarantineConfig::default(),
            audit_max_events: 100_000,
            email: EmailGuardConfig::default(),
            api_token: None,
            tls_cert: None,
            tls_key: None,
            webhook_urls: Vec::new(),
            ferrum_mail: None,
            signature_update: None,
            nexus_pulse: None,
        }
    }
}

impl Default for SqlFirewallConfig {
    fn default() -> Self {
        Self {
            allow_comments: false,
            max_query_length: 10_000,
            max_subquery_depth: 3,
            blocked_functions: Vec::new(),
            blocked_schemas: Vec::new(),
        }
    }
}

impl Default for SsrfConfig {
    fn default() -> Self {
        Self {
            block_private_ips: true,
            block_loopback: true,
            block_link_local: true,
            block_metadata_endpoints: true,
            allowed_schemes: default_allowed_schemes(),
            allowlist: HashSet::new(),
            blocklist: HashSet::new(),
            blocked_ports: default_blocked_ports(),
        }
    }
}

impl Default for RateConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 50.0,
            burst_capacity: 100.0,
            warn_after: 3,
            throttle_after: 8,
            block_after: 15,
            ban_after: 30,
            ban_duration_secs: 300,
            violation_decay_secs: 60,
        }
    }
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            max_rows: 5_000_000,
            max_size_bytes: 500 * 1024 * 1024,
            max_columns: 500,
            check_formula_injection: true,
            check_embedded_scripts: true,
        }
    }
}

/// Load configuration from a TOML file, falling back to defaults for missing fields.
pub fn load_config(path: &Path) -> Result<ShieldConfig, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file {}: {}", path.display(), e))?;
    let config: ShieldConfig = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse config file {}: {}", path.display(), e))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = ShieldConfig::default();
        assert_eq!(config.block_threshold, 0.7);
        assert_eq!(config.warn_threshold, 0.4);
        assert!(config.api_token.is_none());
        assert!(config.tls_cert.is_none());
        assert!(config.webhook_urls.is_empty());
        assert!(config.ferrum_mail.is_none());
        assert!(config.signature_update.is_none());
    }

    #[test]
    fn parse_minimal_toml() {
        let toml = r#"
block_threshold = 0.8
warn_threshold = 0.5
"#;
        let config: ShieldConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.block_threshold, 0.8);
        assert_eq!(config.warn_threshold, 0.5);
        assert_eq!(config.rate.requests_per_second, 50.0); // default
    }

    #[test]
    fn parse_full_toml() {
        let toml = r#"
block_threshold = 0.9
warn_threshold = 0.6
api_token = "my-secret-token"
tls_cert = "/etc/nexus-shield/cert.pem"
tls_key = "/etc/nexus-shield/key.pem"

[sql]
allow_comments = true
max_query_length = 20000

[rate]
requests_per_second = 100.0
burst_capacity = 200.0
ban_duration_secs = 600

[[webhook_urls]]
url = "https://hooks.slack.com/services/xxx"
min_severity = "critical"
webhook_type = "slack"

[ferrum_mail]
api_url = "http://localhost:3030"
api_key = "fm-key-123"
from_address = "shield@company.com"
alert_recipients = ["admin@company.com", "security@company.com"]

[signature_update]
feed_url = "https://signatures.nexusshield.dev/v1/latest.ndjson"
interval_secs = 1800
"#;
        let config: ShieldConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.block_threshold, 0.9);
        assert_eq!(config.api_token, Some("my-secret-token".to_string()));
        assert_eq!(config.sql.max_query_length, 20000);
        assert_eq!(config.rate.requests_per_second, 100.0);
        assert_eq!(config.webhook_urls.len(), 1);
        assert_eq!(config.webhook_urls[0].webhook_type, "slack");
        let fm = config.ferrum_mail.unwrap();
        assert_eq!(fm.alert_recipients.len(), 2);
        let su = config.signature_update.unwrap();
        assert_eq!(su.interval_secs, 1800);
    }

    #[test]
    fn parse_empty_toml() {
        let config: ShieldConfig = toml::from_str("").unwrap();
        assert_eq!(config.block_threshold, 0.7); // all defaults
    }

    #[test]
    fn load_nonexistent_file() {
        let result = load_config(Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn webhook_config_defaults() {
        let toml = r#"
[[webhook_urls]]
url = "https://example.com/hook"
"#;
        let config: ShieldConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.webhook_urls[0].min_severity, "high");
        assert_eq!(config.webhook_urls[0].webhook_type, "generic");
    }
}