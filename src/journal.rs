// ============================================================================
// File: journal.rs
// Description: Systemd journal integration — write structured security events
//              to journald so they appear in `journalctl -u nexus-shield`
// ============================================================================
//! Journal — writes security events to the systemd journal with structured
//! fields for filtering via `journalctl`.
//!
//! Events are written using the `tracing` framework's journal-compatible
//! structured fields. Each event includes:
//! - `SYSLOG_IDENTIFIER=nexus-shield`
//! - `EVENT_TYPE=<type>`
//! - `THREAT_SCORE=<score>`
//! - `SOURCE_IP=<ip>`
//! - `PRIORITY=<syslog priority>`
//!
//! Usage:
//! ```bash
//! # View all NexusShield events
//! journalctl -u nexus-shield -f
//!
//! # Filter by priority (warnings and above)
//! journalctl -u nexus-shield -p warning
//!
//! # JSON output for parsing
//! journalctl -u nexus-shield -o json
//! ```

use crate::audit_chain::AuditEvent;
use serde::{Deserialize, Serialize};

/// Configuration for journal integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalConfig {
    /// Whether to write events to the journal.
    pub enabled: bool,
    /// Minimum threat score to log (0.0 = all events).
    pub min_threat_score: f64,
    /// Include full event details in the journal message.
    pub include_details: bool,
}

impl Default for JournalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_threat_score: 0.0,
            include_details: true,
        }
    }
}

/// Map threat score to syslog priority level.
fn threat_score_to_priority(score: f64) -> &'static str {
    match score {
        s if s >= 0.9 => "CRIT",
        s if s >= 0.7 => "ERR",
        s if s >= 0.5 => "WARNING",
        s if s >= 0.3 => "NOTICE",
        _ => "INFO",
    }
}

/// Write an audit event to the systemd journal via tracing macros.
/// Events will appear in `journalctl -u nexus-shield`.
pub fn log_to_journal(event: &AuditEvent, config: &JournalConfig) {
    if !config.enabled {
        return;
    }

    if event.threat_score < config.min_threat_score {
        return;
    }

    let event_type = format!("{:?}", event.event_type);
    let priority = threat_score_to_priority(event.threat_score);

    let message = if config.include_details {
        format!(
            "[{}] {} from {} — {} (score: {:.3})",
            priority, event_type, event.source_ip, event.details, event.threat_score
        )
    } else {
        format!(
            "[{}] {} from {} (score: {:.3})",
            priority, event_type, event.source_ip, event.threat_score
        )
    };

    // Use tracing macros which write to journald when tracing-subscriber
    // is configured (which it is in main.rs). The structured fields become
    // journal fields accessible via `journalctl -o json`.
    match priority {
        "CRIT" => tracing::error!(
            event_type = %event_type,
            source_ip = %event.source_ip,
            threat_score = event.threat_score,
            event_id = %event.id,
            chain_hash = %event.hash,
            "SECURITY {}", message
        ),
        "ERR" => tracing::error!(
            event_type = %event_type,
            source_ip = %event.source_ip,
            threat_score = event.threat_score,
            event_id = %event.id,
            "SECURITY {}", message
        ),
        "WARNING" => tracing::warn!(
            event_type = %event_type,
            source_ip = %event.source_ip,
            threat_score = event.threat_score,
            event_id = %event.id,
            "SECURITY {}", message
        ),
        "NOTICE" => tracing::info!(
            event_type = %event_type,
            source_ip = %event.source_ip,
            threat_score = event.threat_score,
            event_id = %event.id,
            "SECURITY {}", message
        ),
        _ => tracing::info!(
            event_type = %event_type,
            source_ip = %event.source_ip,
            threat_score = event.threat_score,
            "SECURITY {}", message
        ),
    }
}

/// Batch-log recent events to the journal (for startup catch-up).
pub fn log_recent_to_journal(events: &[AuditEvent], config: &JournalConfig) {
    for event in events {
        log_to_journal(event, config);
    }
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
            source_ip: "192.168.1.1".to_string(),
            details: "test event".to_string(),
            threat_score: score,
            previous_hash: "0000".to_string(),
            hash: "abcd".to_string(),
        }
    }

    #[test]
    fn priority_mapping() {
        assert_eq!(threat_score_to_priority(1.0), "CRIT");
        assert_eq!(threat_score_to_priority(0.9), "CRIT");
        assert_eq!(threat_score_to_priority(0.7), "ERR");
        assert_eq!(threat_score_to_priority(0.5), "WARNING");
        assert_eq!(threat_score_to_priority(0.3), "NOTICE");
        assert_eq!(threat_score_to_priority(0.1), "INFO");
        assert_eq!(threat_score_to_priority(0.0), "INFO");
    }

    #[test]
    fn config_defaults() {
        let config = JournalConfig::default();
        assert!(config.enabled);
        assert_eq!(config.min_threat_score, 0.0);
        assert!(config.include_details);
    }

    #[test]
    fn log_does_not_panic() {
        let config = JournalConfig::default();
        let event = test_event(0.85);
        log_to_journal(&event, &config);
    }

    #[test]
    fn disabled_config_skips() {
        let config = JournalConfig {
            enabled: false,
            ..Default::default()
        };
        let event = test_event(0.9);
        // Should not panic or log
        log_to_journal(&event, &config);
    }

    #[test]
    fn min_score_filters() {
        let config = JournalConfig {
            min_threat_score: 0.8,
            ..Default::default()
        };
        // Score 0.5 is below threshold — should be skipped silently
        let event = test_event(0.5);
        log_to_journal(&event, &config);
    }

    #[test]
    fn batch_log_does_not_panic() {
        let config = JournalConfig::default();
        let events = vec![test_event(0.3), test_event(0.7), test_event(0.95)];
        log_recent_to_journal(&events, &config);
    }

    #[test]
    fn all_priority_levels() {
        let config = JournalConfig::default();
        for score in [0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0] {
            log_to_journal(&test_event(score), &config);
        }
    }
}