// ============================================================================
// File: audit_chain.rs
// Description: SHA-256 hash-chained tamper-evident security audit event log
// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
//! Audit Chain — Tamper-evident, hash-chained security event log.
//!
//! Every security event is recorded with a SHA-256 hash that includes the hash
//! of the previous event, forming an append-only chain. If any event is modified
//! or deleted, the chain breaks — detectable via `verify_chain()`.

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

/// Types of security events recorded in the audit chain.
#[derive(Debug, Clone, serde::Serialize)]
pub enum SecurityEventType {
    RequestAllowed,
    RequestBlocked,
    RateLimitHit,
    SqlInjectionAttempt,
    SsrfAttempt,
    PathTraversalAttempt,
    MaliciousPayload,
    DataQuarantined,
    AuthFailure,
    BanIssued,
    BanLifted,
    ChainVerified,
    // Endpoint protection events
    MalwareDetected,
    SuspiciousProcess,
    SuspiciousNetwork,
    MemoryAnomaly,
    RootkitIndicator,
    FileQuarantined,
    FileRestored,
    SignatureDbUpdated,
    EndpointScanStarted,
    EndpointScanCompleted,
}

/// A single event in the hash-chained audit log.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEvent {
    /// Unique event identifier.
    pub id: String,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// What type of security event.
    pub event_type: SecurityEventType,
    /// Source IP address.
    pub source_ip: String,
    /// Human-readable details (internal only — never exposed to clients).
    pub details: String,
    /// Threat score at the time of this event (0.0–1.0).
    pub threat_score: f64,
    /// Hash of the previous event in the chain.
    pub previous_hash: String,
    /// SHA-256 hash of this event (computed from all fields + previous_hash).
    pub hash: String,
}

/// Append-only, hash-chained security audit log.
pub struct AuditChain {
    events: RwLock<Vec<AuditEvent>>,
    max_events: usize,
    /// Broadcast channel for SSE subscriptions (256 capacity = 256 max lagged clients)
    tx: broadcast::Sender<AuditEvent>,
}

impl AuditChain {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            events: RwLock::new(Vec::new()),
            max_events: 100_000,
            tx,
        }
    }

    pub fn with_max_events(max_events: usize) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            events: RwLock::new(Vec::new()),
            max_events,
            tx,
        }
    }

    /// Subscribe to audit events via broadcast channel (for SSE streaming).
    pub fn subscribe(&self) -> broadcast::Receiver<AuditEvent> {
        self.tx.subscribe()
    }

    /// Record a new security event. The event is hash-chained to the previous event.
    pub fn record(
        &self,
        event_type: SecurityEventType,
        source_ip: &str,
        details: &str,
        threat_score: f64,
    ) {
        let mut events = self.events.write();

        let previous_hash = events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "genesis".to_string());

        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        let hash = compute_event_hash(
            &id,
            &timestamp,
            &event_type,
            source_ip,
            details,
            threat_score,
            &previous_hash,
        );

        let event = AuditEvent {
            id,
            timestamp,
            event_type,
            source_ip: source_ip.to_string(),
            details: details.to_string(),
            threat_score,
            previous_hash,
            hash,
        };

        tracing::debug!(
            event_type = ?event.event_type,
            ip = %event.source_ip,
            score = event.threat_score,
            "Shield audit event"
        );

        events.push(event.clone());

        // Broadcast the event to SSE subscribers (ignore if no subscribers)
        let _ = self.tx.send(event);

        // Prune old events if over limit (keep the tail)
        if events.len() > self.max_events {
            let drain_count = events.len() - self.max_events;
            events.drain(..drain_count);
        }
    }

    /// Verify the integrity of the entire hash chain.
    /// Returns true if no events have been tampered with or removed.
    pub fn verify_chain(&self) -> ChainVerification {
        let events = self.events.read();

        if events.is_empty() {
            return ChainVerification {
                valid: true,
                total_events: 0,
                first_broken_at: None,
            };
        }

        for (i, event) in events.iter().enumerate() {
            // Verify previous_hash link
            let expected_prev = if i == 0 {
                "genesis".to_string()
            } else {
                events[i - 1].hash.clone()
            };

            if event.previous_hash != expected_prev {
                return ChainVerification {
                    valid: false,
                    total_events: events.len(),
                    first_broken_at: Some(i),
                };
            }

            // Recompute hash and verify
            let computed = compute_event_hash(
                &event.id,
                &event.timestamp,
                &event.event_type,
                &event.source_ip,
                &event.details,
                event.threat_score,
                &event.previous_hash,
            );

            if computed != event.hash {
                return ChainVerification {
                    valid: false,
                    total_events: events.len(),
                    first_broken_at: Some(i),
                };
            }
        }

        ChainVerification {
            valid: true,
            total_events: events.len(),
            first_broken_at: None,
        }
    }

    /// Get the total number of events in the chain.
    pub fn len(&self) -> usize {
        self.events.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.read().is_empty()
    }

    /// Get recent events (most recent first).
    pub fn recent(&self, count: usize) -> Vec<AuditEvent> {
        let events = self.events.read();
        events.iter().rev().take(count).cloned().collect()
    }

    /// Count events by type since a given time.
    pub fn count_since(
        &self,
        event_type: &SecurityEventType,
        since: DateTime<Utc>,
    ) -> usize {
        let events = self.events.read();
        let type_str = format!("{:?}", event_type);
        events
            .iter()
            .rev()
            .take_while(|e| e.timestamp >= since)
            .filter(|e| format!("{:?}", e.event_type) == type_str)
            .count()
    }

    /// Export the chain as JSON for external audit.
    pub fn export_json(&self) -> String {
        let events = self.events.read();
        serde_json::to_string_pretty(&*events).unwrap_or_else(|_| "[]".to_string())
    }
}

#[derive(Debug)]
pub struct ChainVerification {
    /// Whether the entire chain is intact.
    pub valid: bool,
    /// Total number of events checked.
    pub total_events: usize,
    /// Index of the first broken link (if any).
    pub first_broken_at: Option<usize>,
}

fn compute_event_hash(
    id: &str,
    timestamp: &DateTime<Utc>,
    event_type: &SecurityEventType,
    source_ip: &str,
    details: &str,
    threat_score: f64,
    previous_hash: &str,
) -> String {
    let input = format!(
        "{}|{}|{:?}|{}|{}|{:.6}|{}",
        id, timestamp, event_type, source_ip, details, threat_score, previous_hash
    );
    hex::encode(Sha256::digest(input.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_chain_is_valid() {
        let chain = AuditChain::new();
        let v = chain.verify_chain();
        assert!(v.valid);
        assert_eq!(v.total_events, 0);
    }

    #[test]
    fn single_event_chain_is_valid() {
        let chain = AuditChain::new();
        chain.record(SecurityEventType::RequestAllowed, "1.2.3.4", "test", 0.1);
        let v = chain.verify_chain();
        assert!(v.valid);
        assert_eq!(v.total_events, 1);
    }

    #[test]
    fn multi_event_chain_is_valid() {
        let chain = AuditChain::new();
        chain.record(SecurityEventType::RequestAllowed, "1.2.3.4", "req 1", 0.1);
        chain.record(SecurityEventType::RateLimitHit, "5.6.7.8", "rate limit", 0.8);
        chain.record(SecurityEventType::SqlInjectionAttempt, "9.0.1.2", "union injection", 0.95);
        let v = chain.verify_chain();
        assert!(v.valid);
        assert_eq!(v.total_events, 3);
    }

    #[test]
    fn tampered_chain_detected() {
        let chain = AuditChain::new();
        chain.record(SecurityEventType::RequestAllowed, "1.2.3.4", "req 1", 0.1);
        chain.record(SecurityEventType::RequestBlocked, "5.6.7.8", "blocked", 0.9);

        // Tamper with the chain
        {
            let mut events = chain.events.write();
            events[0].details = "tampered".to_string();
        }

        let v = chain.verify_chain();
        assert!(!v.valid);
        assert_eq!(v.first_broken_at, Some(0));
    }

    #[test]
    fn pruning_works() {
        let chain = AuditChain::with_max_events(5);
        for i in 0..10 {
            chain.record(SecurityEventType::RequestAllowed, "1.2.3.4", &format!("req {i}"), 0.1);
        }
        assert_eq!(chain.len(), 5);
    }

    #[test]
    fn recent_returns_newest_first() {
        let chain = AuditChain::new();
        chain.record(SecurityEventType::RequestAllowed, "1.2.3.4", "first", 0.1);
        chain.record(SecurityEventType::RequestBlocked, "5.6.7.8", "second", 0.9);
        let recent = chain.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].details, "second");
        assert_eq!(recent[1].details, "first");
    }
}