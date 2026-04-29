// ============================================================================
// File: endpoint/dns_filter.rs
// Description: DNS filtering proxy — intercept, inspect, and block malicious
//              domain resolutions at the network level
// ============================================================================
//! DNS Filter — a lightweight UDP DNS proxy that checks every query against
//! the threat intelligence database and blocks resolutions to known-malicious
//! domains. Returns NXDOMAIN for blocked queries, forwards clean queries to
//! the upstream resolver.
//!
//! Operates on 127.0.0.1:5353 by default. Configure the system resolver
//! (or per-app) to use this address for transparent DNS filtering.

use super::threat_intel::ThreatIntelDB;
use super::{DetectionCategory, RecommendedAction, ScanResult, Severity};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the DNS filtering proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFilterConfig {
    /// Address to listen on (default: 127.0.0.1:5353).
    pub listen_addr: String,
    /// Upstream DNS resolver to forward clean queries to.
    pub upstream_dns: String,
    /// Timeout for upstream DNS queries in milliseconds.
    pub upstream_timeout_ms: u64,
    /// Maximum DNS packet size.
    pub max_packet_size: usize,
    /// Enable query logging (all queries, not just blocked).
    pub log_all_queries: bool,
    /// Custom blocklist of domains (in addition to threat intel).
    pub custom_blocklist: Vec<String>,
    /// Domains that should never be blocked.
    pub whitelist: Vec<String>,
}

impl Default for DnsFilterConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:5353".to_string(),
            upstream_dns: "8.8.8.8:53".to_string(),
            upstream_timeout_ms: 3000,
            max_packet_size: 4096,
            log_all_queries: false,
            custom_blocklist: Vec::new(),
            whitelist: vec![
                "localhost".to_string(),
            ],
        }
    }
}

// =============================================================================
// DNS Filter Stats
// =============================================================================

/// Runtime statistics for the DNS filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFilterStats {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub forwarded_queries: u64,
    pub failed_queries: u64,
    pub top_blocked_domains: Vec<(String, u64)>,
}

// =============================================================================
// DNS Packet Parsing
// =============================================================================

/// Minimal DNS header (12 bytes).
#[derive(Debug, Clone)]
struct DnsHeader {
    id: u16,
    flags: u16,
    qd_count: u16,
}

/// Extract the queried domain name from a DNS packet.
///
/// DNS name format: sequence of length-prefixed labels, terminated by 0x00.
/// Example: \x03www\x06google\x03com\x00 -> "www.google.com"
fn parse_query_domain(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None; // Too short for DNS header
    }

    // Skip 12-byte header
    let mut pos = 12;
    let mut labels = Vec::new();

    loop {
        if pos >= packet.len() {
            return None;
        }

        let len = packet[pos] as usize;
        pos += 1;

        if len == 0 {
            break; // End of name
        }

        // Compression pointer (top 2 bits set) — shouldn't appear in queries
        if len >= 0xC0 {
            return None;
        }

        if pos + len > packet.len() {
            return None;
        }

        let label = std::str::from_utf8(&packet[pos..pos + len]).ok()?;
        labels.push(label.to_lowercase());
        pos += len;
    }

    if labels.is_empty() {
        return None;
    }

    Some(labels.join("."))
}

/// Parse the DNS header to get the transaction ID and flags.
fn parse_dns_header(packet: &[u8]) -> Option<DnsHeader> {
    if packet.len() < 12 {
        return None;
    }
    Some(DnsHeader {
        id: u16::from_be_bytes([packet[0], packet[1]]),
        flags: u16::from_be_bytes([packet[2], packet[3]]),
        qd_count: u16::from_be_bytes([packet[4], packet[5]]),
    })
}

/// Build an NXDOMAIN response for a given DNS query packet.
/// Copies the original question section and sets RCODE=3 (NXDOMAIN).
fn build_nxdomain_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    let mut response = query.to_vec();

    // Set QR bit (response), keep opcode, set RA bit, RCODE=3 (NXDOMAIN)
    // Byte 2: QR=1, Opcode=keep, AA=1, TC=0, RD=keep
    response[2] = (query[2] & 0x78) | 0x84; // QR=1, AA=1, keep opcode and RD
    // Byte 3: RA=1, Z=0, RCODE=3
    response[3] = 0x83; // RA=1, RCODE=NXDOMAIN

    // Set answer count, authority count, additional count to 0
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;

    Some(response)
}

/// Build a response that resolves to 0.0.0.0 (sinkhole).
/// More compatible than NXDOMAIN for some applications.
fn build_sinkhole_response(query: &[u8]) -> Option<Vec<u8>> {
    let header = parse_dns_header(query)?;

    if query.len() < 12 {
        return None;
    }

    let mut response = Vec::with_capacity(query.len() + 16);

    // Copy header, modify flags
    response.extend_from_slice(&header.id.to_be_bytes());
    // QR=1, AA=1, RD=1, RA=1, RCODE=0 (no error)
    response.push(0x85); // QR=1, AA=1, RD=1
    response.push(0x80); // RA=1, RCODE=0
    // QD count (keep original)
    response.extend_from_slice(&header.qd_count.to_be_bytes());
    // AN count = 1
    response.push(0x00);
    response.push(0x01);
    // NS count = 0, AR count = 0
    response.extend_from_slice(&[0, 0, 0, 0]);

    // Copy question section from original query
    response.extend_from_slice(&query[12..]);

    // Append answer: pointer to name in question, type A, class IN, TTL 60, 0.0.0.0
    response.extend_from_slice(&[
        0xC0, 0x0C, // Name pointer to offset 12 (question name)
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
        0x00, 0x00, 0x00, 0x3C, // TTL = 60 seconds
        0x00, 0x04, // RDLENGTH = 4
        0x00, 0x00, 0x00, 0x00, // RDATA = 0.0.0.0
    ]);

    Some(response)
}

// =============================================================================
// DNS Filter
// =============================================================================

/// DNS filtering proxy that checks queries against threat intelligence.
pub struct DnsFilter {
    config: DnsFilterConfig,
    threat_intel: Arc<ThreatIntelDB>,
    /// Custom blocklist loaded at init + runtime additions.
    custom_blocklist: RwLock<Vec<String>>,
    /// Per-domain block counters for stats.
    block_counts: RwLock<HashMap<String, u64>>,
    /// Counters.
    total_queries: AtomicU64,
    blocked_queries: AtomicU64,
    forwarded_queries: AtomicU64,
    failed_queries: AtomicU64,
    /// Shutdown flag.
    running: Arc<AtomicBool>,
}

impl DnsFilter {
    pub fn new(config: DnsFilterConfig, threat_intel: Arc<ThreatIntelDB>) -> Self {
        let custom = config.custom_blocklist.clone();
        Self {
            config,
            threat_intel,
            custom_blocklist: RwLock::new(custom),
            block_counts: RwLock::new(HashMap::new()),
            total_queries: AtomicU64::new(0),
            blocked_queries: AtomicU64::new(0),
            forwarded_queries: AtomicU64::new(0),
            failed_queries: AtomicU64::new(0),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Check if a domain should be blocked.
    pub fn should_block(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();

        // Whitelist takes precedence
        for w in &self.config.whitelist {
            if lower == *w || lower.ends_with(&format!(".{}", w)) {
                return false;
            }
        }

        // Check threat intel database
        if self.threat_intel.check_domain(&lower) {
            return true;
        }

        // Check custom blocklist (exact match and subdomain match)
        let blocklist = self.custom_blocklist.read();
        for blocked in blocklist.iter() {
            let b = blocked.to_lowercase();
            if lower == b || lower.ends_with(&format!(".{}", b)) {
                return true;
            }
        }

        false
    }

    /// Add a domain to the runtime blocklist.
    pub fn block_domain(&self, domain: String) {
        self.custom_blocklist.write().push(domain);
    }

    /// Remove a domain from the runtime blocklist.
    pub fn unblock_domain(&self, domain: &str) -> bool {
        let mut list = self.custom_blocklist.write();
        let lower = domain.to_lowercase();
        let before = list.len();
        list.retain(|d| d.to_lowercase() != lower);
        list.len() < before
    }

    /// Get current statistics.
    pub fn stats(&self) -> DnsFilterStats {
        let counts = self.block_counts.read();
        let mut top: Vec<(String, u64)> = counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        top.truncate(20);

        DnsFilterStats {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            forwarded_queries: self.forwarded_queries.load(Ordering::Relaxed),
            failed_queries: self.failed_queries.load(Ordering::Relaxed),
            top_blocked_domains: top,
        }
    }

    /// Handle a single DNS query: check, block, or forward.
    async fn handle_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        let domain = parse_query_domain(query)?;
        self.total_queries.fetch_add(1, Ordering::Relaxed);

        if self.should_block(&domain) {
            self.blocked_queries.fetch_add(1, Ordering::Relaxed);
            *self.block_counts.write().entry(domain).or_insert(0) += 1;
            return build_sinkhole_response(query);
        }

        // Forward to upstream
        match self.forward_query(query).await {
            Ok(response) => {
                self.forwarded_queries.fetch_add(1, Ordering::Relaxed);
                Some(response)
            }
            Err(_) => {
                self.failed_queries.fetch_add(1, Ordering::Relaxed);
                // Return NXDOMAIN on upstream failure
                build_nxdomain_response(query)
            }
        }
    }

    /// Forward a DNS query to the upstream resolver.
    async fn forward_query(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let upstream: SocketAddr = self
            .config
            .upstream_dns
            .parse()
            .map_err(|e| format!("invalid upstream DNS: {}", e))?;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("failed to bind UDP socket: {}", e))?;

        socket
            .send_to(query, upstream)
            .await
            .map_err(|e| format!("failed to send to upstream: {}", e))?;

        let mut buf = vec![0u8; self.config.max_packet_size];
        let timeout =
            std::time::Duration::from_millis(self.config.upstream_timeout_ms);

        match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Ok(buf[..len].to_vec()),
            Ok(Err(e)) => Err(format!("recv error: {}", e)),
            Err(_) => Err("upstream DNS timeout".to_string()),
        }
    }

    /// Start the DNS filter proxy. Returns a JoinHandle and a detection sender
    /// for blocked domain alerts.
    pub fn start(
        self: Arc<Self>,
        detection_tx: tokio::sync::mpsc::UnboundedSender<ScanResult>,
    ) -> tokio::task::JoinHandle<()> {
        let running = Arc::clone(&self.running);
        let listen_addr = self.config.listen_addr.clone();
        let log_all = self.config.log_all_queries;

        tokio::spawn(async move {
            let socket = match UdpSocket::bind(&listen_addr).await {
                Ok(s) => {
                    tracing::info!(addr = %listen_addr, "DNS filter proxy started");
                    Arc::new(s)
                }
                Err(e) => {
                    tracing::error!(error = %e, addr = %listen_addr, "Failed to start DNS filter");
                    return;
                }
            };

            let mut buf = vec![0u8; 4096];

            while running.load(Ordering::Relaxed) {
                let recv_result = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    socket.recv_from(&mut buf),
                )
                .await;

                let (len, client_addr) = match recv_result {
                    Ok(Ok((len, addr))) => (len, addr),
                    Ok(Err(e)) => {
                        tracing::debug!(error = %e, "DNS recv error");
                        continue;
                    }
                    Err(_) => continue, // Timeout, check running flag
                };

                let query = buf[..len].to_vec();
                let domain = parse_query_domain(&query).unwrap_or_default();

                let blocked = self.should_block(&domain);

                if blocked {
                    // Generate detection alert
                    let result = ScanResult::new(
                        "dns_filter",
                        &domain,
                        Severity::High,
                        DetectionCategory::NetworkAnomaly {
                            connection: format!("dns:{}", domain),
                        },
                        format!(
                            "DNS query blocked — {} is a known malicious domain",
                            domain
                        ),
                        0.95,
                        RecommendedAction::BlockConnection {
                            addr: domain.clone(),
                        },
                    );
                    let _ = detection_tx.send(result);
                } else if log_all && !domain.is_empty() {
                    tracing::debug!(domain = %domain, "DNS query forwarded");
                }

                // Handle the query (block or forward)
                let filter = Arc::clone(&self);
                let sock = Arc::clone(&socket);
                tokio::spawn(async move {
                    if let Some(response) = filter.handle_query(&query).await {
                        let _ = sock.send_to(&response, client_addr).await;
                    }
                });
            }

            tracing::info!("DNS filter proxy stopped");
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::threat_intel::{ThreatIntelConfig, ThreatIntelDB};

    fn test_threat_intel() -> Arc<ThreatIntelDB> {
        let config = ThreatIntelConfig::new(std::env::temp_dir().join("nexus-dns-test"));
        Arc::new(ThreatIntelDB::new(config))
    }

    fn test_filter() -> DnsFilter {
        let ti = test_threat_intel();
        let mut config = DnsFilterConfig::default();
        config.custom_blocklist = vec![
            "evil.example.com".to_string(),
            "malware-c2.net".to_string(),
        ];
        DnsFilter::new(config, ti)
    }

    #[test]
    fn parse_simple_domain() {
        // Build a minimal DNS query for "www.google.com"
        let mut packet = vec![0u8; 12]; // Header (all zeros)
        packet[4] = 0; packet[5] = 1; // QD count = 1

        // www.google.com
        packet.push(3); packet.extend_from_slice(b"www");
        packet.push(6); packet.extend_from_slice(b"google");
        packet.push(3); packet.extend_from_slice(b"com");
        packet.push(0); // End of name
        packet.extend_from_slice(&[0, 1, 0, 1]); // Type A, Class IN

        let domain = parse_query_domain(&packet).unwrap();
        assert_eq!(domain, "www.google.com");
    }

    #[test]
    fn parse_single_label() {
        let mut packet = vec![0u8; 12];
        packet[5] = 1;
        packet.push(9); packet.extend_from_slice(b"localhost");
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0, 1]);

        let domain = parse_query_domain(&packet).unwrap();
        assert_eq!(domain, "localhost");
    }

    #[test]
    fn parse_too_short() {
        assert!(parse_query_domain(&[0; 5]).is_none());
    }

    #[test]
    fn parse_empty_name() {
        let mut packet = vec![0u8; 12];
        packet.push(0); // Empty name
        assert!(parse_query_domain(&packet).is_none());
    }

    #[test]
    fn block_custom_domain() {
        let filter = test_filter();
        assert!(filter.should_block("evil.example.com"));
        assert!(filter.should_block("sub.evil.example.com"));
        assert!(filter.should_block("malware-c2.net"));
    }

    #[test]
    fn allow_clean_domain() {
        let filter = test_filter();
        assert!(!filter.should_block("google.com"));
        assert!(!filter.should_block("github.com"));
        assert!(!filter.should_block("rust-lang.org"));
    }

    #[test]
    fn whitelist_overrides_block() {
        let ti = test_threat_intel();
        let mut config = DnsFilterConfig::default();
        config.custom_blocklist = vec!["example.com".to_string()];
        config.whitelist = vec!["safe.example.com".to_string()];
        let filter = DnsFilter::new(config, ti);

        assert!(filter.should_block("example.com"));
        assert!(filter.should_block("evil.example.com"));
        assert!(!filter.should_block("safe.example.com"));
    }

    #[test]
    fn block_threat_intel_domain() {
        let ti = test_threat_intel();
        // ThreatIntelDB seeds with malicious.example.com, etc.
        ti.add_malicious_domain("c2-server.bad.com".to_string());

        let config = DnsFilterConfig::default();
        let filter = DnsFilter::new(config, ti);

        assert!(filter.should_block("c2-server.bad.com"));
    }

    #[test]
    fn runtime_block_unblock() {
        let filter = test_filter();
        assert!(!filter.should_block("newbad.com"));

        filter.block_domain("newbad.com".to_string());
        assert!(filter.should_block("newbad.com"));
        assert!(filter.should_block("sub.newbad.com"));

        filter.unblock_domain("newbad.com");
        assert!(!filter.should_block("newbad.com"));
    }

    #[test]
    fn nxdomain_response() {
        let mut query = vec![0xAB, 0xCD]; // Transaction ID
        query.extend_from_slice(&[0x01, 0x00]); // Standard query, RD=1
        query.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1

        // test.com
        query.push(4); query.extend_from_slice(b"test");
        query.push(3); query.extend_from_slice(b"com");
        query.push(0);
        query.extend_from_slice(&[0, 1, 0, 1]);

        let response = build_nxdomain_response(&query).unwrap();
        assert_eq!(response[0], 0xAB); // Same transaction ID
        assert_eq!(response[1], 0xCD);
        assert!(response[2] & 0x80 != 0); // QR bit set (response)
        assert_eq!(response[3] & 0x0F, 3); // RCODE = NXDOMAIN
    }

    #[test]
    fn sinkhole_response() {
        let mut query = vec![0x12, 0x34]; // Transaction ID
        query.extend_from_slice(&[0x01, 0x00]); // Standard query
        query.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1

        query.push(4); query.extend_from_slice(b"evil");
        query.push(3); query.extend_from_slice(b"com");
        query.push(0);
        query.extend_from_slice(&[0, 1, 0, 1]);

        let response = build_sinkhole_response(&query).unwrap();
        assert_eq!(response[0], 0x12); // Same transaction ID
        assert_eq!(response[1], 0x34);
        assert!(response[2] & 0x80 != 0); // QR bit set
        assert_eq!(response[3] & 0x0F, 0); // RCODE = 0 (no error)
        // AN count = 1
        assert_eq!(response[6], 0);
        assert_eq!(response[7], 1);
    }

    #[test]
    fn stats_tracking() {
        let filter = test_filter();
        assert_eq!(filter.stats().total_queries, 0);
        assert_eq!(filter.stats().blocked_queries, 0);
    }

    #[test]
    fn case_insensitive_blocking() {
        let filter = test_filter();
        assert!(filter.should_block("Evil.Example.COM"));
        assert!(filter.should_block("MALWARE-C2.NET"));
    }

    #[test]
    fn config_defaults() {
        let config = DnsFilterConfig::default();
        assert_eq!(config.listen_addr, "127.0.0.1:5353");
        assert_eq!(config.upstream_dns, "8.8.8.8:53");
        assert_eq!(config.upstream_timeout_ms, 3000);
        assert!(!config.log_all_queries);
    }
}