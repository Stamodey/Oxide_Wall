// ============================================================================
// File: endpoint/threat_intel.rs
// Description: Threat intelligence database — IOC matching for IPs, domains, hashes
// ============================================================================
//! Threat Intelligence DB — maintains lists of known-malicious IPs, domains,
//! and file hashes for indicator-of-compromise (IOC) matching.

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Configuration for the threat intelligence database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    pub db_dir: PathBuf,
    pub update_interval_hours: u32,
    pub enable_community_feeds: bool,
}

impl ThreatIntelConfig {
    pub fn new(db_dir: PathBuf) -> Self {
        Self {
            db_dir,
            update_interval_hours: 24,
            enable_community_feeds: true,
        }
    }
}

/// Statistics about the threat intelligence database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelStats {
    pub malicious_ips: usize,
    pub malicious_domains: usize,
    pub ioc_hashes: usize,
    pub last_update: Option<DateTime<Utc>>,
}

/// Threat intelligence database for IOC matching.
pub struct ThreatIntelDB {
    malicious_ips: RwLock<HashSet<String>>,
    malicious_domains: RwLock<HashSet<String>>,
    ioc_hashes: RwLock<HashSet<String>>,
    last_update: RwLock<Option<DateTime<Utc>>>,
    config: ThreatIntelConfig,
}

impl ThreatIntelDB {
    /// Create a new threat intelligence database, loading from disk if available.
    pub fn new(config: ThreatIntelConfig) -> Self {
        let db = Self {
            malicious_ips: RwLock::new(HashSet::new()),
            malicious_domains: RwLock::new(HashSet::new()),
            ioc_hashes: RwLock::new(HashSet::new()),
            last_update: RwLock::new(None),
            config: config.clone(),
        };

        // Load from disk
        db.load_from_disk();

        // Add seed data
        db.seed_data();

        db
    }

    /// Add built-in known-bad indicators for testing and baseline detection.
    fn seed_data(&self) {
        // RFC 5737 test IPs (198.51.100.0/24 — documentation range, safe to use)
        let test_ips = [
            "198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4",
            "198.51.100.5", "198.51.100.6", "198.51.100.7", "198.51.100.8",
            "198.51.100.9", "198.51.100.10", "198.51.100.11", "198.51.100.12",
            "198.51.100.13", "198.51.100.14", "198.51.100.15", "198.51.100.16",
            "198.51.100.17", "198.51.100.18", "198.51.100.19", "198.51.100.20",
        ];

        let test_domains = [
            "malware-c2.example.com",
            "phishing-kit.example.net",
            "ransomware-payment.example.org",
            "cryptominer-pool.example.com",
            "botnet-controller.example.net",
            "exploit-kit.example.org",
            "dropper-server.example.com",
            "data-exfil.example.net",
            "keylogger-c2.example.org",
            "rat-controller.example.com",
            "ddos-botnet.example.net",
            "spambot-relay.example.org",
            "credential-harvest.example.com",
            "watering-hole.example.net",
            "supply-chain-attack.example.org",
            "apt-infrastructure.example.com",
            "zero-day-host.example.net",
            "rootkit-update.example.org",
            "backdoor-c2.example.com",
            "fileless-staging.example.net",
        ];

        let test_hashes = [
            // EICAR test file
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            // Test IOC hashes
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
            "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
            "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
            "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
            "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7",
            "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
            "b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9",
            "c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0",
        ];

        let mut ips = self.malicious_ips.write();
        for ip in &test_ips {
            ips.insert(ip.to_string());
        }

        let mut domains = self.malicious_domains.write();
        for domain in &test_domains {
            domains.insert(domain.to_string());
        }

        let mut hashes = self.ioc_hashes.write();
        for hash in &test_hashes {
            hashes.insert(hash.to_string());
        }

        *self.last_update.write() = Some(Utc::now());
    }

    /// Check if an IP address is known malicious.
    pub fn check_ip(&self, ip: &str) -> bool {
        self.malicious_ips.read().contains(ip)
    }

    /// Check if a domain is known malicious.
    pub fn check_domain(&self, domain: &str) -> bool {
        self.malicious_domains.read().contains(domain)
    }

    /// Check if a file hash is a known IOC.
    pub fn check_hash(&self, sha256: &str) -> bool {
        self.ioc_hashes.read().contains(&sha256.to_lowercase())
    }

    /// Add a malicious IP to the database.
    pub fn add_malicious_ip(&self, ip: String) {
        self.malicious_ips.write().insert(ip);
    }

    /// Add a malicious domain to the database.
    pub fn add_malicious_domain(&self, domain: String) {
        self.malicious_domains.write().insert(domain);
    }

    /// Add an IOC hash to the database.
    pub fn add_ioc_hash(&self, hash: String) {
        self.ioc_hashes.write().insert(hash.to_lowercase());
    }

    /// Load the database from disk (ips.txt, domains.txt, hashes.txt).
    pub fn load_from_disk(&self) {
        let dir = &self.config.db_dir;
        if !dir.exists() {
            return;
        }

        self.load_file(dir.join("ips.txt"), &self.malicious_ips);
        self.load_file(dir.join("domains.txt"), &self.malicious_domains);
        self.load_file(dir.join("hashes.txt"), &self.ioc_hashes);
    }

    fn load_file(&self, path: PathBuf, target: &RwLock<HashSet<String>>) {
        if let Ok(content) = std::fs::read_to_string(&path) {
            let mut set = target.write();
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    set.insert(line.to_string());
                }
            }
        }
    }

    /// Save the database to disk.
    pub fn save_to_disk(&self) -> Result<(), String> {
        let dir = &self.config.db_dir;
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;

        self.save_file(&dir.join("ips.txt"), &self.malicious_ips)?;
        self.save_file(&dir.join("domains.txt"), &self.malicious_domains)?;
        self.save_file(&dir.join("hashes.txt"), &self.ioc_hashes)?;
        Ok(())
    }

    fn save_file(&self, path: &Path, source: &RwLock<HashSet<String>>) -> Result<(), String> {
        let set = source.read();
        let mut lines: Vec<&str> = set.iter().map(|s| s.as_str()).collect();
        lines.sort();
        std::fs::write(path, lines.join("\n")).map_err(|e| e.to_string())
    }

    /// Get database statistics.
    pub fn stats(&self) -> ThreatIntelStats {
        ThreatIntelStats {
            malicious_ips: self.malicious_ips.read().len(),
            malicious_domains: self.malicious_domains.read().len(),
            ioc_hashes: self.ioc_hashes.read().len(),
            last_update: *self.last_update.read(),
        }
    }

    /// Clear all data from the database.
    pub fn clear(&self) {
        self.malicious_ips.write().clear();
        self.malicious_domains.write().clear();
        self.ioc_hashes.write().clear();
        *self.last_update.write() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> ThreatIntelDB {
        ThreatIntelDB::new(ThreatIntelConfig::new(
            std::env::temp_dir().join("nexus-threat-intel-test"),
        ))
    }

    #[test]
    fn seed_ip_present() {
        let db = test_db();
        assert!(db.check_ip("198.51.100.1"));
        assert!(db.check_ip("198.51.100.20"));
        assert!(!db.check_ip("8.8.8.8"));
    }

    #[test]
    fn seed_domain_present() {
        let db = test_db();
        assert!(db.check_domain("malware-c2.example.com"));
        assert!(db.check_domain("phishing-kit.example.net"));
        assert!(!db.check_domain("google.com"));
    }

    #[test]
    fn seed_hash_present() {
        let db = test_db();
        assert!(db.check_hash(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        ));
    }

    #[test]
    fn add_custom_ip() {
        let db = test_db();
        assert!(!db.check_ip("10.0.0.1"));
        db.add_malicious_ip("10.0.0.1".to_string());
        assert!(db.check_ip("10.0.0.1"));
    }

    #[test]
    fn add_custom_domain() {
        let db = test_db();
        db.add_malicious_domain("evil.example.com".to_string());
        assert!(db.check_domain("evil.example.com"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("nexus-ti-rt-{}", uuid::Uuid::new_v4()));
        let config = ThreatIntelConfig::new(dir.clone());

        {
            let db = ThreatIntelDB::new(config.clone());
            db.add_malicious_ip("192.0.2.99".to_string());
            db.add_malicious_domain("custom-evil.example.org".to_string());
            db.add_ioc_hash("abcdef1234567890".to_string());
            db.save_to_disk().unwrap();
        }

        let db2 = ThreatIntelDB::new(config);
        assert!(db2.check_ip("192.0.2.99"));
        assert!(db2.check_domain("custom-evil.example.org"));
        assert!(db2.check_hash("abcdef1234567890"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stats_accurate() {
        let db = test_db();
        let stats = db.stats();
        assert_eq!(stats.malicious_ips, 20);
        assert_eq!(stats.malicious_domains, 20);
        assert!(stats.ioc_hashes >= 10);
        assert!(stats.last_update.is_some());
    }

    #[test]
    fn clear_empties_everything() {
        let db = test_db();
        assert!(db.stats().malicious_ips > 0);
        db.clear();
        assert_eq!(db.stats().malicious_ips, 0);
        assert_eq!(db.stats().malicious_domains, 0);
        assert_eq!(db.stats().ioc_hashes, 0);
    }

    #[test]
    fn hash_check_case_insensitive() {
        let db = test_db();
        assert!(db.check_hash(
            "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"
        ));
    }
}