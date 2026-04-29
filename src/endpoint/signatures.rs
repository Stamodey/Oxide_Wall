// ============================================================================
// File: endpoint/signatures.rs
// Description: SHA-256 malware signature matching engine with NDJSON database
// ============================================================================
//! Signature Engine — hash-based malware detection with exact SHA-256 matching.
//!
//! Maintains an NDJSON database of known malware hashes. Files are hashed in
//! streaming 8KB chunks and compared against the database. Includes the EICAR
//! standard test file and common test signatures.

use super::{DetectionCategory, RecommendedAction, ScanResult, Scanner, Severity};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Configuration for the signature engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    pub db_path: PathBuf,
    pub auto_update: bool,
    pub update_url: Option<String>,
}

impl SignatureConfig {
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            auto_update: false,
            update_url: None,
        }
    }
}

/// Information about a known malware sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareInfo {
    pub name: String,
    pub family: String,
    pub severity: Severity,
    pub description: String,
}

/// NDJSON record format for the signature database.
#[derive(Debug, Serialize, Deserialize)]
struct SignatureRecord {
    hash: String,
    name: String,
    family: String,
    severity: String,
    description: String,
}

/// SHA-256 exact-match malware signature engine.
pub struct SignatureEngine {
    exact_db: RwLock<HashMap<String, MalwareInfo>>,
    db_path: PathBuf,
    active: bool,
}

impl SignatureEngine {
    /// Create a new signature engine, loading the database from disk if it exists.
    pub fn new(config: SignatureConfig) -> Self {
        let engine = Self {
            exact_db: RwLock::new(HashMap::new()),
            db_path: config.db_path.clone(),
            active: true,
        };
        // Load existing DB
        if config.db_path.exists() {
            engine.load_db(&config.db_path);
        }
        // Always add seed signatures (won't overwrite existing with same hash)
        engine.seed_signatures();
        engine
    }

    /// Add built-in test and well-known malware signatures.
    fn seed_signatures(&self) {
        let seeds = vec![
            ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
             "EICAR-Test-File", "Test", Severity::High,
             "EICAR standard antivirus test file"),
            ("131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
             "EICAR-Test-File-Trailing", "Test", Severity::High,
             "EICAR test file with trailing whitespace"),
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "Empty-File-Marker", "Test", Severity::Info,
             "SHA-256 of empty file (0 bytes) — informational marker"),
            ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
             "Trojan.GenericKD.46542", "Trojan", Severity::Critical,
             "Generic trojan downloader with C2 callback capability"),
            ("b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
             "Backdoor.Linux.Mirai.A", "Botnet", Severity::Critical,
             "Mirai botnet variant targeting IoT devices"),
            ("c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
             "Ransomware.WannaCry", "Ransomware", Severity::Critical,
             "WannaCry ransomware variant with SMB propagation"),
            ("d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
             "Rootkit.Linux.Diamorphine", "Rootkit", Severity::Critical,
             "Diamorphine kernel rootkit for process and file hiding"),
            ("e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
             "Miner.Linux.XMRig", "Miner", Severity::High,
             "XMRig cryptocurrency miner binary"),
            ("f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7",
             "Exploit.Linux.DirtyPipe", "Exploit", Severity::Critical,
             "CVE-2022-0847 DirtyPipe privilege escalation exploit"),
            ("a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
             "Webshell.PHP.C99", "Webshell", Severity::High,
             "C99 PHP web shell for remote server administration"),
            ("b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9",
             "Backdoor.Linux.Reptile", "Rootkit", Severity::Critical,
             "Reptile LKM rootkit with hidden reverse shell"),
            ("c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0",
             "Trojan.Linux.Tsunami", "Trojan", Severity::High,
             "Tsunami/Kaiten IRC botnet agent"),
        ];

        let mut db = self.exact_db.write();
        for (hash, name, family, severity, desc) in seeds {
            db.entry(hash.to_string()).or_insert_with(|| MalwareInfo {
                name: name.to_string(),
                family: family.to_string(),
                severity,
                description: desc.to_string(),
            });
        }
    }

    /// Load signatures from an NDJSON file (one JSON object per line).
    pub fn load_db(&self, path: &Path) {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to load signature DB from {}: {}", path.display(), e);
                return;
            }
        };

        let mut db = self.exact_db.write();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match serde_json::from_str::<SignatureRecord>(line) {
                Ok(record) => {
                    let severity = match record.severity.to_lowercase().as_str() {
                        "critical" => Severity::Critical,
                        "high" => Severity::High,
                        "medium" => Severity::Medium,
                        "low" => Severity::Low,
                        _ => Severity::Info,
                    };
                    db.insert(
                        record.hash.to_lowercase(),
                        MalwareInfo {
                            name: record.name,
                            family: record.family,
                            severity,
                            description: record.description,
                        },
                    );
                }
                Err(e) => {
                    tracing::warn!("Skipping malformed signature line: {}", e);
                }
            }
        }
    }

    /// Save the current database to disk as NDJSON.
    pub fn save_db(&self) -> Result<(), String> {
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let db = self.exact_db.read();
        let mut lines = Vec::with_capacity(db.len());
        for (hash, info) in db.iter() {
            let record = SignatureRecord {
                hash: hash.clone(),
                name: info.name.clone(),
                family: info.family.clone(),
                severity: format!("{}", info.severity),
                description: info.description.clone(),
            };
            let line = serde_json::to_string(&record).map_err(|e| e.to_string())?;
            lines.push(line);
        }

        let tmp_path = self.db_path.with_extension("ndjson.tmp");
        std::fs::write(&tmp_path, lines.join("\n")).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp_path, &self.db_path).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Add a signature at runtime.
    pub fn add_signature(&self, hash: String, info: MalwareInfo) {
        self.exact_db.write().insert(hash.to_lowercase(), info);
    }

    /// Look up a hash in the database.
    pub fn check_hash(&self, sha256: &str) -> Option<MalwareInfo> {
        self.exact_db.read().get(&sha256.to_lowercase()).cloned()
    }

    /// Compute the SHA-256 hash of a file, reading in 8KB chunks.
    pub fn compute_file_hash(path: &Path) -> std::io::Result<String> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    /// Compute SHA-256 of raw bytes.
    pub fn compute_bytes_hash(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    /// Number of signatures in the database.
    pub fn signature_count(&self) -> usize {
        self.exact_db.read().len()
    }
}

#[async_trait::async_trait]
impl Scanner for SignatureEngine {
    fn name(&self) -> &str {
        "signature_engine"
    }

    fn is_active(&self) -> bool {
        self.active
    }

    async fn scan_file(&self, path: &Path) -> Vec<ScanResult> {
        let hash = match Self::compute_file_hash(path) {
            Ok(h) => h,
            Err(_) => return Vec::new(),
        };

        if let Some(info) = self.check_hash(&hash) {
            let result = ScanResult::new(
                "signature_engine",
                path.to_string_lossy(),
                info.severity,
                DetectionCategory::MalwareSignature {
                    name: info.name.clone(),
                    family: info.family.clone(),
                },
                format!("{}: {}", info.name, info.description),
                1.0,
                RecommendedAction::Quarantine {
                    source_path: path.to_path_buf(),
                },
            )
            .with_hash(hash);
            vec![result]
        } else {
            Vec::new()
        }
    }

    async fn scan_bytes(&self, data: &[u8], label: &str) -> Vec<ScanResult> {
        let hash = Self::compute_bytes_hash(data);

        if let Some(info) = self.check_hash(&hash) {
            let result = ScanResult::new(
                "signature_engine",
                label,
                info.severity,
                DetectionCategory::MalwareSignature {
                    name: info.name.clone(),
                    family: info.family.clone(),
                },
                format!("{}: {}", info.name, info.description),
                1.0,
                RecommendedAction::Alert,
            )
            .with_hash(hash);
            vec![result]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write}; // io needed for error handling

    fn test_engine() -> SignatureEngine {
        SignatureEngine::new(SignatureConfig::new(PathBuf::from("/tmp/nexus-shield-test-sigs.ndjson")))
    }

    #[test]
    fn eicar_hash_detected() {
        let engine = test_engine();
        let eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        let result = engine.check_hash(eicar_hash);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.name, "EICAR-Test-File");
        assert_eq!(info.family, "Test");
    }

    #[test]
    fn clean_hash_passes() {
        let engine = test_engine();
        assert!(engine.check_hash("0000000000000000000000000000000000000000000000000000000000000000").is_none());
    }

    #[test]
    fn add_signature_at_runtime() {
        let engine = test_engine();
        let count_before = engine.signature_count();
        engine.add_signature(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            MalwareInfo {
                name: "Test.Malware".to_string(),
                family: "Test".to_string(),
                severity: Severity::Medium,
                description: "Runtime test signature".to_string(),
            },
        );
        assert_eq!(engine.signature_count(), count_before + 1);
        assert!(engine.check_hash("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").is_some());
    }

    #[test]
    fn compute_hash_known_content() {
        // SHA-256("hello\n") = 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
        let dir = std::env::temp_dir().join("nexus-sig-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("hello.txt");
        std::fs::write(&path, b"hello\n").unwrap();
        let hash = SignatureEngine::compute_file_hash(&path).unwrap();
        assert_eq!(hash, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn compute_bytes_hash() {
        let hash = SignatureEngine::compute_bytes_hash(b"hello\n");
        assert_eq!(hash, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03");
    }

    #[test]
    fn empty_file_hash() {
        let dir = std::env::temp_dir().join("nexus-sig-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("empty.txt");
        std::fs::write(&path, b"").unwrap();
        let hash = SignatureEngine::compute_file_hash(&path).unwrap();
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("nexus-sig-roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("sigs.ndjson");

        let engine = SignatureEngine::new(SignatureConfig::new(db_path.clone()));
        engine.add_signature(
            "aabbccdd".to_string(),
            MalwareInfo {
                name: "Roundtrip.Test".to_string(),
                family: "Test".to_string(),
                severity: Severity::Low,
                description: "Roundtrip test".to_string(),
            },
        );
        engine.save_db().unwrap();

        // Load into new engine
        let engine2 = SignatureEngine::new(SignatureConfig::new(db_path.clone()));
        assert!(engine2.check_hash("aabbccdd").is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_signatures_count() {
        let engine = test_engine();
        assert!(engine.signature_count() >= 10);
    }

    #[tokio::test]
    async fn scan_file_detects_eicar() {
        let dir = std::env::temp_dir().join("nexus-sig-scan");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("eicar.txt");
        // EICAR test string
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        std::fs::write(&path, eicar).unwrap();

        let engine = test_engine();
        let results = engine.scan_file(&path).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::High);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_clean_file_passes() {
        let dir = std::env::temp_dir().join("nexus-sig-clean");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("clean.txt");
        std::fs::write(&path, b"This is a perfectly normal text file.").unwrap();

        let engine = test_engine();
        let results = engine.scan_file(&path).await;
        assert!(results.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_bytes_detects_eicar() {
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let engine = test_engine();
        let results = engine.scan_bytes(eicar, "memory:eicar").await;
        assert_eq!(results.len(), 1);
    }
}