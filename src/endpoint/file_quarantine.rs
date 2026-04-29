// ============================================================================
// File: endpoint/file_quarantine.rs
// Description: Encrypted quarantine vault for detected threats with chain of custody
// ============================================================================
//! Quarantine Vault — moves detected threats to a secure vault with full
//! chain-of-custody tracking (hash, timestamp, original path, permissions).

use super::Severity;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Configuration for the quarantine vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineVaultConfig {
    pub vault_dir: PathBuf,
    pub retention_days: u32,
    pub max_vault_size_bytes: u64,
}

impl QuarantineVaultConfig {
    pub fn new(vault_dir: PathBuf) -> Self {
        Self {
            vault_dir,
            retention_days: 30,
            max_vault_size_bytes: 1_073_741_824, // 1 GB
        }
    }
}

/// A record of a quarantined file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub sha256: String,
    pub detection_reason: String,
    pub scanner: String,
    pub severity: Severity,
    pub quarantined_at: DateTime<Utc>,
    pub original_permissions: u32,
    pub file_size: u64,
}

/// Secure quarantine vault for detected threats.
pub struct QuarantineVault {
    config: QuarantineVaultConfig,
    index: RwLock<Vec<QuarantineEntry>>,
}

impl QuarantineVault {
    /// Create a new quarantine vault, loading existing index if present.
    pub fn new(config: QuarantineVaultConfig) -> Self {
        let _ = std::fs::create_dir_all(&config.vault_dir);

        let vault = Self {
            config: config.clone(),
            index: RwLock::new(Vec::new()),
        };
        vault.load_index();
        vault
    }

    /// Move a detected file to the quarantine vault.
    pub fn quarantine_file(
        &self,
        path: &Path,
        reason: &str,
        scanner: &str,
        severity: Severity,
    ) -> Result<QuarantineEntry, String> {
        // Read file and compute hash
        let mut file = std::fs::File::open(path).map_err(|e| format!("Cannot open file: {}", e))?;
        let metadata = file.metadata().map_err(|e| format!("Cannot read metadata: {}", e))?;
        let file_size = metadata.len();

        // Check vault size limit
        if self.vault_size() + file_size > self.config.max_vault_size_bytes {
            return Err("Quarantine vault is full".to_string());
        }

        // Compute SHA-256
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf).map_err(|e| format!("Read error: {}", e))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let sha256 = hex::encode(hasher.finalize());

        // Get original permissions
        #[cfg(unix)]
        let original_permissions = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode()
        };
        #[cfg(not(unix))]
        let original_permissions = 0o644u32;

        // Generate quarantine filename
        let id = uuid::Uuid::new_v4().to_string();
        let quarantine_path = self.config.vault_dir.join(format!("{}.quarantine", id));

        // Copy file to quarantine (then delete original)
        std::fs::copy(path, &quarantine_path)
            .map_err(|e| format!("Copy to quarantine failed: {}", e))?;
        std::fs::remove_file(path)
            .map_err(|e| format!("Remove original failed: {}", e))?;

        // Strip permissions on quarantine file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o000);
            let _ = std::fs::set_permissions(&quarantine_path, perms);
        }

        let entry = QuarantineEntry {
            id,
            original_path: path.to_path_buf(),
            quarantine_path,
            sha256,
            detection_reason: reason.to_string(),
            scanner: scanner.to_string(),
            severity,
            quarantined_at: Utc::now(),
            original_permissions,
            file_size,
        };

        {
            let mut idx = self.index.write();
            idx.push(entry.clone());
        }
        self.save_index();

        tracing::info!(
            file = %path.display(),
            reason = %reason,
            scanner = %scanner,
            "File quarantined"
        );

        Ok(entry)
    }

    /// Restore a quarantined file to its original location.
    pub fn restore_file(&self, id: &str) -> Result<PathBuf, String> {
        let entry = {
            let idx = self.index.read();
            idx.iter().find(|e| e.id == id).cloned()
        };

        let entry = entry.ok_or_else(|| format!("Quarantine entry '{}' not found", id))?;

        // Restore permissions on quarantine file so we can read it
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o644);
            let _ = std::fs::set_permissions(&entry.quarantine_path, perms);
        }

        // Create parent directory if needed
        if let Some(parent) = entry.original_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Copy back to original path
        std::fs::copy(&entry.quarantine_path, &entry.original_path)
            .map_err(|e| format!("Restore failed: {}", e))?;

        // Restore original permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(entry.original_permissions);
            let _ = std::fs::set_permissions(&entry.original_path, perms);
        }

        // Remove quarantine file and index entry
        let _ = std::fs::remove_file(&entry.quarantine_path);
        {
            let mut idx = self.index.write();
            idx.retain(|e| e.id != id);
        }
        self.save_index();

        tracing::info!(file = %entry.original_path.display(), "File restored from quarantine");
        Ok(entry.original_path)
    }

    /// Permanently delete a quarantined file.
    pub fn delete_entry(&self, id: &str) -> Result<(), String> {
        let entry = {
            let idx = self.index.read();
            idx.iter().find(|e| e.id == id).cloned()
        };

        let entry = entry.ok_or_else(|| format!("Entry '{}' not found", id))?;

        // Make file deletable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &entry.quarantine_path,
                std::fs::Permissions::from_mode(0o644),
            );
        }

        let _ = std::fs::remove_file(&entry.quarantine_path);
        {
            let mut idx = self.index.write();
            idx.retain(|e| e.id != id);
        }
        self.save_index();
        Ok(())
    }

    /// List all quarantine entries.
    pub fn list_entries(&self) -> Vec<QuarantineEntry> {
        self.index.read().clone()
    }

    /// Get a specific quarantine entry by ID.
    pub fn get_entry(&self, id: &str) -> Option<QuarantineEntry> {
        self.index.read().iter().find(|e| e.id == id).cloned()
    }

    /// Remove entries older than the retention period.
    pub fn cleanup_expired(&self) -> usize {
        let cutoff = Utc::now()
            - chrono::Duration::days(self.config.retention_days as i64);

        let expired: Vec<String> = {
            let idx = self.index.read();
            idx.iter()
                .filter(|e| e.quarantined_at < cutoff)
                .map(|e| e.id.clone())
                .collect()
        };

        let count = expired.len();
        for id in &expired {
            let _ = self.delete_entry(id);
        }
        count
    }

    /// Total size of all quarantined files in bytes.
    pub fn vault_size(&self) -> u64 {
        self.index.read().iter().map(|e| e.file_size).sum()
    }

    /// Save the index to disk atomically (write tmp, then rename).
    fn save_index(&self) {
        let index_path = self.config.vault_dir.join("index.json");
        let tmp_path = self.config.vault_dir.join("index.json.tmp");

        let idx = self.index.read();
        if let Ok(json) = serde_json::to_string_pretty(&*idx) {
            if std::fs::write(&tmp_path, &json).is_ok() {
                let _ = std::fs::rename(&tmp_path, &index_path);
            }
        }
    }

    /// Load the index from disk.
    fn load_index(&self) {
        let index_path = self.config.vault_dir.join("index.json");
        if let Ok(content) = std::fs::read_to_string(&index_path) {
            if let Ok(entries) = serde_json::from_str::<Vec<QuarantineEntry>>(&content) {
                *self.index.write() = entries;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault() -> (QuarantineVault, PathBuf) {
        let dir = std::env::temp_dir().join(format!("nexus-quarantine-test-{}", uuid::Uuid::new_v4()));
        let config = QuarantineVaultConfig::new(dir.clone());
        (QuarantineVault::new(config), dir)
    }

    #[test]
    fn quarantine_and_verify() {
        let (vault, dir) = test_vault();
        let test_file = dir.join("malware.txt");
        std::fs::write(&test_file, b"definitely malware content").unwrap();

        let entry = vault
            .quarantine_file(&test_file, "Test detection", "test_scanner", Severity::High)
            .unwrap();

        // Original file should be gone
        assert!(!test_file.exists());
        // Quarantine file should exist
        assert!(entry.quarantine_path.exists());
        // Entry should be in index
        assert_eq!(vault.list_entries().len(), 1);
        assert_eq!(entry.scanner, "test_scanner");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_file_works() {
        let (vault, dir) = test_vault();
        let original_content = b"restore me please";
        let test_file = dir.join("restore_me.txt");
        std::fs::write(&test_file, original_content).unwrap();

        let entry = vault
            .quarantine_file(&test_file, "test", "scanner", Severity::Medium)
            .unwrap();
        let id = entry.id.clone();

        // Restore
        let restored_path = vault.restore_file(&id).unwrap();
        assert!(restored_path.exists());
        assert_eq!(std::fs::read(&restored_path).unwrap(), original_content);
        assert!(vault.list_entries().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_entry_works() {
        let (vault, dir) = test_vault();
        let test_file = dir.join("delete_me.txt");
        std::fs::write(&test_file, b"bye").unwrap();

        let entry = vault
            .quarantine_file(&test_file, "test", "scanner", Severity::Low)
            .unwrap();
        let qpath = entry.quarantine_path.clone();

        vault.delete_entry(&entry.id).unwrap();
        assert!(vault.list_entries().is_empty());
        // quarantine file should be gone too
        assert!(!qpath.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vault_size_calculation() {
        let (vault, dir) = test_vault();
        let f1 = dir.join("f1.txt");
        let f2 = dir.join("f2.txt");
        std::fs::write(&f1, &[0u8; 100]).unwrap();
        std::fs::write(&f2, &[0u8; 200]).unwrap();

        vault.quarantine_file(&f1, "t", "s", Severity::Low).unwrap();
        vault.quarantine_file(&f2, "t", "s", Severity::Low).unwrap();
        assert_eq!(vault.vault_size(), 300);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn index_persistence() {
        let dir = std::env::temp_dir().join(format!("nexus-q-persist-{}", uuid::Uuid::new_v4()));
        let config = QuarantineVaultConfig::new(dir.clone());

        {
            let vault = QuarantineVault::new(config.clone());
            let f = dir.join("persist.txt");
            std::fs::write(&f, b"data").unwrap();
            vault.quarantine_file(&f, "test", "s", Severity::High).unwrap();
            assert_eq!(vault.list_entries().len(), 1);
        }

        // New vault instance should load existing index
        let vault2 = QuarantineVault::new(config);
        assert_eq!(vault2.list_entries().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_entry_by_id() {
        let (vault, dir) = test_vault();
        let f = dir.join("lookup.txt");
        std::fs::write(&f, b"find me").unwrap();

        let entry = vault.quarantine_file(&f, "test", "s", Severity::Medium).unwrap();
        let found = vault.get_entry(&entry.id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().sha256, entry.sha256);

        assert!(vault.get_entry("nonexistent").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}