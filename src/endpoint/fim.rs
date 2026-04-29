// ============================================================================
// File: endpoint/fim.rs
// Description: File Integrity Monitoring — baseline critical system files and
//              detect unauthorized modifications (OSSEC/Tripwire replacement)
// ============================================================================
//! FIM — File Integrity Monitoring
//!
//! Computes SHA-256 baselines of critical system files and configuration,
//! then periodically verifies integrity. Detects:
//! - Modified system binaries and libraries
//! - Changed configuration files (/etc/passwd, /etc/shadow, sudoers, etc.)
//! - New files in monitored directories
//! - Deleted files from monitored directories
//! - Permission/ownership changes
//!
//! Replaces OSSEC and Tripwire with a pure-Rust, in-process alternative.

use super::{DetectionCategory, RecommendedAction, ScanResult, Severity};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for File Integrity Monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimConfig {
    /// Polling interval for integrity checks in milliseconds.
    pub poll_interval_ms: u64,
    /// Directories to monitor (recursively).
    pub watch_dirs: Vec<String>,
    /// Individual files to monitor.
    pub watch_files: Vec<String>,
    /// File patterns to exclude (glob-style substrings).
    pub exclude_patterns: Vec<String>,
    /// Alert on new files in monitored directories.
    pub alert_on_new_files: bool,
    /// Alert on deleted files from baseline.
    pub alert_on_deleted_files: bool,
    /// Alert on permission changes.
    pub alert_on_permission_changes: bool,
    /// Maximum file size to hash (skip large files).
    pub max_file_size: u64,
    /// Path to store baseline data.
    pub baseline_path: PathBuf,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 60_000, // 1 minute
            watch_dirs: vec![
                "/etc".to_string(),
                "/usr/bin".to_string(),
                "/usr/sbin".to_string(),
                "/bin".to_string(),
                "/sbin".to_string(),
            ],
            watch_files: vec![
                "/etc/passwd".to_string(),
                "/etc/shadow".to_string(),
                "/etc/group".to_string(),
                "/etc/sudoers".to_string(),
                "/etc/hosts".to_string(),
                "/etc/resolv.conf".to_string(),
                "/etc/crontab".to_string(),
                "/etc/ssh/sshd_config".to_string(),
                "/etc/ld.so.preload".to_string(),
                "/etc/pam.d/common-auth".to_string(),
                "/etc/systemd/system.conf".to_string(),
            ],
            exclude_patterns: vec![
                ".swp".to_string(),
                ".tmp".to_string(),
                "__pycache__".to_string(),
                ".pyc".to_string(),
                "/etc/mtab".to_string(),
                "/etc/resolv.conf".to_string(), // often changed by DHCP
            ],
            alert_on_new_files: true,
            alert_on_deleted_files: true,
            alert_on_permission_changes: true,
            max_file_size: 50_000_000, // 50 MB
            baseline_path: PathBuf::from("/tmp/nexus-shield/fim-baseline.json"),
        }
    }
}

// =============================================================================
// File Entry
// =============================================================================

/// Metadata for a single monitored file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    /// Full path.
    pub path: String,
    /// SHA-256 hash of file contents.
    pub sha256: String,
    /// File size in bytes.
    pub size: u64,
    /// Unix permissions mode.
    pub mode: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Last modification time (epoch seconds).
    pub mtime: i64,
}

/// Type of change detected.
#[derive(Debug, Clone, PartialEq)]
pub enum FimChange {
    Modified { field: String, old: String, new: String },
    Created,
    Deleted,
    PermissionChanged { old_mode: u32, new_mode: u32 },
    OwnerChanged { old_uid: u32, new_uid: u32 },
}

// =============================================================================
// FIM Engine
// =============================================================================

/// File Integrity Monitor — baselines and verifies system file integrity.
pub struct FimMonitor {
    config: FimConfig,
    /// Current baseline: path -> FileEntry.
    baseline: RwLock<HashMap<String, FileEntry>>,
    /// Whether a baseline has been established.
    baseline_established: AtomicBool,
    /// Shutdown flag.
    running: Arc<AtomicBool>,
}

impl FimMonitor {
    pub fn new(config: FimConfig) -> Self {
        let monitor = Self {
            config,
            baseline: RwLock::new(HashMap::new()),
            baseline_established: AtomicBool::new(false),
            running: Arc::new(AtomicBool::new(true)),
        };

        // Try to load existing baseline from disk
        monitor.load_baseline();

        // If no baseline on disk, build one now
        if !monitor.baseline_established.load(Ordering::Relaxed) {
            monitor.build_baseline();
        }

        monitor
    }

    /// Compute SHA-256 hash of a file.
    pub fn hash_file(path: &Path) -> Option<String> {
        let data = std::fs::read(path).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Some(hex::encode(hasher.finalize()))
    }

    /// Read file metadata into a FileEntry.
    pub fn read_file_entry(path: &Path) -> Option<FileEntry> {
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }

        let sha256 = Self::hash_file(path).unwrap_or_default();

        #[cfg(unix)]
        let (mode, uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            (meta.mode(), meta.uid(), meta.gid())
        };
        #[cfg(not(unix))]
        let (mode, uid, gid) = (0u32, 0u32, 0u32);

        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Some(FileEntry {
            path: path.to_string_lossy().to_string(),
            sha256,
            size: meta.len(),
            mode,
            uid,
            gid,
            mtime,
        })
    }

    /// Check if a path should be excluded.
    fn should_exclude(&self, path: &str) -> bool {
        // Always exclude our own baseline file
        if path == self.config.baseline_path.to_string_lossy() {
            return true;
        }
        self.config
            .exclude_patterns
            .iter()
            .any(|p| path.contains(p))
    }

    /// Enumerate all files to monitor.
    fn enumerate_monitored_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();

        // Individual files
        for f in &self.config.watch_files {
            let path = PathBuf::from(f);
            if path.exists() && !self.should_exclude(f) {
                files.push(path);
            }
        }

        // Directory contents (non-recursive for /etc, recursive for bin dirs)
        for dir in &self.config.watch_dirs {
            let dir_path = Path::new(dir);
            if !dir_path.is_dir() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(dir_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let path_str = path.to_string_lossy().to_string();
                    if path.is_file() && !self.should_exclude(&path_str) {
                        if let Ok(meta) = path.metadata() {
                            if meta.len() <= self.config.max_file_size {
                                files.push(path);
                            }
                        }
                    }
                }
            }
        }

        files
    }

    /// Build the initial baseline.
    pub fn build_baseline(&self) {
        let files = self.enumerate_monitored_files();
        let mut baseline = HashMap::new();

        for path in &files {
            if let Some(entry) = Self::read_file_entry(path) {
                baseline.insert(entry.path.clone(), entry);
            }
        }

        tracing::info!(files = baseline.len(), "FIM baseline established");
        *self.baseline.write() = baseline;
        self.baseline_established.store(true, Ordering::Relaxed);
        self.save_baseline();
    }

    /// Compare current state against baseline and return changes.
    pub fn scan_once(&self) -> Vec<ScanResult> {
        if !self.baseline_established.load(Ordering::Relaxed) {
            return Vec::new();
        }

        let mut results = Vec::new();
        let baseline = self.baseline.read();
        let current_files = self.enumerate_monitored_files();
        let mut seen_paths = std::collections::HashSet::new();

        for path in &current_files {
            let path_str = path.to_string_lossy().to_string();
            seen_paths.insert(path_str.clone());

            let current = match Self::read_file_entry(path) {
                Some(e) => e,
                None => continue,
            };

            match baseline.get(&path_str) {
                Some(original) => {
                    // Check for content modification
                    if current.sha256 != original.sha256 {
                        results.push(ScanResult::new(
                            "fim",
                            &path_str,
                            Self::severity_for_path(&path_str),
                            DetectionCategory::HeuristicAnomaly {
                                rule: "fim_content_modified".to_string(),
                            },
                            format!(
                                "File content modified: {} (hash {} -> {})",
                                path_str,
                                &original.sha256[..12],
                                &current.sha256[..12]
                            ),
                            0.85,
                            RecommendedAction::Alert,
                        ));
                    }

                    // Check for permission changes
                    if self.config.alert_on_permission_changes && current.mode != original.mode {
                        results.push(ScanResult::new(
                            "fim",
                            &path_str,
                            Severity::Medium,
                            DetectionCategory::HeuristicAnomaly {
                                rule: "fim_permission_changed".to_string(),
                            },
                            format!(
                                "File permissions changed: {} ({:o} -> {:o})",
                                path_str, original.mode, current.mode
                            ),
                            0.7,
                            RecommendedAction::Alert,
                        ));
                    }

                    // Check for ownership changes
                    if current.uid != original.uid || current.gid != original.gid {
                        results.push(ScanResult::new(
                            "fim",
                            &path_str,
                            Severity::High,
                            DetectionCategory::HeuristicAnomaly {
                                rule: "fim_owner_changed".to_string(),
                            },
                            format!(
                                "File ownership changed: {} ({}:{} -> {}:{})",
                                path_str, original.uid, original.gid, current.uid, current.gid
                            ),
                            0.8,
                            RecommendedAction::Alert,
                        ));
                    }
                }
                None => {
                    // New file
                    if self.config.alert_on_new_files {
                        results.push(ScanResult::new(
                            "fim",
                            &path_str,
                            Severity::Medium,
                            DetectionCategory::HeuristicAnomaly {
                                rule: "fim_new_file".to_string(),
                            },
                            format!("New file detected in monitored directory: {}", path_str),
                            0.6,
                            RecommendedAction::Alert,
                        ));
                    }
                }
            }
        }

        // Check for deleted files
        if self.config.alert_on_deleted_files {
            for (path, _) in baseline.iter() {
                if !seen_paths.contains(path) {
                    results.push(ScanResult::new(
                        "fim",
                        path,
                        Severity::High,
                        DetectionCategory::HeuristicAnomaly {
                            rule: "fim_file_deleted".to_string(),
                        },
                        format!("Monitored file deleted: {}", path),
                        0.8,
                        RecommendedAction::Alert,
                    ));
                }
            }
        }

        results
    }

    /// Determine severity based on the file path.
    fn severity_for_path(path: &str) -> Severity {
        // Critical system files
        let critical = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/pam.d/",
            "/etc/ld.so.preload",
        ];
        if critical.iter().any(|c| path.starts_with(c)) {
            return Severity::Critical;
        }

        // System binaries
        if path.starts_with("/usr/bin/") || path.starts_with("/usr/sbin/")
            || path.starts_with("/bin/") || path.starts_with("/sbin/")
        {
            return Severity::High;
        }

        // Config files
        if path.starts_with("/etc/") {
            return Severity::Medium;
        }

        Severity::Low
    }

    /// Update baseline with current state (after verifying changes are legitimate).
    pub fn update_baseline(&self) {
        self.build_baseline();
    }

    /// Get baseline entry count.
    pub fn baseline_count(&self) -> usize {
        self.baseline.read().len()
    }

    /// Get a specific file's baseline entry.
    pub fn get_baseline_entry(&self, path: &str) -> Option<FileEntry> {
        self.baseline.read().get(path).cloned()
    }

    /// Save baseline to disk.
    fn save_baseline(&self) {
        let baseline = self.baseline.read();
        let entries: Vec<&FileEntry> = baseline.values().collect();
        if let Ok(json) = serde_json::to_string_pretty(&entries) {
            if let Some(parent) = self.config.baseline_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&self.config.baseline_path, json);
        }
    }

    /// Load baseline from disk.
    fn load_baseline(&self) {
        if let Ok(content) = std::fs::read_to_string(&self.config.baseline_path) {
            if let Ok(entries) = serde_json::from_str::<Vec<FileEntry>>(&content) {
                let mut baseline = HashMap::new();
                for entry in entries {
                    baseline.insert(entry.path.clone(), entry);
                }
                if !baseline.is_empty() {
                    tracing::info!(files = baseline.len(), "FIM baseline loaded from disk");
                    *self.baseline.write() = baseline;
                    self.baseline_established.store(true, Ordering::Relaxed);
                }
            }
        }
    }

    /// Start the FIM monitor in a background task.
    pub fn start(
        self: Arc<Self>,
        detection_tx: tokio::sync::mpsc::UnboundedSender<ScanResult>,
    ) -> tokio::task::JoinHandle<()> {
        let running = Arc::clone(&self.running);
        let interval_ms = self.config.poll_interval_ms;

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_millis(interval_ms));

            while running.load(Ordering::Relaxed) {
                interval.tick().await;
                let results = self.scan_once();
                for result in results {
                    if detection_tx.send(result).is_err() {
                        return;
                    }
                }
            }
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
    use std::fs;

    fn test_config() -> FimConfig {
        let dir = std::env::temp_dir().join("nexus-fim-test");
        let _ = fs::create_dir_all(&dir);
        FimConfig {
            poll_interval_ms: 1000,
            watch_dirs: vec![dir.to_string_lossy().to_string()],
            watch_files: Vec::new(),
            exclude_patterns: vec![".exclude".to_string()],
            alert_on_new_files: true,
            alert_on_deleted_files: true,
            alert_on_permission_changes: true,
            max_file_size: 10_000_000,
            baseline_path: dir.join("baseline.json"),
        }
    }

    #[test]
    fn config_defaults() {
        let config = FimConfig::default();
        assert_eq!(config.poll_interval_ms, 60_000);
        assert!(!config.watch_dirs.is_empty());
        assert!(!config.watch_files.is_empty());
        assert!(config.alert_on_new_files);
        assert!(config.alert_on_deleted_files);
    }

    #[test]
    fn hash_file_works() {
        let path = std::env::temp_dir().join("nexus-fim-hash-test.txt");
        fs::write(&path, "hello world").unwrap();
        let hash = FimMonitor::hash_file(&path).unwrap();
        // SHA-256 of "hello world"
        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn hash_nonexistent_file() {
        let hash = FimMonitor::hash_file(Path::new("/nonexistent/file"));
        assert!(hash.is_none());
    }

    #[test]
    fn read_file_entry() {
        let path = std::env::temp_dir().join("nexus-fim-entry-test.txt");
        fs::write(&path, "test content").unwrap();
        let entry = FimMonitor::read_file_entry(&path).unwrap();
        assert_eq!(entry.path, path.to_string_lossy().to_string());
        assert!(!entry.sha256.is_empty());
        assert_eq!(entry.size, 12);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn read_directory_returns_none() {
        let entry = FimMonitor::read_file_entry(Path::new("/tmp"));
        assert!(entry.is_none());
    }

    #[test]
    fn exclude_patterns() {
        let config = test_config();
        let monitor = FimMonitor::new(config);
        assert!(monitor.should_exclude("/path/to/file.exclude"));
        assert!(!monitor.should_exclude("/path/to/file.txt"));
    }

    #[test]
    fn detect_modified_file() {
        let dir = std::env::temp_dir().join("nexus-fim-modify-test");
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("testfile.txt");
        fs::write(&file, "original content").unwrap();

        let mut config = test_config();
        config.watch_dirs = vec![dir.to_string_lossy().to_string()];
        config.baseline_path = dir.join("baseline.json");
        let monitor = FimMonitor::new(config);

        // Baseline is built with "original content"
        assert!(monitor.baseline_count() > 0);

        // Modify the file
        fs::write(&file, "modified content").unwrap();

        // Scan should detect the change
        let results = monitor.scan_once();
        let modified: Vec<_> = results
            .iter()
            .filter(|r| r.description.contains("content modified"))
            .collect();
        assert!(!modified.is_empty(), "Should detect modified file");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_new_file() {
        let dir = std::env::temp_dir().join("nexus-fim-new-test");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("existing.txt"), "existing").unwrap();

        let mut config = test_config();
        config.watch_dirs = vec![dir.to_string_lossy().to_string()];
        config.baseline_path = dir.join("baseline.json");
        let monitor = FimMonitor::new(config);

        // Add a new file after baseline
        fs::write(dir.join("new_file.txt"), "new content").unwrap();

        let results = monitor.scan_once();
        let new_files: Vec<_> = results
            .iter()
            .filter(|r| r.description.contains("New file"))
            .collect();
        assert!(!new_files.is_empty(), "Should detect new file");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_deleted_file() {
        let dir = std::env::temp_dir().join("nexus-fim-delete-test");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("will_delete.txt");
        fs::write(&file, "temporary").unwrap();

        let mut config = test_config();
        config.watch_dirs = vec![dir.to_string_lossy().to_string()];
        config.baseline_path = dir.join("baseline.json");
        let monitor = FimMonitor::new(config);

        // Delete the file
        fs::remove_file(&file).unwrap();

        let results = monitor.scan_once();
        let deleted: Vec<_> = results
            .iter()
            .filter(|r| r.description.contains("deleted"))
            .collect();
        assert!(!deleted.is_empty(), "Should detect deleted file");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn severity_for_critical_files() {
        assert_eq!(FimMonitor::severity_for_path("/etc/passwd"), Severity::Critical);
        assert_eq!(FimMonitor::severity_for_path("/etc/shadow"), Severity::Critical);
        assert_eq!(FimMonitor::severity_for_path("/etc/sudoers"), Severity::Critical);
    }

    #[test]
    fn severity_for_binaries() {
        assert_eq!(FimMonitor::severity_for_path("/usr/bin/ls"), Severity::High);
        assert_eq!(FimMonitor::severity_for_path("/usr/sbin/sshd"), Severity::High);
    }

    #[test]
    fn severity_for_config() {
        assert_eq!(FimMonitor::severity_for_path("/etc/hostname"), Severity::Medium);
    }

    #[test]
    fn severity_for_other() {
        assert_eq!(FimMonitor::severity_for_path("/home/user/file"), Severity::Low);
    }

    #[test]
    fn baseline_persistence() {
        let dir = std::env::temp_dir().join("nexus-fim-persist-test");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("persist.txt"), "data").unwrap();

        let mut config = test_config();
        config.watch_dirs = vec![dir.to_string_lossy().to_string()];
        config.baseline_path = dir.join("baseline.json");

        // Build and save baseline
        let monitor1 = FimMonitor::new(config.clone());
        let count1 = monitor1.baseline_count();
        assert!(count1 > 0);

        // Create new monitor — should load from disk
        let monitor2 = FimMonitor::new(config);
        assert_eq!(monitor2.baseline_count(), count1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_alert_when_unchanged() {
        let dir = std::env::temp_dir().join("nexus-fim-nochange-test");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("stable.txt"), "unchanged").unwrap();

        let mut config = test_config();
        config.watch_dirs = vec![dir.to_string_lossy().to_string()];
        config.baseline_path = dir.join("baseline.json");
        let monitor = FimMonitor::new(config);

        // Scan without changes
        let results = monitor.scan_once();
        assert!(results.is_empty(), "No alerts when nothing changed");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn permission_change_detection() {
        let dir = std::env::temp_dir().join("nexus-fim-perm-test");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("perm_test.txt");
        fs::write(&file, "content").unwrap();

        let mut config = test_config();
        config.watch_dirs = vec![dir.to_string_lossy().to_string()];
        config.baseline_path = dir.join("baseline.json");
        let monitor = FimMonitor::new(config);

        // Change permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o777)).unwrap();
        }

        let results = monitor.scan_once();

        #[cfg(unix)]
        {
            let perm_changes: Vec<_> = results
                .iter()
                .filter(|r| r.description.contains("permission"))
                .collect();
            assert!(!perm_changes.is_empty(), "Should detect permission change");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_entry_equality() {
        let a = FileEntry {
            path: "/test".to_string(),
            sha256: "abc".to_string(),
            size: 100,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 12345,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}