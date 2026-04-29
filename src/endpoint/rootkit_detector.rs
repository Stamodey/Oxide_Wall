// ============================================================================
// File: endpoint/rootkit_detector.rs
// Description: System integrity verification and rootkit detection

// ============================================================================
//! Rootkit Detector — verifies system binary integrity, detects hidden processes,
//! checks for suspicious kernel modules, and monitors LD_PRELOAD injection.

use super::{DetectionCategory, RecommendedAction, ScanResult, Severity};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Known rootkit kernel module names.
const KNOWN_ROOTKIT_MODULES: &[&str] = &[
    "diamorphine", "reptile", "bdvl", "suterusu", "adore-ng",
    "knark", "rkkit", "heroin", "override", "modhide",
    "enyelkm", "kbeast", "azazel", "jynx", "brootus",
    "nurupo", "phalanx", "suckit", "synapsys", "khook",
];

/// Configuration for the rootkit detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootkitConfig {
    pub scan_interval_secs: u64,
    pub system_dirs: Vec<PathBuf>,
    pub hash_db_path: PathBuf,
    pub check_kernel_modules: bool,
    pub check_ld_preload: bool,
}

impl RootkitConfig {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            scan_interval_secs: 300,
            system_dirs: vec![
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/sbin"),
                PathBuf::from("/bin"),
                PathBuf::from("/sbin"),
            ],
            hash_db_path: data_dir.join("system-hashes.json"),
            check_kernel_modules: true,
            check_ld_preload: true,
        }
    }
}

/// Rootkit detector with system integrity verification.
pub struct RootkitDetector {
    config: RootkitConfig,
    system_hashes: RwLock<HashMap<String, String>>, // path -> sha256
    running: Arc<AtomicBool>,
}

impl RootkitDetector {
    pub fn new(config: RootkitConfig) -> Self {
        let detector = Self {
            config: config.clone(),
            system_hashes: RwLock::new(HashMap::new()),
            running: Arc::new(AtomicBool::new(true)),
        };
        detector.load_baseline();
        detector
    }

    /// Build a baseline of SHA-256 hashes for all system binaries.
    /// Returns the number of files hashed.
    pub fn build_baseline(&self) -> Result<usize, String> {
        let mut hashes = HashMap::new();

        for dir in &self.config.system_dirs {
            if !dir.exists() {
                continue;
            }

            let entries = std::fs::read_dir(dir).map_err(|e| {
                format!("Cannot read {}: {}", dir.display(), e)
            })?;

            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                match compute_file_hash(&path) {
                    Ok(hash) => {
                        hashes.insert(path.to_string_lossy().to_string(), hash);
                    }
                    Err(_) => continue, // Skip unreadable files
                }
            }
        }

        let count = hashes.len();
        *self.system_hashes.write() = hashes;
        self.save_baseline();
        Ok(count)
    }

    /// Verify system binary integrity against the stored baseline.
    pub fn verify_integrity(&self) -> Vec<ScanResult> {
        let mut results = Vec::new();
        let baseline = self.system_hashes.read();

        if baseline.is_empty() {
            return results;
        }

        // Check each baselined file
        for (path_str, expected_hash) in baseline.iter() {
            let path = Path::new(path_str);

            if !path.exists() {
                // Binary was removed
                results.push(ScanResult::new(
                    "rootkit_detector",
                    path_str,
                    Severity::Medium,
                    DetectionCategory::RootkitIndicator {
                        technique: "binary_removed".to_string(),
                    },
                    format!("System binary removed: {} — may indicate rootkit replacing binaries", path_str),
                    0.6,
                    RecommendedAction::Alert,
                ));
                continue;
            }

            match compute_file_hash(path) {
                Ok(current_hash) => {
                    if &current_hash != expected_hash {
                        results.push(ScanResult::new(
                            "rootkit_detector",
                            path_str,
                            Severity::Critical,
                            DetectionCategory::RootkitIndicator {
                                technique: "binary_modified".to_string(),
                            },
                            format!(
                                "System binary MODIFIED: {} — expected hash {:.16}…, got {:.16}…",
                                path_str,
                                expected_hash,
                                current_hash,
                            ),
                            0.95,
                            RecommendedAction::Alert,
                        ));
                    }
                }
                Err(_) => {
                    // Can't read — permissions changed?
                    results.push(ScanResult::new(
                        "rootkit_detector",
                        path_str,
                        Severity::Medium,
                        DetectionCategory::RootkitIndicator {
                            technique: "binary_unreadable".to_string(),
                        },
                        format!("System binary unreadable: {} — permissions may have been modified", path_str),
                        0.5,
                        RecommendedAction::Alert,
                    ));
                }
            }
        }

        // Check for NEW files in system dirs not in baseline
        for dir in &self.config.system_dirs {
            if !dir.exists() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let path_str = path.to_string_lossy().to_string();
                        if !baseline.contains_key(&path_str) {
                            results.push(ScanResult::new(
                                "rootkit_detector",
                                &path_str,
                                Severity::Info,
                                DetectionCategory::RootkitIndicator {
                                    technique: "new_binary".to_string(),
                                },
                                format!("New binary in system directory: {}", path_str),
                                0.2,
                                RecommendedAction::LogOnly,
                            ));
                        }
                    }
                }
            }
        }

        results
    }

    /// Check loaded kernel modules for known rootkit names.
    pub fn check_kernel_modules(&self) -> Vec<ScanResult> {
        if !self.config.check_kernel_modules {
            return Vec::new();
        }

        let modules_content = match std::fs::read_to_string("/proc/modules") {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut results = Vec::new();

        for line in modules_content.lines() {
            let module_name = match line.split_whitespace().next() {
                Some(n) => n,
                None => continue,
            };

            let module_lower = module_name.to_lowercase();
            for rootkit_name in KNOWN_ROOTKIT_MODULES {
                if module_lower.contains(rootkit_name) {
                    results.push(ScanResult::new(
                        "rootkit_detector",
                        module_name,
                        Severity::Critical,
                        DetectionCategory::RootkitIndicator {
                            technique: "rootkit_kernel_module".to_string(),
                        },
                        format!(
                            "ROOTKIT kernel module detected: '{}' matches known rootkit '{}'",
                            module_name, rootkit_name
                        ),
                        0.95,
                        RecommendedAction::Alert,
                    ));
                    break;
                }
            }
        }

        results
    }

    /// Check for LD_PRELOAD injection.
    pub fn check_ld_preload(&self) -> Vec<ScanResult> {
        if !self.config.check_ld_preload {
            return Vec::new();
        }

        let mut results = Vec::new();

        // Check /etc/ld.so.preload
        if let Ok(content) = std::fs::read_to_string("/etc/ld.so.preload") {
            let content = content.trim();
            if !content.is_empty() && !content.starts_with('#') {
                results.push(ScanResult::new(
                    "rootkit_detector",
                    "/etc/ld.so.preload",
                    Severity::High,
                    DetectionCategory::RootkitIndicator {
                        technique: "ld_preload_file".to_string(),
                    },
                    format!(
                        "/etc/ld.so.preload contains entries: '{}' — libraries will be injected into ALL processes",
                        content.lines().next().unwrap_or("")
                    ),
                    0.8,
                    RecommendedAction::Alert,
                ));
            }
        }

        // Check current process environment for LD_PRELOAD
        if let Ok(environ) = std::fs::read("/proc/self/environ") {
            let env_str = String::from_utf8_lossy(&environ);
            // environ is null-separated
            for var in env_str.split('\0') {
                if var.starts_with("LD_PRELOAD=") {
                    let value = &var["LD_PRELOAD=".len()..];
                    if !value.is_empty() {
                        results.push(ScanResult::new(
                            "rootkit_detector",
                            "LD_PRELOAD",
                            Severity::High,
                            DetectionCategory::RootkitIndicator {
                                technique: "ld_preload_env".to_string(),
                            },
                            format!(
                                "LD_PRELOAD set in current process: '{}' — possible library injection",
                                value
                            ),
                            0.85,
                            RecommendedAction::Alert,
                        ));
                    }
                }
            }
        }

        // Check PID 1 (init/systemd) environment for LD_PRELOAD
        if let Ok(environ) = std::fs::read("/proc/1/environ") {
            let env_str = String::from_utf8_lossy(&environ);
            for var in env_str.split('\0') {
                if var.starts_with("LD_PRELOAD=") {
                    let value = &var["LD_PRELOAD=".len()..];
                    if !value.is_empty() {
                        results.push(ScanResult::new(
                            "rootkit_detector",
                            "LD_PRELOAD:init",
                            Severity::Critical,
                            DetectionCategory::RootkitIndicator {
                                technique: "ld_preload_init".to_string(),
                            },
                            format!(
                                "LD_PRELOAD set in init process (PID 1): '{}' — system-wide library injection",
                                value
                            ),
                            0.95,
                            RecommendedAction::Alert,
                        ));
                    }
                }
            }
        }

        results
    }

    /// Check for hidden processes (PIDs visible in readdir but inaccessible).
    #[cfg(unix)]
    pub fn check_hidden_processes(&self) -> Vec<ScanResult> {
        let mut results = Vec::new();

        let entries = match std::fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => return results,
        };

        let my_uid = unsafe { libc::getuid() };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let pid: u32 = match name.to_string_lossy().parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Try to read /proc/[pid]/status
            let status_path = format!("/proc/{}/status", pid);
            match std::fs::read_to_string(&status_path) {
                Ok(status) => {
                    // Check if UID matches ours — if so, we should be able to read everything
                    let proc_uid: u32 = status
                        .lines()
                        .find(|l| l.starts_with("Uid:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(u32::MAX);

                    if proc_uid == my_uid {
                        // Our process — check if /proc/[pid]/exe is accessible
                        let exe_path = format!("/proc/{}/exe", pid);
                        if std::fs::read_link(&exe_path).is_err() {
                            // Our own process but can't read exe — suspicious
                            results.push(ScanResult::new(
                                "rootkit_detector",
                                format!("pid:{}", pid),
                                Severity::Medium,
                                DetectionCategory::RootkitIndicator {
                                    technique: "hidden_process_exe".to_string(),
                                },
                                format!(
                                    "Process {} owned by us but /proc/{}/exe inaccessible — possible process hiding",
                                    pid, pid
                                ),
                                0.5,
                                RecommendedAction::Alert,
                            ));
                        }
                    }
                }
                Err(_) => {
                    // PID visible in readdir but status unreadable
                    // This is normal for other users' processes — only flag if we're root
                    if my_uid == 0 {
                        results.push(ScanResult::new(
                            "rootkit_detector",
                            format!("pid:{}", pid),
                            Severity::High,
                            DetectionCategory::RootkitIndicator {
                                technique: "hidden_process".to_string(),
                            },
                            format!(
                                "Process {} visible in /proc but status unreadable as root — possible kernel-level hiding",
                                pid
                            ),
                            0.85,
                            RecommendedAction::Alert,
                        ));
                    }
                }
            }
        }

        results
    }

    /// Check for hidden processes (Windows stub — not implemented on Windows).
    #[cfg(not(unix))]
    pub fn check_hidden_processes(&self) -> Vec<ScanResult> {
        Vec::new()  // Placeholder for Windows (process hiding detection not implemented)
    }
    pub fn scan_all(&self) -> Vec<ScanResult> {
        let mut results = Vec::new();
        results.extend(self.verify_integrity());
        results.extend(self.check_kernel_modules());
        results.extend(self.check_ld_preload());
        results.extend(self.check_hidden_processes());
        results
    }

    /// Save the baseline hash database to disk.
    pub fn save_baseline(&self) {
        let hashes = self.system_hashes.read();
        if let Ok(json) = serde_json::to_string_pretty(&*hashes) {
            if let Some(parent) = self.config.hash_db_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let tmp = self.config.hash_db_path.with_extension("json.tmp");
            if std::fs::write(&tmp, &json).is_ok() {
                let _ = std::fs::rename(&tmp, &self.config.hash_db_path);
            }
        }
    }

    /// Load the baseline hash database from disk.
    pub fn load_baseline(&self) {
        if let Ok(content) = std::fs::read_to_string(&self.config.hash_db_path) {
            if let Ok(hashes) = serde_json::from_str::<HashMap<String, String>>(&content) {
                *self.system_hashes.write() = hashes;
            }
        }
    }

    /// Start periodic rootkit scanning in a background task.
    pub fn start(
        self: Arc<Self>,
        detection_tx: tokio::sync::mpsc::UnboundedSender<ScanResult>,
    ) -> tokio::task::JoinHandle<()> {
        let running = Arc::clone(&self.running);
        let interval_secs = self.config.scan_interval_secs;

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(interval_secs));

            while running.load(Ordering::Relaxed) {
                interval.tick().await;
                let results = self.scan_all();
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

    /// Get the number of baselined files.
    pub fn baseline_count(&self) -> usize {
        self.system_hashes.read().len()
    }
}

/// Compute SHA-256 of a file in streaming 8KB chunks.
fn compute_file_hash(path: &Path) -> std::io::Result<String> {
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_baseline_on_temp_dir() {
        let dir = std::env::temp_dir().join(format!("nexus-rootkit-test-{}", uuid::Uuid::new_v4()));
        let bin_dir = dir.join("bin");
        let _ = std::fs::create_dir_all(&bin_dir);

        // Create test "binaries"
        std::fs::write(bin_dir.join("ls"), b"fake ls binary").unwrap();
        std::fs::write(bin_dir.join("cat"), b"fake cat binary").unwrap();
        std::fs::write(bin_dir.join("grep"), b"fake grep binary").unwrap();

        let config = RootkitConfig {
            scan_interval_secs: 300,
            system_dirs: vec![bin_dir.clone()],
            hash_db_path: dir.join("hashes.json"),
            check_kernel_modules: false,
            check_ld_preload: false,
        };

        let detector = RootkitDetector::new(config);
        let count = detector.build_baseline().unwrap();
        assert_eq!(count, 3);
        assert_eq!(detector.baseline_count(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_modified_file() {
        let dir = std::env::temp_dir().join(format!("nexus-rootkit-mod-{}", uuid::Uuid::new_v4()));
        let bin_dir = dir.join("bin");
        let _ = std::fs::create_dir_all(&bin_dir);

        std::fs::write(bin_dir.join("ls"), b"original content").unwrap();

        let config = RootkitConfig {
            scan_interval_secs: 300,
            system_dirs: vec![bin_dir.clone()],
            hash_db_path: dir.join("hashes.json"),
            check_kernel_modules: false,
            check_ld_preload: false,
        };

        let detector = RootkitDetector::new(config);
        detector.build_baseline().unwrap();

        // Modify the file
        std::fs::write(bin_dir.join("ls"), b"MODIFIED by rootkit!").unwrap();

        let results = detector.verify_integrity();
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.severity == Severity::Critical));
        assert!(results.iter().any(|r| r.description.contains("MODIFIED")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_removed_file() {
        let dir = std::env::temp_dir().join(format!("nexus-rootkit-rm-{}", uuid::Uuid::new_v4()));
        let bin_dir = dir.join("bin");
        let _ = std::fs::create_dir_all(&bin_dir);

        std::fs::write(bin_dir.join("ls"), b"binary").unwrap();

        let config = RootkitConfig {
            scan_interval_secs: 300,
            system_dirs: vec![bin_dir.clone()],
            hash_db_path: dir.join("hashes.json"),
            check_kernel_modules: false,
            check_ld_preload: false,
        };

        let detector = RootkitDetector::new(config);
        detector.build_baseline().unwrap();

        // Remove the file
        std::fs::remove_file(bin_dir.join("ls")).unwrap();

        let results = detector.verify_integrity();
        assert!(results.iter().any(|r| r.description.contains("removed")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kernel_module_name_matching() {
        for name in KNOWN_ROOTKIT_MODULES {
            assert!(
                name.to_lowercase() == *name,
                "Rootkit name '{}' should be lowercase",
                name
            );
        }
        // Check a known rootkit is in the list
        assert!(KNOWN_ROOTKIT_MODULES.contains(&"diamorphine"));
        assert!(KNOWN_ROOTKIT_MODULES.contains(&"reptile"));
    }

    #[test]
    fn ld_preload_environ_parsing() {
        // Simulate /proc/self/environ format (null-separated)
        let environ = "HOME=/root\0PATH=/usr/bin\0LD_PRELOAD=/tmp/evil.so\0TERM=xterm\0";
        let has_preload = environ
            .split('\0')
            .any(|v| v.starts_with("LD_PRELOAD=") && !v["LD_PRELOAD=".len()..].is_empty());
        assert!(has_preload);

        // Without LD_PRELOAD
        let clean = "HOME=/root\0PATH=/usr/bin\0TERM=xterm\0";
        let no_preload = clean
            .split('\0')
            .any(|v| v.starts_with("LD_PRELOAD=") && !v["LD_PRELOAD=".len()..].is_empty());
        assert!(!no_preload);
    }

    #[test]
    fn baseline_save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("nexus-rootkit-rt-{}", uuid::Uuid::new_v4()));
        let bin_dir = dir.join("bin");
        let _ = std::fs::create_dir_all(&bin_dir);

        std::fs::write(bin_dir.join("test"), b"test binary").unwrap();

        let config = RootkitConfig {
            scan_interval_secs: 300,
            system_dirs: vec![bin_dir.clone()],
            hash_db_path: dir.join("hashes.json"),
            check_kernel_modules: false,
            check_ld_preload: false,
        };

        let detector = RootkitDetector::new(config.clone());
        detector.build_baseline().unwrap();
        assert_eq!(detector.baseline_count(), 1);

        // New detector should load saved baseline
        let detector2 = RootkitDetector::new(config);
        assert_eq!(detector2.baseline_count(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_all_no_crash() {
        let dir = std::env::temp_dir().join("nexus-rootkit-nocrash");
        let config = RootkitConfig {
            scan_interval_secs: 300,
            system_dirs: vec![],
            hash_db_path: dir.join("hashes.json"),
            check_kernel_modules: true,
            check_ld_preload: true,
        };
        let detector = RootkitDetector::new(config);
        let _ = detector.scan_all(); // Should not crash
    }
}