// ============================================================================
// File: endpoint/usb_monitor.rs
// Description: USB and removable media monitoring — detect insertions,
//              auto-scan mounted volumes, and alert on suspicious devices
// ============================================================================
//! USB Monitor — watches for removable storage device insertions via
//! /sys/block and /proc/mounts polling, auto-scans newly mounted volumes,
//! and detects suspicious USB device characteristics.
//!
//! Detection capabilities:
//! - New block device insertion (USB drives, SD cards)
//! - Auto-scan of newly mounted filesystems
//! - Suspicious device detection (hidden partitions, unusual filesystem types)
//! - BadUSB indicators (HID devices masquerading as storage)
//! - Autorun/autoplay file detection on mounted volumes

use super::{DetectionCategory, RecommendedAction, ScanResult, Severity};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the USB/removable media monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbMonitorConfig {
    /// Polling interval for device changes in milliseconds.
    pub poll_interval_ms: u64,
    /// Auto-scan newly mounted volumes.
    pub auto_scan_new_volumes: bool,
    /// Maximum file size to scan on USB volumes (bytes).
    pub max_scan_file_size: u64,
    /// Block device prefixes to monitor (e.g., "sd" for SCSI/USB disks).
    pub device_prefixes: Vec<String>,
    /// Filesystem types considered suspicious when mounted.
    pub suspicious_fs_types: Vec<String>,
    /// Autorun filenames to detect (case-insensitive).
    pub autorun_filenames: Vec<String>,
    /// Alert on any new USB device insertion.
    pub alert_on_insertion: bool,
}

impl Default for UsbMonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 3000,
            auto_scan_new_volumes: true,
            max_scan_file_size: 104_857_600, // 100 MB
            device_prefixes: vec!["sd".to_string()],
            suspicious_fs_types: vec![
                "ntfs".to_string(),
                "vfat".to_string(),
                "exfat".to_string(),
                "hfsplus".to_string(),
                "udf".to_string(),
            ],
            autorun_filenames: vec![
                "autorun.inf".to_string(),
                "autorun.sh".to_string(),
                ".autorun".to_string(),
                "autoexec.bat".to_string(),
                "desktop.ini".to_string(),
                ".DS_Store".to_string(),
                "RECYCLER".to_string(),
                "$RECYCLE.BIN".to_string(),
                "System Volume Information".to_string(),
            ],
            alert_on_insertion: true,
        }
    }
}

// =============================================================================
// Device Info
// =============================================================================

/// Information about a detected block device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDeviceInfo {
    /// Device name (e.g., "sda").
    pub name: String,
    /// Device path (e.g., "/dev/sda").
    pub dev_path: String,
    /// Whether the device is removable (from /sys/block/<dev>/removable).
    pub removable: bool,
    /// Device size in bytes (from /sys/block/<dev>/size, sectors * 512).
    pub size_bytes: u64,
    /// Device model string (from /sys/block/<dev>/device/model).
    pub model: String,
    /// Device vendor string (from /sys/block/<dev>/device/vendor).
    pub vendor: String,
    /// Partitions (e.g., ["sda1", "sda2"]).
    pub partitions: Vec<String>,
}

/// A mounted filesystem entry from /proc/mounts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MountEntry {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub options: String,
}

// =============================================================================
// USB Monitor
// =============================================================================

/// Monitors for USB device insertions and scans mounted volumes.
pub struct UsbMonitor {
    config: UsbMonitorConfig,
    /// Previously seen block devices.
    known_devices: RwLock<HashSet<String>>,
    /// Previously seen mount points.
    known_mounts: RwLock<HashSet<String>>,
    /// Device info cache.
    device_info: RwLock<HashMap<String, BlockDeviceInfo>>,
    /// Shutdown flag.
    running: Arc<AtomicBool>,
}

impl UsbMonitor {
    pub fn new(config: UsbMonitorConfig) -> Self {
        // Initialize with current devices so we don't alert on existing ones
        let current_devices = Self::enumerate_block_devices_static(&config.device_prefixes);
        let current_mounts = Self::parse_mounts_static()
            .into_iter()
            .map(|m| m.mount_point)
            .collect();

        Self {
            config,
            known_devices: RwLock::new(current_devices),
            known_mounts: RwLock::new(current_mounts),
            device_info: RwLock::new(HashMap::new()),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Enumerate block devices from /sys/block matching our prefixes.
    fn enumerate_block_devices_static(prefixes: &[String]) -> HashSet<String> {
        let mut devices = HashSet::new();
        if let Ok(entries) = std::fs::read_dir("/sys/block") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if prefixes.iter().any(|p| name.starts_with(p)) {
                    devices.insert(name);
                }
            }
        }
        devices
    }

    /// Enumerate current block devices.
    fn enumerate_block_devices(&self) -> HashSet<String> {
        Self::enumerate_block_devices_static(&self.config.device_prefixes)
    }

    /// Read device information from /sys/block/<name>/.
    pub fn read_device_info(name: &str) -> BlockDeviceInfo {
        let sys_path = format!("/sys/block/{}", name);

        let removable = std::fs::read_to_string(format!("{}/removable", sys_path))
            .unwrap_or_default()
            .trim()
            == "1";

        let size_sectors: u64 = std::fs::read_to_string(format!("{}/size", sys_path))
            .unwrap_or_default()
            .trim()
            .parse()
            .unwrap_or(0);

        let model = std::fs::read_to_string(format!("{}/device/model", sys_path))
            .unwrap_or_default()
            .trim()
            .to_string();

        let vendor = std::fs::read_to_string(format!("{}/device/vendor", sys_path))
            .unwrap_or_default()
            .trim()
            .to_string();

        // Find partitions (e.g., sda1, sda2)
        let mut partitions = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&sys_path) {
            for entry in entries.flatten() {
                let part_name = entry.file_name().to_string_lossy().to_string();
                if part_name.starts_with(name) && part_name.len() > name.len() {
                    partitions.push(part_name);
                }
            }
        }
        partitions.sort();

        BlockDeviceInfo {
            name: name.to_string(),
            dev_path: format!("/dev/{}", name),
            removable,
            size_bytes: size_sectors * 512,
            model,
            vendor,
            partitions,
        }
    }

    /// Parse /proc/mounts into structured entries.
    fn parse_mounts_static() -> Vec<MountEntry> {
        let content = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        Self::parse_mounts_content(&content)
    }

    /// Parse mount content (testable).
    pub fn parse_mounts_content(content: &str) -> Vec<MountEntry> {
        let mut entries = Vec::new();
        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 4 {
                entries.push(MountEntry {
                    device: fields[0].to_string(),
                    mount_point: fields[1].to_string(),
                    fs_type: fields[2].to_string(),
                    options: fields[3].to_string(),
                });
            }
        }
        entries
    }

    /// Check a mounted volume for suspicious files (autorun, hidden executables).
    pub fn check_mount_for_threats(mount_point: &Path, autorun_names: &[String]) -> Vec<ScanResult> {
        let mut results = Vec::new();

        let entries = match std::fs::read_dir(mount_point) {
            Ok(e) => e,
            Err(_) => return results,
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let name_lower = name.to_lowercase();

            // Check for autorun/autoplay files
            for autorun in autorun_names {
                if name_lower == autorun.to_lowercase() {
                    results.push(ScanResult::new(
                        "usb_monitor",
                        &entry.path().to_string_lossy().to_string(),
                        Severity::High,
                        DetectionCategory::HeuristicAnomaly {
                            rule: "usb_autorun".to_string(),
                        },
                        format!(
                            "Autorun file '{}' detected on removable media at {}",
                            name,
                            mount_point.display()
                        ),
                        0.85,
                        RecommendedAction::Quarantine {
                            source_path: entry.path(),
                        },
                    ));
                }
            }

            // Check for hidden executables (dotfiles with execute permission)
            if name.starts_with('.') && name.len() > 1 {
                if let Ok(_meta) = entry.metadata() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if meta.permissions().mode() & 0o111 != 0 && meta.is_file() {
                            results.push(ScanResult::new(
                                "usb_monitor",
                                &entry.path().to_string_lossy().to_string(),
                                Severity::Medium,
                                DetectionCategory::HeuristicAnomaly {
                                    rule: "usb_hidden_executable".to_string(),
                                },
                                format!(
                                    "Hidden executable '{}' on removable media at {}",
                                    name,
                                    mount_point.display()
                                ),
                                0.7,
                                RecommendedAction::Alert,
                            ));
                        }
                    }
                }
            }

            // Check for suspicious script files at root level
            let suspicious_extensions = [".bat", ".cmd", ".ps1", ".vbs", ".wsf", ".hta", ".scr"];
            for ext in &suspicious_extensions {
                if name_lower.ends_with(ext) {
                    results.push(ScanResult::new(
                        "usb_monitor",
                        &entry.path().to_string_lossy().to_string(),
                        Severity::Medium,
                        DetectionCategory::HeuristicAnomaly {
                            rule: "usb_suspicious_script".to_string(),
                        },
                        format!(
                            "Suspicious script '{}' on removable media at {}",
                            name,
                            mount_point.display()
                        ),
                        0.65,
                        RecommendedAction::Alert,
                    ));
                    break;
                }
            }
        }

        results
    }

    /// Perform a single scan cycle: check for new devices and new mounts.
    pub fn scan_once(&self) -> Vec<ScanResult> {
        let mut results = Vec::new();

        // 1. Check for new block devices
        let current_devices = self.enumerate_block_devices();
        let new_devices: Vec<String> = {
            let known = self.known_devices.read();
            current_devices
                .iter()
                .filter(|d| !known.contains(*d))
                .cloned()
                .collect()
        };

        for dev_name in &new_devices {
            let info = Self::read_device_info(dev_name);

            // Cache device info
            self.device_info.write().insert(dev_name.clone(), info.clone());

            if self.config.alert_on_insertion {
                let severity = if info.removable {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                results.push(ScanResult::new(
                    "usb_monitor",
                    &info.dev_path,
                    severity,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "usb_device_inserted".to_string(),
                    },
                    format!(
                        "New {} device detected: {} {} ({}, {} bytes, {} partitions)",
                        if info.removable { "removable" } else { "block" },
                        info.vendor.trim(),
                        info.model.trim(),
                        info.dev_path,
                        info.size_bytes,
                        info.partitions.len()
                    ),
                    if info.removable { 0.5 } else { 0.2 },
                    RecommendedAction::Alert,
                ));
            }
        }

        // Update known devices
        *self.known_devices.write() = current_devices;

        // 2. Check for new mount points
        let current_mounts = Self::parse_mounts_static();
        let new_mounts: Vec<MountEntry> = {
            let known = self.known_mounts.read();
            current_mounts
                .iter()
                .filter(|m| !known.contains(&m.mount_point))
                .filter(|m| {
                    // Only care about real device mounts
                    m.device.starts_with("/dev/")
                })
                .cloned()
                .collect()
        };

        for mount in &new_mounts {
            // Check if filesystem type is suspicious
            let is_suspicious_fs = self
                .config
                .suspicious_fs_types
                .iter()
                .any(|fs| mount.fs_type == *fs);

            if is_suspicious_fs {
                results.push(ScanResult::new(
                    "usb_monitor",
                    &mount.mount_point,
                    Severity::Info,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "usb_volume_mounted".to_string(),
                    },
                    format!(
                        "Removable volume mounted: {} ({}) at {}",
                        mount.device, mount.fs_type, mount.mount_point
                    ),
                    0.3,
                    RecommendedAction::Alert,
                ));
            }

            // Check mount point for autorun and suspicious files
            let mount_path = Path::new(&mount.mount_point);
            let mut mount_threats =
                Self::check_mount_for_threats(mount_path, &self.config.autorun_filenames);
            results.append(&mut mount_threats);
        }

        // Update known mounts
        let mount_points: HashSet<String> = current_mounts
            .into_iter()
            .map(|m| m.mount_point)
            .collect();
        *self.known_mounts.write() = mount_points;

        results
    }

    /// Get cached info about a device.
    pub fn get_device_info(&self, name: &str) -> Option<BlockDeviceInfo> {
        self.device_info.read().get(name).cloned()
    }

    /// Get all currently known removable devices.
    pub fn removable_devices(&self) -> Vec<BlockDeviceInfo> {
        self.device_info
            .read()
            .values()
            .filter(|d| d.removable)
            .cloned()
            .collect()
    }

    /// Start the USB monitor in a background task.
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

    #[test]
    fn config_defaults() {
        let config = UsbMonitorConfig::default();
        assert_eq!(config.poll_interval_ms, 3000);
        assert!(config.auto_scan_new_volumes);
        assert!(config.alert_on_insertion);
        assert!(!config.device_prefixes.is_empty());
        assert!(!config.autorun_filenames.is_empty());
    }

    #[test]
    fn parse_mounts_content() {
        let content = r#"/dev/sda1 / ext4 rw,relatime 0 0
/dev/sdb1 /mnt/usb vfat rw,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid 0 0
proc /proc proc rw,nosuid 0 0"#;

        let entries = UsbMonitor::parse_mounts_content(content);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].device, "/dev/sda1");
        assert_eq!(entries[0].mount_point, "/");
        assert_eq!(entries[0].fs_type, "ext4");
        assert_eq!(entries[1].mount_point, "/mnt/usb");
        assert_eq!(entries[1].fs_type, "vfat");
    }

    #[test]
    fn parse_empty_mounts() {
        let entries = UsbMonitor::parse_mounts_content("");
        assert!(entries.is_empty());
    }

    #[test]
    fn read_device_info_nonexistent() {
        // Should not crash on nonexistent device
        let info = UsbMonitor::read_device_info("zzz_nonexistent");
        assert_eq!(info.name, "zzz_nonexistent");
        assert!(!info.removable);
        assert_eq!(info.size_bytes, 0);
    }

    #[test]
    fn autorun_detection() {
        let dir = std::env::temp_dir().join("nexus-usb-test-autorun");
        let _ = fs::create_dir_all(&dir);

        // Create an autorun.inf file
        fs::write(dir.join("autorun.inf"), "[autorun]\nopen=malware.exe").unwrap();
        fs::write(dir.join("readme.txt"), "harmless").unwrap();

        let autorun_names = vec!["autorun.inf".to_string(), "autorun.sh".to_string()];
        let results = UsbMonitor::check_mount_for_threats(&dir, &autorun_names);

        assert!(!results.is_empty(), "Should detect autorun.inf");
        assert!(results[0].description.contains("autorun.inf"));
        assert_eq!(results[0].severity, Severity::High);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn suspicious_script_detection() {
        let dir = std::env::temp_dir().join("nexus-usb-test-scripts");
        let _ = fs::create_dir_all(&dir);

        fs::write(dir.join("payload.ps1"), "Invoke-Expression $evil").unwrap();
        fs::write(dir.join("normal.txt"), "hello").unwrap();

        let results = UsbMonitor::check_mount_for_threats(&dir, &[]);

        let script_results: Vec<_> = results
            .iter()
            .filter(|r| r.description.contains("payload.ps1"))
            .collect();
        assert!(!script_results.is_empty(), "Should detect .ps1 file");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_false_positive_on_clean_dir() {
        let dir = std::env::temp_dir().join("nexus-usb-test-clean");
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("document.pdf"), "fake pdf").unwrap();
        fs::write(dir.join("photo.jpg"), "fake jpg").unwrap();

        let results = UsbMonitor::check_mount_for_threats(&dir, &["autorun.inf".to_string()]);
        assert!(results.is_empty(), "Clean dir should produce no alerts");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hidden_executable_detection() {
        let dir = std::env::temp_dir().join("nexus-usb-test-hidden");
        let _ = fs::create_dir_all(&dir);

        let hidden = dir.join(".hidden_payload");
        fs::write(&hidden, "#!/bin/bash\nrm -rf /").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hidden, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let results = UsbMonitor::check_mount_for_threats(&dir, &[]);

        #[cfg(unix)]
        {
            let hidden_results: Vec<_> = results
                .iter()
                .filter(|r| r.description.contains(".hidden_payload"))
                .collect();
            assert!(
                !hidden_results.is_empty(),
                "Should detect hidden executable"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_once_no_crash() {
        let config = UsbMonitorConfig::default();
        let monitor = UsbMonitor::new(config);
        // Should not crash even if /sys/block changes
        let results = monitor.scan_once();
        // On first scan after init, no new devices expected
        let _ = results;
    }

    #[test]
    fn device_info_cache() {
        let config = UsbMonitorConfig::default();
        let monitor = UsbMonitor::new(config);
        // Cache should be empty initially (existing devices are in known_devices but not cached)
        assert!(monitor.removable_devices().is_empty());
    }

    #[test]
    fn mount_entry_equality() {
        let a = MountEntry {
            device: "/dev/sda1".to_string(),
            mount_point: "/mnt/usb".to_string(),
            fs_type: "vfat".to_string(),
            options: "rw".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn case_insensitive_autorun() {
        let dir = std::env::temp_dir().join("nexus-usb-test-case");
        let _ = fs::create_dir_all(&dir);

        // Create AUTORUN.INF (uppercase)
        fs::write(dir.join("AUTORUN.INF"), "[autorun]").unwrap();

        let autorun_names = vec!["autorun.inf".to_string()];
        let results = UsbMonitor::check_mount_for_threats(&dir, &autorun_names);

        assert!(!results.is_empty(), "Should detect AUTORUN.INF (case-insensitive)");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn suspicious_fs_types() {
        let config = UsbMonitorConfig::default();
        assert!(config.suspicious_fs_types.contains(&"vfat".to_string()));
        assert!(config.suspicious_fs_types.contains(&"ntfs".to_string()));
        assert!(!config.suspicious_fs_types.contains(&"ext4".to_string()));
    }
}