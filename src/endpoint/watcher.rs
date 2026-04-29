// ============================================================================
// File: endpoint/watcher.rs
// Description: Real-time filesystem monitoring via inotify (notify crate)
// ============================================================================
//! File Watcher — monitors directories for file creation, modification, and
//! renames, then dispatches paths to the scanner pipeline.

use super::allowlist::DeveloperAllowlist;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Configuration for the filesystem watcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherConfig {
    /// Directories to monitor recursively.
    pub watch_paths: Vec<PathBuf>,
    /// Path patterns to exclude (component or extension match).
    pub exclude_patterns: Vec<String>,
    /// Maximum file size to scan (bytes). Larger files are skipped.
    pub max_file_size: u64,
    /// Debounce interval in milliseconds for rapid file events.
    pub debounce_ms: u64,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/root"));

        Self {
            watch_paths: vec![home, PathBuf::from("/tmp")],
            exclude_patterns: vec![
                "node_modules".to_string(),
                "target".to_string(),
                ".git".to_string(),
                "__pycache__".to_string(),
                ".cache".to_string(),
                "*.o".to_string(),
                "*.a".to_string(),
                "*.pyc".to_string(),
                "*.class".to_string(),
            ],
            max_file_size: 104_857_600, // 100 MB
            debounce_ms: 300,
        }
    }
}

/// Real-time filesystem watcher that dispatches file paths to the scan pipeline.
pub struct FileWatcher {
    config: WatcherConfig,
    scan_tx: tokio::sync::mpsc::UnboundedSender<PathBuf>,
    running: Arc<AtomicBool>,
}

impl FileWatcher {
    /// Create a new file watcher.
    pub fn new(
        config: WatcherConfig,
        scan_tx: tokio::sync::mpsc::UnboundedSender<PathBuf>,
    ) -> Self {
        Self {
            config,
            scan_tx,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Start the watcher in a background task. Returns a JoinHandle.
    pub fn start(self, allowlist: Arc<DeveloperAllowlist>) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let scan_tx = self.scan_tx.clone();
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            // Use a std channel for the notify watcher (it's sync)
            let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();

            let mut watcher = match notify::RecommendedWatcher::new(
                tx,
                notify::Config::default()
                    .with_poll_interval(std::time::Duration::from_millis(config.debounce_ms)),
            ) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!("Failed to create file watcher: {}", e);
                    return;
                }
            };

            // Add watch paths
            for path in &config.watch_paths {
                if path.exists() {
                    match watcher.watch(path, RecursiveMode::Recursive) {
                        Ok(_) => tracing::info!("Watching directory: {}", path.display()),
                        Err(e) => tracing::warn!("Cannot watch {}: {}", path.display(), e),
                    }
                }
            }

            // Process events
            while running.load(Ordering::Relaxed) {
                match rx.recv_timeout(std::time::Duration::from_secs(1)) {
                    Ok(Ok(event)) => {
                        // Only process create and modify events
                        let dominated = matches!(
                            event.kind,
                            EventKind::Create(_) | EventKind::Modify(_)
                        );

                        if !dominated {
                            continue;
                        }

                        for path in event.paths {
                            // Skip directories
                            if path.is_dir() {
                                continue;
                            }

                            // Check exclude patterns
                            if should_exclude(&path, &config.exclude_patterns) {
                                continue;
                            }

                            // Check developer allowlist
                            if allowlist.should_skip_path(&path) {
                                tracing::trace!(file = %path.display(), "Skipped by allowlist");
                                continue;
                            }

                            // Check file size
                            if let Ok(meta) = std::fs::metadata(&path) {
                                if meta.len() > config.max_file_size {
                                    continue;
                                }
                                if !meta.is_file() {
                                    continue;
                                }
                            } else {
                                continue;
                            }

                            // Send to scan pipeline
                            if scan_tx.send(path).is_err() {
                                tracing::warn!("Scan channel closed, stopping watcher");
                                return;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("Watch error: {}", e);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Normal timeout, check running flag
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        tracing::info!("Watcher channel disconnected, stopping");
                        return;
                    }
                }
            }

            tracing::info!("File watcher stopped");
        })
    }

    /// Signal the watcher to stop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Check if a path matches any exclude pattern.
pub fn should_exclude(path: &Path, patterns: &[String]) -> bool {
    let path_str = path.to_string_lossy();

    for pattern in patterns {
        // Extension match: *.ext
        if let Some(ext_pat) = pattern.strip_prefix("*.") {
            if let Some(ext) = path.extension() {
                if ext.to_string_lossy().eq_ignore_ascii_case(ext_pat) {
                    return true;
                }
            }
            continue;
        }

        // Component match: check if any path component equals the pattern
        for component in path.components() {
            if let std::path::Component::Normal(c) = component {
                if c.to_string_lossy() == pattern.as_str() {
                    return true;
                }
            }
        }

        // Substring match fallback
        if path_str.contains(pattern.as_str()) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_node_modules() {
        let patterns = vec!["node_modules".to_string()];
        assert!(should_exclude(
            Path::new("/home/user/project/node_modules/express/index.js"),
            &patterns
        ));
    }

    #[test]
    fn exclude_deep_target() {
        let patterns = vec!["target".to_string()];
        assert!(should_exclude(
            Path::new("/home/user/rust-project/target/debug/myapp"),
            &patterns
        ));
    }

    #[test]
    fn exclude_object_extension() {
        let patterns = vec!["*.o".to_string(), "*.a".to_string()];
        assert!(should_exclude(Path::new("/tmp/build/main.o"), &patterns));
        assert!(should_exclude(Path::new("/tmp/lib/libz.a"), &patterns));
    }

    #[test]
    fn normal_file_not_excluded() {
        let patterns = vec![
            "node_modules".to_string(),
            "target".to_string(),
            "*.o".to_string(),
        ];
        assert!(!should_exclude(
            Path::new("/home/user/Documents/report.pdf"),
            &patterns
        ));
        assert!(!should_exclude(
            Path::new("/tmp/download.exe"),
            &patterns
        ));
    }

    #[test]
    fn config_defaults() {
        let config = WatcherConfig::default();
        assert!(!config.watch_paths.is_empty());
        assert!(!config.exclude_patterns.is_empty());
        assert!(config.max_file_size > 0);
        assert!(config.debounce_ms > 0);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = WatcherConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let config2: WatcherConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.max_file_size, config2.max_file_size);
        assert_eq!(config.debounce_ms, config2.debounce_ms);
    }

    #[test]
    fn exclude_git_directory() {
        let patterns = vec![".git".to_string()];
        assert!(should_exclude(
            Path::new("/home/user/repo/.git/objects/pack/pack-abc.idx"),
            &patterns
        ));
    }

    #[test]
    fn exclude_pycache() {
        let patterns = vec!["__pycache__".to_string()];
        assert!(should_exclude(
            Path::new("/home/user/app/__pycache__/module.cpython-311.pyc"),
            &patterns
        ));
    }
}