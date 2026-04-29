// ============================================================================
// File: endpoint/mod.rs
// Description: Real-time endpoint protection engine — core types and orchestrator
// ============================================================================
//! # Endpoint Protection Engine
//!
//! Real-time file, process, network, and memory monitoring with multi-engine
//! malware detection. Developer-aware allowlisting eliminates false positives
//! on dev machines.

pub mod allowlist;
pub mod container_scanner;
pub mod dns_filter;
pub mod file_quarantine;
pub mod fim;
pub mod heuristics;
pub mod memory_scanner;
pub mod network_monitor;
pub mod process_monitor;
pub mod rootkit_detector;
pub mod signatures;
pub mod supply_chain;
pub mod threat_intel;
pub mod usb_monitor;
pub mod watcher;
// pub mod yara_engine;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::audit_chain::{AuditChain, SecurityEventType};

// =============================================================================
// Severity
// =============================================================================

/// Detection severity levels, ordered from lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// =============================================================================
// Detection Category
// =============================================================================

/// Category of a detection, carrying module-specific metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionCategory {
    MalwareSignature { name: String, family: String },
    HeuristicAnomaly { rule: String },
    SuspiciousProcess { pid: u32, name: String },
    NetworkAnomaly { connection: String },
    MemoryAnomaly { pid: u32, region: String },
    RootkitIndicator { technique: String },
    YaraMatch { rule_name: String, tags: Vec<String> },
    FilelessMalware { technique: String },
}

// =============================================================================
// Recommended Action
// =============================================================================

/// Action the engine recommends after a detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendedAction {
    LogOnly,
    Alert,
    Quarantine { source_path: PathBuf },
    KillProcess { pid: u32 },
    BlockConnection { addr: String },
    Multi(Vec<RecommendedAction>),
}

impl std::fmt::Display for RecommendedAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LogOnly => write!(f, "log_only"),
            Self::Alert => write!(f, "alert"),
            Self::Quarantine { source_path } => {
                write!(f, "quarantine({})", source_path.display())
            }
            Self::KillProcess { pid } => write!(f, "kill({})", pid),
            Self::BlockConnection { addr } => write!(f, "block({})", addr),
            Self::Multi(actions) => {
                let names: Vec<String> = actions.iter().map(|a| a.to_string()).collect();
                write!(f, "multi[{}]", names.join(", "))
            }
        }
    }
}

// =============================================================================
// Scan Result
// =============================================================================

/// Unified result returned by every scanner engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Unique detection ID.
    pub id: String,
    /// When the detection occurred.
    pub timestamp: DateTime<Utc>,
    /// Which scanner produced this result.
    pub scanner: String,
    /// What was scanned (file path, PID, connection, etc.).
    pub target: String,
    /// Severity of the detection.
    pub severity: Severity,
    /// Category with detection-specific metadata.
    pub category: DetectionCategory,
    /// Human-readable description.
    pub description: String,
    /// Confidence score 0.0–1.0.
    pub confidence: f64,
    /// Recommended action.
    pub action: RecommendedAction,
    /// SHA-256 of the scanned artifact (if applicable).
    pub artifact_hash: Option<String>,
}

impl ScanResult {
    /// Create a new ScanResult with auto-generated ID and timestamp.
    pub fn new(
        scanner: impl Into<String>,
        target: impl Into<String>,
        severity: Severity,
        category: DetectionCategory,
        description: impl Into<String>,
        confidence: f64,
        action: RecommendedAction,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            scanner: scanner.into(),
            target: target.into(),
            severity,
            category,
            description: description.into(),
            confidence: confidence.clamp(0.0, 1.0),
            action,
            artifact_hash: None,
        }
    }

    /// Attach an artifact hash to this result.
    pub fn with_hash(mut self, hash: String) -> Self {
        self.artifact_hash = Some(hash);
        self
    }
}

// =============================================================================
// Scanner Trait
// =============================================================================

/// Trait that all scanning engines implement.
#[async_trait::async_trait]
pub trait Scanner: Send + Sync {
    /// Human-readable name of this scanner.
    fn name(&self) -> &str;

    /// Whether this scanner is currently enabled and operational.
    fn is_active(&self) -> bool;

    /// Scan a file on disk. Returns empty vec if clean.
    async fn scan_file(&self, path: &Path) -> Vec<ScanResult>;

    /// Scan raw bytes (for in-memory content). Default: no-op.
    async fn scan_bytes(&self, _data: &[u8], _label: &str) -> Vec<ScanResult> {
        Vec::new()
    }

    /// Scan a running process by PID. Default: no-op.
    async fn scan_process(&self, _pid: u32) -> Vec<ScanResult> {
        Vec::new()
    }
}

// =============================================================================
// Endpoint Configuration
// =============================================================================

/// Top-level configuration for the endpoint protection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    pub enabled: bool,
    pub enable_watcher: bool,
    pub enable_process_monitor: bool,
    pub enable_network_monitor: bool,
    pub enable_memory_scanner: bool,
    pub enable_rootkit_detector: bool,
    pub enable_dns_filter: bool,
    pub enable_usb_monitor: bool,
    pub enable_fim: bool,
    pub data_dir: PathBuf,
    pub watcher: watcher::WatcherConfig,
    pub process_monitor: process_monitor::ProcessMonitorConfig,
    pub network_monitor: network_monitor::NetworkMonitorConfig,
    pub memory_scanner: memory_scanner::MemoryScanConfig,
    pub rootkit_detector: rootkit_detector::RootkitConfig,
    pub heuristics: heuristics::HeuristicConfig,
    pub quarantine: file_quarantine::QuarantineVaultConfig,
    pub allowlist: allowlist::AllowlistConfig,
    pub threat_intel: threat_intel::ThreatIntelConfig,
    pub signatures: signatures::SignatureConfig,
    pub dns_filter: dns_filter::DnsFilterConfig,
    pub usb_monitor: usb_monitor::UsbMonitorConfig,
    pub fim: fim::FimConfig,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        let data_dir = dirs_or_default();
        Self {
            enabled: true,
            enable_watcher: true,
            enable_process_monitor: true,
            enable_network_monitor: true,
            enable_memory_scanner: false, // requires elevated privileges
            enable_rootkit_detector: false, // requires root
            enable_dns_filter: false, // opt-in: requires configuring system DNS
            enable_usb_monitor: true, // on by default: monitors for USB insertions
            enable_fim: false, // opt-in: baselines system files, alerts on changes
            data_dir: data_dir.clone(),
            watcher: watcher::WatcherConfig::default(),
            process_monitor: process_monitor::ProcessMonitorConfig::default(),
            network_monitor: network_monitor::NetworkMonitorConfig::default(),
            memory_scanner: memory_scanner::MemoryScanConfig::default(),
            rootkit_detector: rootkit_detector::RootkitConfig::new(data_dir.clone()),
            heuristics: heuristics::HeuristicConfig::default(),
            quarantine: file_quarantine::QuarantineVaultConfig::new(data_dir.join("quarantine")),
            allowlist: allowlist::AllowlistConfig::default(),
            threat_intel: threat_intel::ThreatIntelConfig::new(data_dir.join("threat-intel")),
            signatures: signatures::SignatureConfig::new(data_dir.join("signatures.ndjson")),
            dns_filter: dns_filter::DnsFilterConfig::default(),
            usb_monitor: usb_monitor::UsbMonitorConfig::default(),
            fim: fim::FimConfig::default(),
        }
    }
}

fn dirs_or_default() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".nexus-shield"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/nexus-shield"))
}

// =============================================================================
// Endpoint Stats
// =============================================================================

/// Runtime statistics for the endpoint protection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointStats {
    pub total_files_scanned: u64,
    pub total_threats_detected: u64,
    pub active_monitors: Vec<String>,
    pub quarantined_files: usize,
    pub last_scan_time: Option<DateTime<Utc>>,
    pub scanners_active: Vec<String>,
}

// =============================================================================
// Endpoint Engine
// =============================================================================

/// Orchestrates all endpoint protection subsystems.
pub struct EndpointEngine {
    /// All registered scanning engines.
    scanners: Vec<Arc<dyn Scanner>>,
    /// Developer-aware allowlist.
    pub allowlist: Arc<allowlist::DeveloperAllowlist>,
    /// Threat intelligence database.
    pub threat_intel: Arc<threat_intel::ThreatIntelDB>,
    /// File quarantine vault.
    pub quarantine: Arc<file_quarantine::QuarantineVault>,
    /// DNS filtering proxy.
    pub dns_filter: Option<Arc<dns_filter::DnsFilter>>,
    /// Container image scanner (on-demand).
    pub container_scanner: container_scanner::ContainerScanner,
    /// Supply chain dependency scanner (on-demand).
    pub supply_chain_scanner: supply_chain::SupplyChainScanner,
    /// Broadcast channel for real-time scan results.
    result_tx: tokio::sync::broadcast::Sender<ScanResult>,
    /// Detection history (ring buffer).
    history: Arc<RwLock<VecDeque<ScanResult>>>,
    /// Configuration.
    config: EndpointConfig,
    /// Counters (Arc-wrapped for safe sharing across spawned tasks).
    files_scanned: Arc<AtomicU64>,
    threats_detected: Arc<AtomicU64>,
    /// Whether the engine is running.
    running: AtomicBool,
}

impl EndpointEngine {
    /// Create a new endpoint engine with the given configuration.
    pub fn new(config: EndpointConfig) -> Self {
        let (result_tx, _) = tokio::sync::broadcast::channel(1024);

        // Ensure data directory exists
        let _ = std::fs::create_dir_all(&config.data_dir);
        let _ = std::fs::create_dir_all(config.data_dir.join("quarantine"));
        let _ = std::fs::create_dir_all(config.data_dir.join("threat-intel"));
        tracing::info!(data_dir = %config.data_dir.display(), "Endpoint data directory initialized");

        // Initialize subsystems
        let allowlist = Arc::new(allowlist::DeveloperAllowlist::new(config.allowlist.clone()));
        let threat_intel = Arc::new(threat_intel::ThreatIntelDB::new(config.threat_intel.clone()));
        let quarantine = Arc::new(file_quarantine::QuarantineVault::new(config.quarantine.clone()));

        // DNS filter (if enabled)
        let dns_filter = if config.enable_dns_filter {
            Some(Arc::new(dns_filter::DnsFilter::new(
                config.dns_filter.clone(),
                Arc::clone(&threat_intel),
            )))
        } else {
            None
        };

        // Build scanner list
        let mut scanners: Vec<Arc<dyn Scanner>> = Vec::new();

        // Signature engine
        let sig_engine = signatures::SignatureEngine::new(config.signatures.clone());
        scanners.push(Arc::new(sig_engine));

        // Heuristic engine
        let heur_engine = heuristics::HeuristicEngine::new(config.heuristics.clone());
        scanners.push(Arc::new(heur_engine));

        // YARA engine
        // let yara = yara_engine::YaraEngine::new(None);
        // scanners.push(Arc::new(yara));

        // On-demand scanners
        let container_scanner = container_scanner::ContainerScanner::new(
            container_scanner::ContainerScanConfig::default(),
        );
        let supply_chain_scanner = supply_chain::SupplyChainScanner::new(
            supply_chain::SupplyChainConfig::default(),
        );

        Self {
            scanners,
            allowlist,
            threat_intel,
            quarantine,
            dns_filter,
            container_scanner,
            supply_chain_scanner,
            result_tx,
            history: Arc::new(RwLock::new(VecDeque::with_capacity(10000))),
            config,
            files_scanned: Arc::new(AtomicU64::new(0)),
            threats_detected: Arc::new(AtomicU64::new(0)),
            running: AtomicBool::new(false),
        }
    }

    /// Start all background monitors. Returns JoinHandles for spawned tasks.
    pub async fn start(&self, audit: Arc<AuditChain>) -> Vec<tokio::task::JoinHandle<()>> {
        self.running.store(true, Ordering::SeqCst);
        let mut handles = Vec::new();

        // Record startup event
        audit.record(
            SecurityEventType::EndpointScanStarted,
            "system",
            "Endpoint protection engine started",
            0.0,
        );

        // Start file watcher
        if self.config.enable_watcher {
            let (scan_tx, mut scan_rx) = tokio::sync::mpsc::unbounded_channel::<PathBuf>();
            let watcher_handle = watcher::FileWatcher::new(
                self.config.watcher.clone(),
                scan_tx,
            );

            let allowlist = Arc::clone(&self.allowlist);
            let _watcher_task = watcher_handle.start(allowlist);

            // File scan consumer task
            let scanners = self.scanners.clone();
            let result_tx = self.result_tx.clone();
            let history = Arc::clone(&self.history);
            let quarantine = Arc::clone(&self.quarantine);
            let audit2 = Arc::clone(&audit);
            let files_scanned = Arc::clone(&self.files_scanned);
            let threats_detected = Arc::clone(&self.threats_detected);

            let handle = tokio::spawn(async move {
                while let Some(path) = scan_rx.recv().await {
                    tracing::debug!(file = %path.display(), "Scanning file");

                    // Run all scanners on the file
                    let mut all_results = Vec::new();
                    for scanner in &scanners {
                        if scanner.is_active() {
                            let results = scanner.scan_file(&path).await;
                            all_results.extend(results);
                        }
                    }

                    files_scanned.fetch_add(1, Ordering::Relaxed);

                    if all_results.is_empty() {
                        tracing::trace!(file = %path.display(), "File clean");
                    } else {
                        tracing::warn!(
                            file = %path.display(),
                            threats = all_results.len(),
                            "THREAT DETECTED"
                        );
                    }

                    // Process results
                    for result in all_results {
                        threats_detected.fetch_add(1, Ordering::Relaxed);

                        // Quarantine if needed
                        if let RecommendedAction::Quarantine { ref source_path } = result.action {
                            let _ = quarantine.quarantine_file(
                                source_path,
                                &result.description,
                                &result.scanner,
                                result.severity,
                            );
                        }

                        // Record to audit chain
                        audit2.record(
                            SecurityEventType::MalwareDetected,
                            &result.target,
                            &result.description,
                            result.confidence,
                        );

                        // Broadcast and save to history
                        let _ = result_tx.send(result.clone());
                        let mut hist = history.write();
                        if hist.len() >= 10000 {
                            hist.pop_front();
                        }
                        hist.push_back(result);
                    }
                }
            });
            handles.push(handle);
        }

        // Start DNS filter proxy
        if self.config.enable_dns_filter {
            if let Some(ref dns) = self.dns_filter {
                let (dns_tx, mut dns_rx) = tokio::sync::mpsc::unbounded_channel::<ScanResult>();
                let dns_handle = Arc::clone(dns).start(dns_tx);
                handles.push(dns_handle);

                // DNS detection consumer
                let history = Arc::clone(&self.history);
                let audit3 = Arc::clone(&audit);
                let result_tx = self.result_tx.clone();
                let threats_detected = Arc::clone(&self.threats_detected);
                let dns_consumer = tokio::spawn(async move {
                    while let Some(result) = dns_rx.recv().await {
                        threats_detected.fetch_add(1, Ordering::Relaxed);
                        audit3.record(
                            SecurityEventType::MalwareDetected,
                            &result.target,
                            &result.description,
                            result.confidence,
                        );
                        let _ = result_tx.send(result.clone());
                        let mut hist = history.write();
                        if hist.len() >= 10000 {
                            hist.pop_front();
                        }
                        hist.push_back(result);
                    }
                });
                handles.push(dns_consumer);
            }
        }

        // Start USB monitor
        if self.config.enable_usb_monitor {
            let (usb_tx, mut usb_rx) = tokio::sync::mpsc::unbounded_channel::<ScanResult>();
            let usb_mon = Arc::new(usb_monitor::UsbMonitor::new(self.config.usb_monitor.clone()));
            let usb_handle = Arc::clone(&usb_mon).start(usb_tx);
            handles.push(usb_handle);

            // USB detection consumer
            let history = Arc::clone(&self.history);
            let audit4 = Arc::clone(&audit);
            let result_tx = self.result_tx.clone();
            let threats_detected = Arc::clone(&self.threats_detected);
            let usb_consumer = tokio::spawn(async move {
                while let Some(result) = usb_rx.recv().await {
                    threats_detected.fetch_add(1, Ordering::Relaxed);
                    audit4.record(
                        SecurityEventType::MalwareDetected,
                        &result.target,
                        &result.description,
                        result.confidence,
                    );
                    let _ = result_tx.send(result.clone());
                    let mut hist = history.write();
                    if hist.len() >= 10000 {
                        hist.pop_front();
                    }
                    hist.push_back(result);
                }
            });
            handles.push(usb_consumer);
        }

        // Start process monitor
        if self.config.enable_process_monitor {
            let (pm_tx, mut pm_rx) = tokio::sync::mpsc::unbounded_channel::<ScanResult>();
            let proc_mon = Arc::new(process_monitor::ProcessMonitor::new(self.config.process_monitor.clone()));
            let pm_handle = Arc::clone(&proc_mon).start(pm_tx);
            handles.push(pm_handle);

            let history = Arc::clone(&self.history);
            let audit_pm = Arc::clone(&audit);
            let result_tx = self.result_tx.clone();
            let threats_detected = Arc::clone(&self.threats_detected);
            let pm_consumer = tokio::spawn(async move {
                while let Some(result) = pm_rx.recv().await {
                    threats_detected.fetch_add(1, Ordering::Relaxed);
                    audit_pm.record(SecurityEventType::SuspiciousProcess, &result.target, &result.description, result.confidence);
                    let _ = result_tx.send(result.clone());
                    let mut hist = history.write();
                    if hist.len() >= 10000 { hist.pop_front(); }
                    hist.push_back(result);
                }
            });
            handles.push(pm_consumer);
        }

        // Start network monitor
        if self.config.enable_network_monitor {
            let (nm_tx, mut nm_rx) = tokio::sync::mpsc::unbounded_channel::<ScanResult>();
            let net_mon = Arc::new(network_monitor::NetworkMonitor::new(
                self.config.network_monitor.clone(),
                Arc::clone(&self.threat_intel),
            ));
            let nm_handle = Arc::clone(&net_mon).start(nm_tx);
            handles.push(nm_handle);

            let history = Arc::clone(&self.history);
            let audit_nm = Arc::clone(&audit);
            let result_tx = self.result_tx.clone();
            let threats_detected = Arc::clone(&self.threats_detected);
            let nm_consumer = tokio::spawn(async move {
                while let Some(result) = nm_rx.recv().await {
                    threats_detected.fetch_add(1, Ordering::Relaxed);
                    audit_nm.record(SecurityEventType::SuspiciousNetwork, &result.target, &result.description, result.confidence);
                    let _ = result_tx.send(result.clone());
                    let mut hist = history.write();
                    if hist.len() >= 10000 { hist.pop_front(); }
                    hist.push_back(result);
                }
            });
            handles.push(nm_consumer);
        }

        // Start memory scanner
        if self.config.enable_memory_scanner {
            let (ms_tx, mut ms_rx) = tokio::sync::mpsc::unbounded_channel::<ScanResult>();
            let mem_scan = Arc::new(memory_scanner::MemoryScanner::new(self.config.memory_scanner.clone()));
            let ms_handle = Arc::clone(&mem_scan).start(ms_tx);
            handles.push(ms_handle);

            let history = Arc::clone(&self.history);
            let audit_ms = Arc::clone(&audit);
            let result_tx = self.result_tx.clone();
            let threats_detected = Arc::clone(&self.threats_detected);
            let ms_consumer = tokio::spawn(async move {
                while let Some(result) = ms_rx.recv().await {
                    threats_detected.fetch_add(1, Ordering::Relaxed);
                    audit_ms.record(SecurityEventType::MemoryAnomaly, &result.target, &result.description, result.confidence);
                    let _ = result_tx.send(result.clone());
                    let mut hist = history.write();
                    if hist.len() >= 10000 { hist.pop_front(); }
                    hist.push_back(result);
                }
            });
            handles.push(ms_consumer);
        }

        // Start rootkit detector
        if self.config.enable_rootkit_detector {
            let (rk_tx, mut rk_rx) = tokio::sync::mpsc::unbounded_channel::<ScanResult>();
            let rk_det = Arc::new(rootkit_detector::RootkitDetector::new(self.config.rootkit_detector.clone()));
            let rk_handle = Arc::clone(&rk_det).start(rk_tx);
            handles.push(rk_handle);

            let history = Arc::clone(&self.history);
            let audit_rk = Arc::clone(&audit);
            let result_tx = self.result_tx.clone();
            let threats_detected = Arc::clone(&self.threats_detected);
            let rk_consumer = tokio::spawn(async move {
                while let Some(result) = rk_rx.recv().await {
                    threats_detected.fetch_add(1, Ordering::Relaxed);
                    audit_rk.record(SecurityEventType::RootkitIndicator, &result.target, &result.description, result.confidence);
                    let _ = result_tx.send(result.clone());
                    let mut hist = history.write();
                    if hist.len() >= 10000 { hist.pop_front(); }
                    hist.push_back(result);
                }
            });
            handles.push(rk_consumer);
        }

        // Start File Integrity Monitor
        if self.config.enable_fim {
            let (fim_tx, mut fim_rx) = tokio::sync::mpsc::unbounded_channel::<ScanResult>();
            let fim_mon = Arc::new(fim::FimMonitor::new(self.config.fim.clone()));
            let fim_handle = Arc::clone(&fim_mon).start(fim_tx);
            handles.push(fim_handle);

            // FIM detection consumer
            let history = Arc::clone(&self.history);
            let audit5 = Arc::clone(&audit);
            let result_tx = self.result_tx.clone();
            let threats_detected = Arc::clone(&self.threats_detected);
            let fim_consumer = tokio::spawn(async move {
                while let Some(result) = fim_rx.recv().await {
                    threats_detected.fetch_add(1, Ordering::Relaxed);
                    audit5.record(
                        SecurityEventType::MalwareDetected,
                        &result.target,
                        &result.description,
                        result.confidence,
                    );
                    let _ = result_tx.send(result.clone());
                    let mut hist = history.write();
                    if hist.len() >= 10000 {
                        hist.pop_front();
                    }
                    hist.push_back(result);
                }
            });
            handles.push(fim_consumer);
        }

        handles
    }

    /// Scan a single file with all engines.
    pub async fn scan_file(&self, path: &Path) -> Vec<ScanResult> {
        if self.allowlist.should_skip_path(path) {
            return Vec::new();
        }

        self.files_scanned.fetch_add(1, Ordering::Relaxed);
        let mut results = Vec::new();

        // Check if it's a dependency lock file (supply chain scan)
        if supply_chain::SupplyChainScanner::detect_ecosystem(path).is_some() {
            let mut sc_results = self.supply_chain_scanner.scan_file(path);
            results.append(&mut sc_results);
        }

        for scanner in &self.scanners {
            if scanner.is_active() {
                let mut r = scanner.scan_file(path).await;
                results.append(&mut r);
            }
        }

        if !results.is_empty() {
            self.threats_detected
                .fetch_add(results.len() as u64, Ordering::Relaxed);
            let mut hist = self.history.write();
            for r in &results {
                if hist.len() >= 10000 {
                    hist.pop_front();
                }
                hist.push_back(r.clone());
            }
        }

        results
    }

    /// Scan a directory recursively.
    pub async fn scan_dir(&self, dir: &Path) -> Vec<ScanResult> {
        let mut results = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if !self.allowlist.should_skip_path(&path) {
                        let mut r = Box::pin(self.scan_dir(&path)).await;
                        results.append(&mut r);
                    }
                } else if path.is_file() {
                    let mut r = self.scan_file(&path).await;
                    results.append(&mut r);
                }
            }
        }
        results
    }

    /// Scan a Docker image for security issues.
    pub fn scan_container_image(&self, image: &str) -> Vec<ScanResult> {
        self.container_scanner.scan_image(image)
    }

    /// Scan a dependency lock file for supply chain risks.
    pub fn scan_dependencies(&self, path: &Path) -> Vec<ScanResult> {
        self.supply_chain_scanner.scan_file(path)
    }

    /// Subscribe to real-time scan results.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ScanResult> {
        self.result_tx.subscribe()
    }

    /// Get recent detection history.
    pub fn recent_detections(&self, count: usize) -> Vec<ScanResult> {
        let hist = self.history.read();
        hist.iter().rev().take(count).cloned().collect()
    }

    /// Get runtime statistics.
    pub fn stats(&self) -> EndpointStats {
        let mut active = Vec::new();
        if self.config.enable_watcher {
            active.push("file_watcher".to_string());
        }
        if self.config.enable_process_monitor {
            active.push("process_monitor".to_string());
        }
        if self.config.enable_network_monitor {
            active.push("network_monitor".to_string());
        }
        if self.config.enable_memory_scanner {
            active.push("memory_scanner".to_string());
        }
        if self.config.enable_rootkit_detector {
            active.push("rootkit_detector".to_string());
        }
        if self.config.enable_dns_filter {
            active.push("dns_filter".to_string());
        }
        if self.config.enable_usb_monitor {
            active.push("usb_monitor".to_string());
        }
        if self.config.enable_fim {
            active.push("fim".to_string());
        }

        let scanner_names: Vec<String> = self
            .scanners
            .iter()
            .filter(|s| s.is_active())
            .map(|s| s.name().to_string())
            .collect();

        EndpointStats {
            total_files_scanned: self.files_scanned.load(Ordering::Relaxed),
            total_threats_detected: self.threats_detected.load(Ordering::Relaxed),
            active_monitors: active,
            quarantined_files: self.quarantine.list_entries().len(),
            last_scan_time: self.history.read().back().map(|r| r.timestamp),
            scanners_active: scanner_names,
        }
    }

    /// Check if the engine is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::Info.to_string(), "info");
    }

    #[test]
    fn test_scan_result_creation() {
        let result = ScanResult::new(
            "test_scanner",
            "/tmp/malware.exe",
            Severity::High,
            DetectionCategory::MalwareSignature {
                name: "EICAR".to_string(),
                family: "Test".to_string(),
            },
            "EICAR test file detected",
            0.99,
            RecommendedAction::Quarantine {
                source_path: PathBuf::from("/tmp/malware.exe"),
            },
        );
        assert!(!result.id.is_empty());
        assert_eq!(result.scanner, "test_scanner");
        assert_eq!(result.severity, Severity::High);
        assert_eq!(result.confidence, 0.99);
    }

    #[test]
    fn test_scan_result_with_hash() {
        let result = ScanResult::new(
            "sig",
            "/tmp/test",
            Severity::Low,
            DetectionCategory::HeuristicAnomaly {
                rule: "test".to_string(),
            },
            "test",
            0.5,
            RecommendedAction::LogOnly,
        )
        .with_hash("abc123".to_string());
        assert_eq!(result.artifact_hash, Some("abc123".to_string()));
    }

    #[test]
    fn test_confidence_clamping() {
        let r1 = ScanResult::new(
            "s", "t", Severity::Low,
            DetectionCategory::HeuristicAnomaly { rule: "x".into() },
            "d", 1.5, RecommendedAction::LogOnly,
        );
        assert_eq!(r1.confidence, 1.0);

        let r2 = ScanResult::new(
            "s", "t", Severity::Low,
            DetectionCategory::HeuristicAnomaly { rule: "x".into() },
            "d", -0.5, RecommendedAction::LogOnly,
        );
        assert_eq!(r2.confidence, 0.0);
    }

    #[test]
    fn test_recommended_action_display() {
        assert_eq!(RecommendedAction::LogOnly.to_string(), "log_only");
        assert_eq!(RecommendedAction::Alert.to_string(), "alert");
        assert_eq!(
            RecommendedAction::KillProcess { pid: 1234 }.to_string(),
            "kill(1234)"
        );
    }

    #[test]
    fn test_endpoint_config_default() {
        let config = EndpointConfig::default();
        assert!(config.enabled);
        assert!(config.enable_watcher);
        assert!(config.enable_process_monitor);
        assert!(!config.enable_memory_scanner); // requires elevated
        assert!(!config.enable_rootkit_detector); // requires root
        assert!(!config.enable_dns_filter); // opt-in
        assert!(config.enable_usb_monitor); // on by default
        assert!(!config.enable_fim); // opt-in
    }
}