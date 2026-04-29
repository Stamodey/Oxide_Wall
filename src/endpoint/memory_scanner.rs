// ============================================================================
// File: endpoint/memory_scanner.rs
// Description: Shellcode and injected code detection via /proc/[pid]/maps
// ============================================================================
//! Memory Scanner — detects shellcode, RWX memory regions, NOP sleds, and
//! injected code by reading /proc/[pid]/maps and /proc/[pid]/mem.

use super::{DetectionCategory, RecommendedAction, ScanResult, Severity};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Configuration for the memory scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanConfig {
    pub scan_interval_secs: u64,
    pub scan_suspicious_only: bool,
    pub max_region_size: u64,
}

impl Default for MemoryScanConfig {
    fn default() -> Self {
        Self {
            scan_interval_secs: 30,
            scan_suspicious_only: true,
            max_region_size: 10_485_760, // 10 MB
        }
    }
}

/// A shellcode byte pattern with optional wildcard mask.
#[derive(Debug, Clone)]
pub struct ShellcodePattern {
    pub name: String,
    pub pattern: Vec<u8>,
    pub mask: Vec<u8>, // 0xFF = must match, 0x00 = wildcard
    pub severity: Severity,
}

/// A parsed entry from /proc/[pid]/maps.
#[derive(Debug, Clone)]
pub struct MapsEntry {
    pub start_addr: u64,
    pub end_addr: u64,
    pub perms: String,
    pub offset: u64,
    pub path: String,
    pub is_rwx: bool,
    pub is_anonymous: bool,
}

/// Memory scanner for detecting shellcode and code injection.
pub struct MemoryScanner {
    config: MemoryScanConfig,
    shellcode_patterns: Vec<ShellcodePattern>,
    running: Arc<AtomicBool>,
}

impl MemoryScanner {
    pub fn new(config: MemoryScanConfig) -> Self {
        Self {
            config,
            shellcode_patterns: builtin_patterns(),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Parse a single line from /proc/[pid]/maps.
    pub fn parse_maps_line(line: &str) -> Option<MapsEntry> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }

        let fields: Vec<&str> = line.splitn(6, char::is_whitespace).collect();
        if fields.len() < 5 {
            return None;
        }

        // Field 0: address range "7f1234000000-7f1234001000"
        let addr_parts: Vec<&str> = fields[0].split('-').collect();
        if addr_parts.len() != 2 {
            return None;
        }
        let start_addr = u64::from_str_radix(addr_parts[0], 16).ok()?;
        let end_addr = u64::from_str_radix(addr_parts[1], 16).ok()?;

        // Field 1: permissions "rwxp"
        let perms = fields[1].to_string();
        let is_rwx = perms.contains('r') && perms.contains('w') && perms.contains('x');

        // Field 2: offset
        let offset = u64::from_str_radix(fields[2], 16).unwrap_or(0);

        // Field 5: pathname (may not exist for anonymous mappings)
        let path = if fields.len() >= 6 {
            fields[5].trim().to_string()
        } else {
            String::new()
        };

        let is_anonymous = path.is_empty() || path.starts_with('[');

        Some(MapsEntry {
            start_addr,
            end_addr,
            perms,
            offset,
            path,
            is_rwx,
            is_anonymous,
        })
    }

    /// Parse all lines from /proc/[pid]/maps content.
    pub fn parse_maps(content: &str) -> Vec<MapsEntry> {
        content
            .lines()
            .filter_map(|line| Self::parse_maps_line(line))
            .collect()
    }

    /// Find RWX (read-write-execute) memory regions for a process.
    pub fn find_rwx_regions(pid: u32) -> Vec<MapsEntry> {
        let maps_path = format!("/proc/{}/maps", pid);
        let content = match std::fs::read_to_string(&maps_path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        Self::parse_maps(&content)
            .into_iter()
            .filter(|e| e.is_rwx)
            .collect()
    }

    /// Match a shellcode pattern against data using a byte mask.
    /// Returns offsets of all matches.
    pub fn pattern_match(data: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<usize> {
        if pattern.is_empty() || data.len() < pattern.len() || mask.len() != pattern.len() {
            return Vec::new();
        }

        let mut matches = Vec::new();
        for i in 0..=(data.len() - pattern.len()) {
            let mut matched = true;
            for j in 0..pattern.len() {
                if (data[i + j] & mask[j]) != (pattern[j] & mask[j]) {
                    matched = false;
                    break;
                }
            }
            if matched {
                matches.push(i);
            }
        }
        matches
    }

    /// Scan a process's memory for shellcode and suspicious regions.
    pub fn scan_process_memory(&self, pid: u32) -> Vec<ScanResult> {
        let mut results = Vec::new();

        let rwx_regions = Self::find_rwx_regions(pid);

        // Each RWX region is already suspicious
        for region in &rwx_regions {
            if region.is_anonymous {
                results.push(ScanResult::new(
                    "memory_scanner",
                    format!("pid:{} region:0x{:x}-0x{:x}", pid, region.start_addr, region.end_addr),
                    Severity::Medium,
                    DetectionCategory::MemoryAnomaly {
                        pid,
                        region: format!("0x{:x}-0x{:x}", region.start_addr, region.end_addr),
                    },
                    format!(
                        "Anonymous RWX memory region at 0x{:x}-0x{:x} ({} bytes) — uncommon in legitimate processes",
                        region.start_addr,
                        region.end_addr,
                        region.end_addr - region.start_addr
                    ),
                    0.6,
                    RecommendedAction::Alert,
                ));
            }

            // Try to read memory and scan for shellcode
            let region_size = region.end_addr - region.start_addr;
            if region_size > self.config.max_region_size {
                continue;
            }

            let mem_path = format!("/proc/{}/mem", pid);
            let data = match read_proc_mem(&mem_path, region.start_addr, region_size as usize) {
                Some(d) => d,
                None => continue, // Permission denied is normal
            };

            // Scan for shellcode patterns
            for pattern in &self.shellcode_patterns {
                let offsets = Self::pattern_match(&data, &pattern.pattern, &pattern.mask);
                if !offsets.is_empty() {
                    results.push(ScanResult::new(
                        "memory_scanner",
                        format!("pid:{} region:0x{:x}", pid, region.start_addr + offsets[0] as u64),
                        pattern.severity,
                        DetectionCategory::FilelessMalware {
                            technique: pattern.name.clone(),
                        },
                        format!(
                            "Shellcode pattern '{}' found at {} offsets in RWX memory of PID {} — possible code injection",
                            pattern.name, offsets.len(), pid
                        ),
                        0.85,
                        RecommendedAction::KillProcess { pid },
                    ));
                }
            }
        }

        results
    }

    /// Scan all processes for suspicious memory.
    pub fn scan_all_processes(&self) -> Vec<ScanResult> {
        let mut results = Vec::new();

        let entries = match std::fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => return results,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let pid: u32 = match name.to_string_lossy().parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let mut r = self.scan_process_memory(pid);
            results.append(&mut r);
        }

        results
    }

    /// Start periodic memory scanning in a background task.
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
                let results = self.scan_all_processes();
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

/// Built-in shellcode detection patterns.
fn builtin_patterns() -> Vec<ShellcodePattern> {
    vec![
        ShellcodePattern {
            name: "x86_64_syscall_preamble".to_string(),
            pattern: vec![0x48, 0x31, 0xc0, 0x48, 0x31, 0xff],
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            severity: Severity::High,
        },
        ShellcodePattern {
            name: "x86_int80_shellcode".to_string(),
            pattern: vec![0x31, 0xc0, 0x50, 0x68],
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
            severity: Severity::High,
        },
        ShellcodePattern {
            name: "nop_sled_16".to_string(),
            pattern: vec![0x90; 16],
            mask: vec![0xFF; 16],
            severity: Severity::Medium,
        },
        ShellcodePattern {
            name: "reverse_tcp_socket".to_string(),
            pattern: vec![0x6a, 0x29, 0x58, 0x6a, 0x02],
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            severity: Severity::Critical,
        },
        ShellcodePattern {
            name: "meterpreter_marker".to_string(),
            pattern: b"meterpreter".to_vec(),
            mask: vec![0xFF; 11],
            severity: Severity::Critical,
        },
        ShellcodePattern {
            name: "metasploit_marker".to_string(),
            pattern: b"metasploit".to_vec(),
            mask: vec![0xFF; 10],
            severity: Severity::Critical,
        },
        ShellcodePattern {
            name: "cobalt_strike_beacon".to_string(),
            pattern: b"beacon.dll".to_vec(),
            mask: vec![0xFF; 10],
            severity: Severity::Critical,
        },
    ]
}

/// Read a region of /proc/[pid]/mem. Returns None on error (permission denied, etc.).
fn read_proc_mem(path: &str, offset: u64, size: usize) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = vec![0u8; size];
    let n = file.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_maps_line_normal() {
        let line = "7f1234000000-7f1234001000 r-xp 00000000 08:01 12345  /usr/bin/cat";
        let entry = MemoryScanner::parse_maps_line(line).unwrap();
        assert_eq!(entry.start_addr, 0x7f1234000000);
        assert_eq!(entry.end_addr, 0x7f1234001000);
        assert_eq!(entry.perms, "r-xp");
        assert!(!entry.is_rwx);
        assert!(!entry.is_anonymous);
        assert_eq!(entry.path, "/usr/bin/cat");
    }

    #[test]
    fn parse_maps_line_rwx_anonymous() {
        let line = "7ffc00000000-7ffc00010000 rwxp 00000000 00:00 0";
        let entry = MemoryScanner::parse_maps_line(line).unwrap();
        assert!(entry.is_rwx);
        assert!(entry.is_anonymous);
    }

    #[test]
    fn parse_maps_line_heap() {
        let line = "55a000000000-55a000100000 rw-p 00000000 00:00 0  [heap]";
        let entry = MemoryScanner::parse_maps_line(line).unwrap();
        assert!(!entry.is_rwx); // heap is rw- not rwx
        assert!(entry.is_anonymous); // [heap] starts with [
    }

    #[test]
    fn pattern_match_exact() {
        let data = vec![0x00, 0x48, 0x31, 0xc0, 0x48, 0x31, 0xff, 0x00];
        let pattern = vec![0x48, 0x31, 0xc0, 0x48, 0x31, 0xff];
        let mask = vec![0xFF; 6];
        let matches = MemoryScanner::pattern_match(&data, &pattern, &mask);
        assert_eq!(matches, vec![1]);
    }

    #[test]
    fn pattern_match_with_wildcard() {
        let data = vec![0x48, 0x31, 0xAA, 0x48, 0x31, 0xBB];
        let pattern = vec![0x48, 0x31, 0x00, 0x48, 0x31, 0x00];
        let mask = vec![0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0x00]; // wildcards at positions 2,5
        let matches = MemoryScanner::pattern_match(&data, &pattern, &mask);
        assert_eq!(matches, vec![0]);
    }

    #[test]
    fn nop_sled_detection() {
        let mut data = vec![0x00; 100];
        // Insert 16 NOPs at offset 20
        for i in 20..36 {
            data[i] = 0x90;
        }
        let pattern = vec![0x90; 16];
        let mask = vec![0xFF; 16];
        let matches = MemoryScanner::pattern_match(&data, &pattern, &mask);
        assert_eq!(matches, vec![20]);
    }

    #[test]
    fn meterpreter_detection() {
        let data = b"some data meterpreter session more data";
        let pattern = b"meterpreter".to_vec();
        let mask = vec![0xFF; 11];
        let matches = MemoryScanner::pattern_match(data, &pattern, &mask);
        assert!(!matches.is_empty());
    }

    #[test]
    fn no_false_positive_on_clean_data() {
        let data = b"This is perfectly normal program text without any shellcode.";
        let scanner = MemoryScanner::new(MemoryScanConfig::default());
        for pattern in &scanner.shellcode_patterns {
            let matches =
                MemoryScanner::pattern_match(data, &pattern.pattern, &pattern.mask);
            assert!(
                matches.is_empty(),
                "False positive for pattern '{}'",
                pattern.name
            );
        }
    }

    #[test]
    fn pattern_match_empty() {
        assert!(MemoryScanner::pattern_match(&[], &[0x90], &[0xFF]).is_empty());
        assert!(MemoryScanner::pattern_match(&[0x90], &[], &[]).is_empty());
    }

    #[test]
    fn config_defaults() {
        let config = MemoryScanConfig::default();
        assert_eq!(config.scan_interval_secs, 30);
        assert!(config.scan_suspicious_only);
        assert!(config.max_region_size > 0);
    }
}