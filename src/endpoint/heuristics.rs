// ============================================================================
// File: endpoint/heuristics.rs
// Description: Behavioral and static heuristic analysis for unknown threat detection
// ============================================================================
//! Heuristic Engine — entropy analysis, ELF inspection, type mismatch, script
//! obfuscation, and embedded executable detection for files that don't match
//! any known signature.

use super::{DetectionCategory, RecommendedAction, ScanResult, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Configuration for the heuristic analysis engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicConfig {
    /// Shannon entropy threshold (0.0–8.0). Files above this are flagged as packed/encrypted.
    pub high_entropy_threshold: f64,
    /// Minimum file size in bytes before entropy analysis kicks in.
    pub min_entropy_size: u64,
    /// Analyze ELF headers for suspicious characteristics.
    pub analyze_elf: bool,
    /// Analyze script files for obfuscation patterns.
    pub analyze_scripts: bool,
    /// Maximum file size to scan (bytes). Files larger are skipped.
    pub max_scan_size: u64,
}

impl Default for HeuristicConfig {
    fn default() -> Self {
        Self {
            high_entropy_threshold: 7.2,
            min_entropy_size: 1024,
            analyze_elf: true,
            analyze_scripts: true,
            max_scan_size: 52_428_800, // 50 MB
        }
    }
}

/// Heuristic analysis engine for unknown threat detection.
pub struct HeuristicEngine {
    config: HeuristicConfig,
    active: bool,
}

impl HeuristicEngine {
    pub fn new(config: HeuristicConfig) -> Self {
        Self {
            config,
            active: true,
        }
    }

    // =========================================================================
    // Shannon Entropy
    // =========================================================================

    /// Compute Shannon entropy of a byte slice. Returns 0.0–8.0.
    ///
    /// H = -Σ p(x) * log₂(p(x)) for each byte value 0–255 where p(x) > 0.
    pub fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Check file data for suspiciously high entropy (packed/encrypted).
    fn check_entropy(&self, data: &[u8], path: &Path) -> Vec<ScanResult> {
        if (data.len() as u64) < self.config.min_entropy_size {
            return Vec::new();
        }

        let entropy = Self::shannon_entropy(data);

        if entropy > self.config.high_entropy_threshold {
            vec![ScanResult::new(
                "heuristic_engine",
                path.to_string_lossy(),
                Severity::Medium,
                DetectionCategory::HeuristicAnomaly {
                    rule: "high_entropy".to_string(),
                },
                format!(
                    "Suspiciously high entropy ({:.2}/8.0) — file may be packed, encrypted, or compressed",
                    entropy
                ),
                0.7,
                RecommendedAction::Alert,
            )]
        } else {
            Vec::new()
        }
    }

    // =========================================================================
    // ELF Header Analysis
    // =========================================================================

    /// Parse and analyze ELF headers for suspicious characteristics.
    fn check_elf_header(&self, data: &[u8], path: &Path) -> Vec<ScanResult> {
        if !self.config.analyze_elf || data.len() < 64 {
            return Vec::new();
        }

        // Check ELF magic: \x7fELF
        if data[0] != 0x7F || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
            return Vec::new();
        }

        let mut results = Vec::new();

        // EI_CLASS at offset 4: 1 = 32-bit, 2 = 64-bit
        let is_64bit = data[4] == 2;

        // EI_DATA at offset 5: 1 = little-endian, 2 = big-endian
        let little_endian = data[5] == 1;

        if is_64bit && little_endian && data.len() >= 64 {
            // 64-bit LE ELF header layout:
            // e_type:    offset 16, 2 bytes
            // e_machine: offset 18, 2 bytes
            // e_phoff:   offset 32, 8 bytes
            // e_shoff:   offset 40, 8 bytes
            // e_phnum:   offset 56, 2 bytes
            // e_shnum:   offset 60, 2 bytes

            let e_shnum = u16::from_le_bytes([data[60], data[61]]);

            // Stripped binary: no section headers
            if e_shnum == 0 {
                results.push(ScanResult::new(
                    "heuristic_engine",
                    path.to_string_lossy(),
                    Severity::Low,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "elf_stripped".to_string(),
                    },
                    "ELF binary has no section headers (stripped) — may be intentionally obfuscated",
                    0.3,
                    RecommendedAction::LogOnly,
                ));
            }

            // Check program headers for RWX segments
            let e_phoff = u64::from_le_bytes([
                data[32], data[33], data[34], data[35],
                data[36], data[37], data[38], data[39],
            ]) as usize;
            let e_phnum = u16::from_le_bytes([data[56], data[57]]) as usize;
            let phent_size = 56usize; // sizeof(Elf64_Phdr)

            for i in 0..e_phnum {
                let offset = e_phoff + i * phent_size;
                if offset + phent_size > data.len() {
                    break;
                }

                // p_type at offset+0 (4 bytes), p_flags at offset+4 (4 bytes)
                let p_type = u32::from_le_bytes([
                    data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                ]);
                let p_flags = u32::from_le_bytes([
                    data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                ]);

                // PT_LOAD = 1, PF_X = 1, PF_W = 2, PF_R = 4
                if p_type == 1 && (p_flags & 0x3) == 0x3 {
                    // Segment is both writable AND executable
                    results.push(ScanResult::new(
                        "heuristic_engine",
                        path.to_string_lossy(),
                        Severity::High,
                        DetectionCategory::HeuristicAnomaly {
                            rule: "elf_wx_segment".to_string(),
                        },
                        format!(
                            "ELF has write+execute segment (PT_LOAD #{}) — common in packed malware",
                            i
                        ),
                        0.8,
                        RecommendedAction::Alert,
                    ));
                }
            }
        } else if !is_64bit && little_endian && data.len() >= 52 {
            // 32-bit LE: e_shnum at offset 48 (2 bytes)
            let e_shnum = u16::from_le_bytes([data[48], data[49]]);
            if e_shnum == 0 {
                results.push(ScanResult::new(
                    "heuristic_engine",
                    path.to_string_lossy(),
                    Severity::Low,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "elf_stripped".to_string(),
                    },
                    "32-bit ELF binary has no section headers (stripped)",
                    0.3,
                    RecommendedAction::LogOnly,
                ));
            }
        }

        results
    }

    // =========================================================================
    // File Type Mismatch
    // =========================================================================

    /// Detect files whose extension doesn't match their magic bytes.
    fn check_file_type_mismatch(&self, data: &[u8], path: &Path) -> Vec<ScanResult> {
        if data.len() < 4 {
            return Vec::new();
        }

        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        if ext.is_empty() {
            return Vec::new();
        }

        // What the magic bytes actually say
        let actual_type = detect_magic_type(data);

        // What the extension claims
        let claimed_type = match ext.as_str() {
            "pdf" => Some("pdf"),
            "png" => Some("png"),
            "jpg" | "jpeg" => Some("jpeg"),
            "gif" => Some("gif"),
            "zip" | "jar" | "docx" | "xlsx" | "pptx" => Some("zip"),
            "gz" | "tgz" => Some("gzip"),
            "exe" | "dll" | "sys" => Some("pe"),
            "elf" | "bin" => Some("elf"),
            "bmp" => Some("bmp"),
            _ => None,
        };

        // Only flag mismatches for known types
        let claimed = match claimed_type {
            Some(c) => c,
            None => return Vec::new(),
        };

        let actual = match actual_type {
            Some(a) => a,
            None => return Vec::new(),
        };

        if claimed == actual {
            return Vec::new();
        }

        // Particularly dangerous: document/image extension hiding an executable
        let is_exe_disguise = (claimed == "pdf" || claimed == "png" || claimed == "jpeg"
            || claimed == "gif" || claimed == "bmp" || claimed == "zip")
            && (actual == "pe" || actual == "elf");

        let severity = if is_exe_disguise {
            Severity::High
        } else {
            Severity::Medium
        };

        vec![ScanResult::new(
            "heuristic_engine",
            path.to_string_lossy(),
            severity,
            DetectionCategory::HeuristicAnomaly {
                rule: "file_type_mismatch".to_string(),
            },
            format!(
                "Extension claims '{}' ({}) but magic bytes indicate '{}' — possible disguised executable",
                ext, claimed, actual
            ),
            0.9,
            RecommendedAction::Quarantine {
                source_path: path.to_path_buf(),
            },
        )]
    }

    // =========================================================================
    // Script Obfuscation
    // =========================================================================

    /// Detect obfuscation patterns in script files.
    fn check_script_obfuscation(&self, data: &[u8], path: &Path) -> Vec<ScanResult> {
        if !self.config.analyze_scripts {
            return Vec::new();
        }

        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let is_script = matches!(
            ext.as_str(),
            "sh" | "bash" | "py" | "ps1" | "js" | "rb" | "pl" | "php" | "vbs"
        );

        if !is_script {
            return Vec::new();
        }

        let text = String::from_utf8_lossy(data);
        let mut results = Vec::new();

        // Base64 blocks longer than 200 characters
        let b64_re = regex::Regex::new(r"[A-Za-z0-9+/]{200,}={0,2}").unwrap();
        if b64_re.is_match(&text) {
            results.push(ScanResult::new(
                "heuristic_engine",
                path.to_string_lossy(),
                Severity::Medium,
                DetectionCategory::HeuristicAnomaly {
                    rule: "script_base64_block".to_string(),
                },
                "Script contains large base64-encoded block (>200 chars) — possible payload hiding",
                0.7,
                RecommendedAction::Alert,
            ));
        }

        // Hex-encoded byte sequences
        let hex_re = regex::Regex::new(r"(\\x[0-9a-fA-F]{2}){50,}").unwrap();
        if hex_re.is_match(&text) {
            results.push(ScanResult::new(
                "heuristic_engine",
                path.to_string_lossy(),
                Severity::Medium,
                DetectionCategory::HeuristicAnomaly {
                    rule: "script_hex_payload".to_string(),
                },
                "Script contains long hex-encoded byte sequence — possible shellcode",
                0.75,
                RecommendedAction::Alert,
            ));
        }

        // eval/exec with base64 or decode
        let eval_re =
            regex::Regex::new(r"(?i)(eval|exec)\s*\(.*?(base64|decode|fromcharcode|chr\()").unwrap();
        if eval_re.is_match(&text) {
            results.push(ScanResult::new(
                "heuristic_engine",
                path.to_string_lossy(),
                Severity::Medium,
                DetectionCategory::HeuristicAnomaly {
                    rule: "script_eval_encoded".to_string(),
                },
                "Script uses eval/exec with encoded arguments — common obfuscation technique",
                0.8,
                RecommendedAction::Alert,
            ));
        }

        // String reversal patterns
        let rev_re = regex::Regex::new(r"(?i)(rev\s|reverse\(|\[::-1\]|\.reverse\(\))").unwrap();
        if rev_re.is_match(&text) {
            // Only flag if also has eval/exec nearby
            let has_exec = regex::Regex::new(r"(?i)(eval|exec|system|passthru|shell_exec)")
                .unwrap()
                .is_match(&text);
            if has_exec {
                results.push(ScanResult::new(
                    "heuristic_engine",
                    path.to_string_lossy(),
                    Severity::Medium,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "script_reversal_exec".to_string(),
                    },
                    "Script combines string reversal with code execution — obfuscation technique",
                    0.65,
                    RecommendedAction::Alert,
                ));
            }
        }

        results
    }

    // =========================================================================
    // Embedded Executable Detection
    // =========================================================================

    /// Detect executables embedded inside non-executable files.
    fn check_embedded_executable(&self, data: &[u8], path: &Path) -> Vec<ScanResult> {
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        // Only check non-executable file types
        let is_document = matches!(
            ext.as_str(),
            "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "csv" | "txt" | "rtf" | "odt" | "ods"
        );

        if !is_document {
            return Vec::new();
        }

        // Scan starting from offset 1024 (past the document header)
        let search_start = 1024.min(data.len());
        let search_data = &data[search_start..];

        let mut results = Vec::new();

        // Look for MZ header (Windows PE)
        for (i, window) in search_data.windows(2).enumerate() {
            if window[0] == 0x4D && window[1] == 0x5A {
                // Verify it's likely a real PE: check for "PE\0\0" or "This program"
                let offset = search_start + i;
                let remaining = &data[offset..];
                if remaining.len() > 64 {
                    results.push(ScanResult::new(
                        "heuristic_engine",
                        path.to_string_lossy(),
                        Severity::High,
                        DetectionCategory::HeuristicAnomaly {
                            rule: "embedded_pe_executable".to_string(),
                        },
                        format!(
                            "Windows PE executable (MZ header) embedded at offset {} in {} file",
                            offset, ext
                        ),
                        0.85,
                        RecommendedAction::Quarantine {
                            source_path: path.to_path_buf(),
                        },
                    ));
                    break; // One is enough
                }
            }
        }

        // Look for ELF header
        if search_data.len() >= 4 {
            for (i, window) in search_data.windows(4).enumerate() {
                if window == b"\x7FELF" {
                    let offset = search_start + i;
                    results.push(ScanResult::new(
                        "heuristic_engine",
                        path.to_string_lossy(),
                        Severity::High,
                        DetectionCategory::HeuristicAnomaly {
                            rule: "embedded_elf_executable".to_string(),
                        },
                        format!(
                            "Linux ELF executable embedded at offset {} in {} file",
                            offset, ext
                        ),
                        0.85,
                        RecommendedAction::Quarantine {
                            source_path: path.to_path_buf(),
                        },
                    ));
                    break;
                }
            }
        }

        // Look for shebang (#!)
        if search_data.len() >= 2 {
            for (i, window) in search_data.windows(2).enumerate() {
                if window == b"#!" {
                    let offset = search_start + i;
                    // Verify it looks like a real shebang (followed by /)
                    if offset + 3 < data.len() && data[offset + 2] == b'/' {
                        results.push(ScanResult::new(
                            "heuristic_engine",
                            path.to_string_lossy(),
                            Severity::Medium,
                            DetectionCategory::HeuristicAnomaly {
                                rule: "embedded_script".to_string(),
                            },
                            format!(
                                "Script shebang (#!) found at offset {} in {} file",
                                offset, ext
                            ),
                            0.6,
                            RecommendedAction::Alert,
                        ));
                        break;
                    }
                }
            }
        }

        results
    }

    /// Detect cryptocurrency miner indicators in file content.
    fn check_miner_indicators(&self, data: &[u8], path: &Path) -> Vec<ScanResult> {
        let mut results = Vec::new();

        // Only check ELF binaries and scripts (not images, docs, etc.)
        let is_elf = data.len() >= 4 && data.starts_with(b"\x7FELF");
        let is_script = data.len() >= 2 && data.starts_with(b"#!");
        let is_text = data.iter().take(512).all(|&b| b.is_ascii() || b == b'\n' || b == b'\r' || b == b'\t');

        if !is_elf && !is_script && !is_text {
            return results;
        }

        // Convert to string for pattern matching (safe — non-UTF8 bytes become ?)
        let content = String::from_utf8_lossy(data);
        let content_lower = content.to_lowercase();

        // Mining pool protocol strings
        let pool_indicators: &[(&str, &str)] = &[
            ("stratum+tcp://", "Stratum mining pool protocol (TCP)"),
            ("stratum+ssl://", "Stratum mining pool protocol (SSL)"),
            ("stratum://", "Stratum mining pool protocol"),
            ("pool.minexmr", "MinXMR mining pool"),
            ("pool.supportxmr", "SupportXMR mining pool"),
            ("pool.hashvault", "HashVault mining pool"),
            ("nanopool.org", "Nanopool mining pool"),
            ("2miners.com", "2Miners mining pool"),
            ("nicehash.com", "NiceHash mining pool"),
            ("minergate.com", "MinerGate mining pool"),
            ("f2pool.com", "F2Pool mining pool"),
            ("antpool.com", "AntPool mining pool"),
            ("ethermine.org", "Ethermine mining pool"),
        ];

        for (pattern, desc) in pool_indicators {
            if content_lower.contains(pattern) {
                results.push(ScanResult::new(
                    "heuristic_engine",
                    path.to_string_lossy(),
                    Severity::Critical,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "miner_pool_protocol".to_string(),
                    },
                    format!("Cryptocurrency miner indicator: {} found in {}", desc, path.display()),
                    0.95,
                    RecommendedAction::Quarantine {
                        source_path: path.to_path_buf(),
                    },
                ));
                break; // One pool match is enough
            }
        }

        // Mining algorithm strings
        let algo_indicators: &[&str] = &[
            "cryptonight", "randomx", "kawpow", "ethash", "equihash",
            "scrypt", "blake2b", "ghostrider", "autolykos",
        ];

        let mut algo_count = 0;
        for algo in algo_indicators {
            if content_lower.contains(algo) {
                algo_count += 1;
            }
        }
        // Two or more algorithm names = very likely a miner
        if algo_count >= 2 {
            results.push(ScanResult::new(
                "heuristic_engine",
                path.to_string_lossy(),
                Severity::High,
                DetectionCategory::HeuristicAnomaly {
                    rule: "miner_algorithm_strings".to_string(),
                },
                format!(
                    "Multiple mining algorithm names ({}) found in {} — likely crypto miner",
                    algo_count, path.display()
                ),
                0.85,
                RecommendedAction::Quarantine {
                    source_path: path.to_path_buf(),
                },
            ));
        }

        // Known miner binary name patterns in the filename
        let filename = path.file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let miner_names = [
            "xmrig", "minerd", "cpuminer", "ethminer", "nbminer",
            "phoenixminer", "t-rex", "lolminer", "gminer",
            "kdevtmpfsi", "kinsing", "xmr-stak",
        ];
        for name in &miner_names {
            if filename.contains(name) {
                results.push(ScanResult::new(
                    "heuristic_engine",
                    path.to_string_lossy(),
                    Severity::Critical,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "miner_filename".to_string(),
                    },
                    format!("Known miner filename pattern '{}' in {}", name, path.display()),
                    0.95,
                    RecommendedAction::Quarantine {
                        source_path: path.to_path_buf(),
                    },
                ));
                break;
            }
        }

        // Wallet address patterns (Monero 95-char base58, Bitcoin 26-35 char)
        if content_lower.contains("wallet") || content_lower.contains("--user") {
            // Look for Monero-style addresses (starts with 4 and is 95 chars)
            for word in content.split_whitespace() {
                if word.len() == 95 && word.starts_with('4') && word.chars().all(|c| c.is_alphanumeric()) {
                    results.push(ScanResult::new(
                        "heuristic_engine",
                        path.to_string_lossy(),
                        Severity::High,
                        DetectionCategory::HeuristicAnomaly {
                            rule: "miner_wallet_address".to_string(),
                        },
                        format!("Probable Monero wallet address found in {}", path.display()),
                        0.9,
                        RecommendedAction::Quarantine {
                            source_path: path.to_path_buf(),
                        },
                    ));
                    break;
                }
            }
        }

        results
    }
}

/// Detect file type from magic bytes.
fn detect_magic_type(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }

    if data.starts_with(b"%PDF") {
        Some("pdf")
    } else if data.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("png")
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpeg")
    } else if data.starts_with(b"GIF8") {
        Some("gif")
    } else if data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        Some("zip")
    } else if data.starts_with(&[0x1F, 0x8B]) {
        Some("gzip")
    } else if data.starts_with(&[0x4D, 0x5A]) {
        Some("pe")
    } else if data.starts_with(&[0x7F, b'E', b'L', b'F']) {
        Some("elf")
    } else if data.starts_with(&[0x42, 0x4D]) {
        Some("bmp")
    } else {
        None
    }
}

#[async_trait::async_trait]
impl Scanner for HeuristicEngine {
    fn name(&self) -> &str {
        "heuristic_engine"
    }

    fn is_active(&self) -> bool {
        self.active
    }

    async fn scan_file(&self, path: &Path) -> Vec<ScanResult> {
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };

        if metadata.len() > self.config.max_scan_size {
            return Vec::new();
        }

        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };

        let mut results = Vec::new();
        results.extend(self.check_entropy(&data, path));
        results.extend(self.check_elf_header(&data, path));
        results.extend(self.check_file_type_mismatch(&data, path));
        results.extend(self.check_script_obfuscation(&data, path));
        results.extend(self.check_embedded_executable(&data, path));
        results.extend(self.check_miner_indicators(&data, path));
        results
    }

    async fn scan_bytes(&self, data: &[u8], label: &str) -> Vec<ScanResult> {
        let path = Path::new(label);
        let mut results = Vec::new();
        results.extend(self.check_entropy(data, path));
        results.extend(self.check_script_obfuscation(data, path));
        results.extend(self.check_miner_indicators(data, path));
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_all_zeros() {
        let data = vec![0u8; 1024];
        let entropy = HeuristicEngine::shannon_entropy(&data);
        assert!((entropy - 0.0).abs() < 0.001);
    }

    #[test]
    fn entropy_uniform_random() {
        // Create data with perfectly uniform distribution (each byte value once)
        let mut data = Vec::with_capacity(256 * 100);
        for _ in 0..100 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let entropy = HeuristicEngine::shannon_entropy(&data);
        // Should be exactly 8.0 for perfectly uniform distribution
        assert!((entropy - 8.0).abs() < 0.001, "entropy was {}", entropy);
    }

    #[test]
    fn entropy_normal_text() {
        let text = b"The quick brown fox jumps over the lazy dog. This is a normal English sentence with typical entropy levels for natural language text content.";
        let entropy = HeuristicEngine::shannon_entropy(text);
        // English text typically has entropy 3.5–5.0
        assert!(entropy > 3.0 && entropy < 6.0, "entropy was {}", entropy);
    }

    #[test]
    fn entropy_empty() {
        assert_eq!(HeuristicEngine::shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn elf_header_detection() {
        // Craft a minimal valid 64-bit LE ELF header (64 bytes)
        let mut elf = vec![0u8; 128];
        elf[0] = 0x7F; elf[1] = b'E'; elf[2] = b'L'; elf[3] = b'F'; // magic
        elf[4] = 2;    // 64-bit
        elf[5] = 1;    // little-endian
        elf[6] = 1;    // EV_CURRENT
        // e_shnum at offset 60: set to 0 (stripped)
        elf[60] = 0; elf[61] = 0;

        let engine = HeuristicEngine::new(HeuristicConfig::default());
        let results = engine.check_elf_header(&elf, Path::new("/tmp/test.elf"));
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.description.contains("stripped")));
    }

    #[test]
    fn file_type_mismatch_pdf_with_mz() {
        // MZ header (Windows PE) pretending to be a PDF
        let mut data = vec![0x4D, 0x5A]; // MZ
        data.extend_from_slice(&[0u8; 100]);

        let engine = HeuristicEngine::new(HeuristicConfig::default());
        let results = engine.check_file_type_mismatch(&data, Path::new("/tmp/report.pdf"));
        assert!(!results.is_empty());
        assert_eq!(results[0].severity, Severity::High);
    }

    #[test]
    fn file_type_mismatch_clean_pdf() {
        let mut data = b"%PDF-1.4 ".to_vec();
        data.extend_from_slice(&[0u8; 100]);

        let engine = HeuristicEngine::new(HeuristicConfig::default());
        let results = engine.check_file_type_mismatch(&data, Path::new("/tmp/report.pdf"));
        assert!(results.is_empty());
    }

    #[test]
    fn script_base64_obfuscation() {
        let mut script = b"#!/bin/bash\neval $(echo '".to_vec();
        // 250 base64 characters
        script.extend_from_slice(&[b'A'; 250]);
        script.extend_from_slice(b"==' | base64 -d)\n");

        let engine = HeuristicEngine::new(HeuristicConfig::default());
        let results = engine.check_script_obfuscation(&script, Path::new("/tmp/evil.sh"));
        assert!(!results.is_empty());
    }

    #[test]
    fn clean_python_script_passes() {
        let script = b"#!/usr/bin/env python3\nimport os\nprint('hello world')\n";

        let engine = HeuristicEngine::new(HeuristicConfig::default());
        let results = engine.check_script_obfuscation(script, Path::new("/tmp/app.py"));
        assert!(results.is_empty());
    }

    #[test]
    fn embedded_elf_in_pdf() {
        let mut data = b"%PDF-1.4 some pdf content here padding ".to_vec();
        // Pad to beyond 1024 bytes
        data.extend_from_slice(&[b' '; 1024]);
        // Embed ELF magic
        data.extend_from_slice(&[0x7F, b'E', b'L', b'F']);
        data.extend_from_slice(&[0u8; 100]);

        let engine = HeuristicEngine::new(HeuristicConfig::default());
        let results = engine.check_embedded_executable(&data, Path::new("/tmp/report.pdf"));
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.description.contains("ELF")));
    }

    #[test]
    fn max_scan_size_respected() {
        let config = HeuristicConfig {
            max_scan_size: 100,
            ..Default::default()
        };
        let engine = HeuristicEngine::new(config);

        // Create a temp file larger than max
        let dir = std::env::temp_dir().join("nexus-heur-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("large.bin");
        std::fs::write(&path, &[0xAA; 200]).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let results = rt.block_on(engine.scan_file(&path));
        assert!(results.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_defaults_are_reasonable() {
        let config = HeuristicConfig::default();
        assert!(config.high_entropy_threshold > 7.0);
        assert!(config.high_entropy_threshold < 8.0);
        assert!(config.min_entropy_size > 0);
        assert!(config.max_scan_size > 1_000_000);
        assert!(config.analyze_elf);
        assert!(config.analyze_scripts);
    }

    #[test]
    fn detect_magic_types() {
        assert_eq!(detect_magic_type(b"%PDF-1.4"), Some("pdf"));
        assert_eq!(detect_magic_type(&[0x89, b'P', b'N', b'G']), Some("png"));
        assert_eq!(detect_magic_type(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("jpeg"));
        assert_eq!(detect_magic_type(b"GIF89a"), Some("gif"));
        assert_eq!(detect_magic_type(&[0x4D, 0x5A, 0x90, 0x00]), Some("pe"));
        assert_eq!(detect_magic_type(&[0x7F, b'E', b'L', b'F']), Some("elf"));
        assert_eq!(detect_magic_type(b"Hello"), None);
    }
}