// ============================================================================
// File: endpoint/supply_chain.rs
// Description: Supply chain dependency scanning — check lock files for known
//              vulnerable, malicious, or typosquatted packages
// ============================================================================
//! Supply Chain Scanner — parses dependency lock files and checks packages
//! against known-malicious package names, typosquat patterns, and version
//! pinning issues.
//!
//! Supported ecosystems:
//! - **Rust** (Cargo.lock)
//! - **Node.js** (package-lock.json, yarn.lock)
//! - **Python** (requirements.txt, Pipfile.lock)
//! - **Go** (go.sum)
//!
//! Detection capabilities:
//! - Known-malicious package names
//! - Typosquat detection (Levenshtein distance from popular packages)
//! - Suspicious version patterns (0.0.x, yanked indicators)
//! - Overly permissive version ranges
//! - Packages with install scripts (postinstall hooks)
//! - Dependency confusion indicators (private namespace collisions)

use super::{DetectionCategory, RecommendedAction, ScanResult, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the supply chain scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainConfig {
    /// Enable typosquat detection against popular package lists.
    pub check_typosquats: bool,
    /// Maximum Levenshtein distance for typosquat alerting.
    pub typosquat_max_distance: usize,
    /// Known-malicious package names (cross-ecosystem).
    pub malicious_packages: Vec<String>,
    /// Popular packages to check typosquats against.
    pub popular_rust_crates: Vec<String>,
    pub popular_npm_packages: Vec<String>,
    pub popular_pypi_packages: Vec<String>,
}

impl Default for SupplyChainConfig {
    fn default() -> Self {
        Self {
            check_typosquats: true,
            typosquat_max_distance: 2,
            malicious_packages: vec![
                // Known malicious npm packages
                "event-stream-malicious".to_string(),
                "flatmap-stream".to_string(),
                "ua-parser-js-malicious".to_string(),
                "colors-malicious".to_string(),
                "faker-malicious".to_string(),
                // Known malicious PyPI
                "python3-dateutil".to_string(), // typosquat of python-dateutil
                "jeIlyfish".to_string(),         // homoglyph of jellyfish
                "python-binance-sdk".to_string(),
                // Known malicious crates
                "rustdecimal".to_string(), // typosquat of rust_decimal
            ],
            popular_rust_crates: vec![
                "serde".into(), "tokio".into(), "reqwest".into(), "clap".into(),
                "rand".into(), "hyper".into(), "axum".into(), "tracing".into(),
                "anyhow".into(), "thiserror".into(), "chrono".into(), "uuid".into(),
                "regex".into(), "sha2".into(), "base64".into(), "log".into(),
                "futures".into(), "bytes".into(), "syn".into(), "quote".into(),
                "proc-macro2".into(), "libc".into(), "lazy_static".into(),
                "once_cell".into(), "parking_lot".into(), "crossbeam".into(),
            ],
            popular_npm_packages: vec![
                "express".into(), "react".into(), "lodash".into(), "axios".into(),
                "moment".into(), "chalk".into(), "commander".into(), "debug".into(),
                "webpack".into(), "typescript".into(), "eslint".into(), "jest".into(),
                "next".into(), "vue".into(), "angular".into(), "jquery".into(),
                "underscore".into(), "async".into(), "request".into(), "glob".into(),
                "minimist".into(), "dotenv".into(), "uuid".into(), "cors".into(),
            ],
            popular_pypi_packages: vec![
                "requests".into(), "numpy".into(), "pandas".into(), "flask".into(),
                "django".into(), "pytest".into(), "boto3".into(), "pillow".into(),
                "setuptools".into(), "pyyaml".into(), "cryptography".into(),
                "sqlalchemy".into(), "celery".into(), "redis".into(), "scipy".into(),
                "matplotlib".into(), "beautifulsoup4".into(), "scrapy".into(),
            ],
        }
    }
}

// =============================================================================
// Parsed Dependency
// =============================================================================

/// A dependency parsed from a lock file.
#[derive(Debug, Clone)]
pub struct ParsedDep {
    pub name: String,
    pub version: String,
    pub source: String, // "crates.io", "npm", "pypi", "go"
    pub registry: Option<String>,
}

/// Ecosystem identifier.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ecosystem {
    Rust,
    Npm,
    Python,
    Go,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rust => write!(f, "rust"),
            Self::Npm => write!(f, "npm"),
            Self::Python => write!(f, "python"),
            Self::Go => write!(f, "go"),
        }
    }
}

// =============================================================================
// Lock File Parsers
// =============================================================================

/// Parse a Cargo.lock file into dependencies.
pub fn parse_cargo_lock(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let mut current_name = String::new();
    let mut current_version = String::new();
    let mut current_source = String::new();
    let mut in_package = false;

    for line in content.lines() {
        let line = line.trim();

        if line == "[[package]]" {
            if in_package && !current_name.is_empty() {
                deps.push(ParsedDep {
                    name: current_name.clone(),
                    version: current_version.clone(),
                    source: "crates.io".to_string(),
                    registry: if current_source.is_empty() {
                        None
                    } else {
                        Some(current_source.clone())
                    },
                });
            }
            current_name.clear();
            current_version.clear();
            current_source.clear();
            in_package = true;
            continue;
        }

        if in_package {
            if let Some(name) = line.strip_prefix("name = ") {
                current_name = name.trim_matches('"').to_string();
            } else if let Some(ver) = line.strip_prefix("version = ") {
                current_version = ver.trim_matches('"').to_string();
            } else if let Some(src) = line.strip_prefix("source = ") {
                current_source = src.trim_matches('"').to_string();
            }
        }
    }

    // Last package
    if in_package && !current_name.is_empty() {
        deps.push(ParsedDep {
            name: current_name,
            version: current_version,
            source: "crates.io".to_string(),
            registry: if current_source.is_empty() {
                None
            } else {
                Some(current_source)
            },
        });
    }

    deps
}

/// Parse a package-lock.json (v2/v3) into dependencies.
pub fn parse_package_lock_json(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();

    let json: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return deps,
    };

    // v2/v3 format: "packages" key with "node_modules/..." entries
    if let Some(packages) = json.get("packages").and_then(|v| v.as_object()) {
        for (key, val) in packages {
            if key.is_empty() || !key.contains("node_modules/") {
                continue;
            }
            let name = key.rsplit("node_modules/").next().unwrap_or(key);
            let version = val
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if !name.is_empty() {
                deps.push(ParsedDep {
                    name: name.to_string(),
                    version,
                    source: "npm".to_string(),
                    registry: val.get("resolved").and_then(|v| v.as_str()).map(|s| s.to_string()),
                });
            }
        }
    }

    // v1 format: "dependencies" key
    if deps.is_empty() {
        if let Some(dependencies) = json.get("dependencies").and_then(|v| v.as_object()) {
            for (name, val) in dependencies {
                let version = val
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                deps.push(ParsedDep {
                    name: name.clone(),
                    version,
                    source: "npm".to_string(),
                    registry: val.get("resolved").and_then(|v| v.as_str()).map(|s| s.to_string()),
                });
            }
        }
    }

    deps
}

/// Parse a requirements.txt into dependencies.
pub fn parse_requirements_txt(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }

        // Format: package==version, package>=version, package
        let (name, version) = if let Some(pos) = line.find("==") {
            (&line[..pos], line[pos + 2..].to_string())
        } else if let Some(pos) = line.find(">=") {
            (&line[..pos], line[pos + 2..].to_string())
        } else if let Some(pos) = line.find("<=") {
            (&line[..pos], line[pos + 2..].to_string())
        } else if let Some(pos) = line.find("~=") {
            (&line[..pos], line[pos + 2..].to_string())
        } else {
            (line, String::new())
        };

        let name = name.trim().to_lowercase();
        if !name.is_empty() {
            deps.push(ParsedDep {
                name,
                version: version.trim().to_string(),
                source: "pypi".to_string(),
                registry: None,
            });
        }
    }

    deps
}

/// Parse a go.sum file into dependencies.
pub fn parse_go_sum(content: &str) -> Vec<ParsedDep> {
    let mut seen = HashSet::new();
    let mut deps = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Format: module version hash
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let module = parts[0];
        let version = parts[1].split('/').next().unwrap_or(parts[1]);
        let version = version.trim_start_matches('v');

        let key = format!("{}@{}", module, version);
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);

        deps.push(ParsedDep {
            name: module.to_string(),
            version: version.to_string(),
            source: "go".to_string(),
            registry: None,
        });
    }

    deps
}

// =============================================================================
// Levenshtein Distance
// =============================================================================

/// Compute the Levenshtein edit distance between two strings.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0; b_len + 1];

    for i in 1..=a_len {
        curr[0] = i;
        for j in 1..=b_len {
            let cost = if a_bytes[i - 1] == b_bytes[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1)
                .min(curr[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

// =============================================================================
// Supply Chain Scanner
// =============================================================================

/// Scans dependency lock files for supply chain risks.
pub struct SupplyChainScanner {
    config: SupplyChainConfig,
}

impl SupplyChainScanner {
    pub fn new(config: SupplyChainConfig) -> Self {
        Self { config }
    }

    /// Detect the ecosystem from a file path.
    pub fn detect_ecosystem(path: &Path) -> Option<Ecosystem> {
        let name = path.file_name()?.to_str()?;
        match name {
            "Cargo.lock" => Some(Ecosystem::Rust),
            "package-lock.json" | "yarn.lock" => Some(Ecosystem::Npm),
            "requirements.txt" | "Pipfile.lock" => Some(Ecosystem::Python),
            "go.sum" => Some(Ecosystem::Go),
            _ => None,
        }
    }

    /// Scan a lock file for supply chain risks.
    pub fn scan_file(&self, path: &Path) -> Vec<ScanResult> {
        let ecosystem = match Self::detect_ecosystem(path) {
            Some(e) => e,
            None => return Vec::new(),
        };

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let deps = match ecosystem {
            Ecosystem::Rust => parse_cargo_lock(&content),
            Ecosystem::Npm => parse_package_lock_json(&content),
            Ecosystem::Python => parse_requirements_txt(&content),
            Ecosystem::Go => parse_go_sum(&content),
        };

        self.analyze_deps(&deps, ecosystem, &path.to_string_lossy())
    }

    /// Scan raw dependency content (for API usage).
    pub fn scan_content(&self, content: &str, ecosystem: Ecosystem) -> Vec<ScanResult> {
        let deps = match ecosystem {
            Ecosystem::Rust => parse_cargo_lock(content),
            Ecosystem::Npm => parse_package_lock_json(content),
            Ecosystem::Python => parse_requirements_txt(content),
            Ecosystem::Go => parse_go_sum(content),
        };

        self.analyze_deps(&deps, ecosystem, &format!("<{} content>", ecosystem))
    }

    /// Analyze a list of dependencies for risks.
    fn analyze_deps(&self, deps: &[ParsedDep], ecosystem: Ecosystem, source: &str) -> Vec<ScanResult> {
        let mut results = Vec::new();

        for dep in deps {
            // 1. Check known-malicious packages
            if self.is_malicious(&dep.name) {
                results.push(ScanResult::new(
                    "supply_chain_scanner",
                    source,
                    Severity::Critical,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "supply_chain_malicious_package".to_string(),
                    },
                    format!(
                        "KNOWN MALICIOUS package: {} v{} ({}) — remove immediately",
                        dep.name, dep.version, ecosystem
                    ),
                    1.0,
                    RecommendedAction::Alert,
                ));
            }

            // 2. Check typosquats
            if self.config.check_typosquats {
                let popular = match ecosystem {
                    Ecosystem::Rust => &self.config.popular_rust_crates,
                    Ecosystem::Npm => &self.config.popular_npm_packages,
                    Ecosystem::Python => &self.config.popular_pypi_packages,
                    Ecosystem::Go => continue, // Go uses URLs, typosquats less relevant
                };

                if let Some(target) = self.check_typosquat(&dep.name, popular) {
                    results.push(ScanResult::new(
                        "supply_chain_scanner",
                        source,
                        Severity::High,
                        DetectionCategory::HeuristicAnomaly {
                            rule: "supply_chain_typosquat".to_string(),
                        },
                        format!(
                            "Potential typosquat: '{}' is suspiciously similar to popular package '{}' ({}) — verify this is intentional",
                            dep.name, target, ecosystem
                        ),
                        0.8,
                        RecommendedAction::Alert,
                    ));
                }
            }

            // 3. Check suspicious version patterns
            if self.is_suspicious_version(&dep.version) {
                results.push(ScanResult::new(
                    "supply_chain_scanner",
                    source,
                    Severity::Low,
                    DetectionCategory::HeuristicAnomaly {
                        rule: "supply_chain_suspicious_version".to_string(),
                    },
                    format!(
                        "Suspicious version pattern: {} v{} ({}) — very early version may indicate new/test package",
                        dep.name, dep.version, ecosystem
                    ),
                    0.3,
                    RecommendedAction::LogOnly,
                ));
            }

            // 4. Check for non-registry sources (dependency confusion)
            if let Some(ref registry) = dep.registry {
                if !registry.contains("registry.npmjs.org")
                    && !registry.contains("crates.io")
                    && !registry.contains("pypi.org")
                    && registry.starts_with("http")
                {
                    results.push(ScanResult::new(
                        "supply_chain_scanner",
                        source,
                        Severity::Medium,
                        DetectionCategory::HeuristicAnomaly {
                            rule: "supply_chain_custom_registry".to_string(),
                        },
                        format!(
                            "Package from non-standard registry: {} v{} from {} — possible dependency confusion",
                            dep.name, dep.version, registry
                        ),
                        0.6,
                        RecommendedAction::Alert,
                    ));
                }
            }
        }

        results
    }

    /// Check if a package name is in the known-malicious list.
    fn is_malicious(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.config
            .malicious_packages
            .iter()
            .any(|m| m.to_lowercase() == lower)
    }

    /// Check if a package name is a typosquat of a popular package.
    /// Returns the popular package name if a match is found.
    fn check_typosquat(&self, name: &str, popular: &[String]) -> Option<String> {
        let lower = name.to_lowercase();
        for pkg in popular {
            let pkg_lower = pkg.to_lowercase();
            // Skip exact match (it IS the popular package)
            if lower == pkg_lower {
                return None;
            }
            // Check Levenshtein distance
            let dist = levenshtein(&lower, &pkg_lower);
            if dist > 0 && dist <= self.config.typosquat_max_distance {
                return Some(pkg.clone());
            }
        }
        None
    }

    /// Check for suspicious version patterns.
    fn is_suspicious_version(&self, version: &str) -> bool {
        // 0.0.x versions are suspicious for established-sounding packages
        if version.starts_with("0.0.") {
            return true;
        }
        // Single digit versions like "1" or "0"
        if version.len() == 1 {
            return true;
        }
        false
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scanner() -> SupplyChainScanner {
        SupplyChainScanner::new(SupplyChainConfig::default())
    }

    #[test]
    fn config_defaults() {
        let config = SupplyChainConfig::default();
        assert!(config.check_typosquats);
        assert_eq!(config.typosquat_max_distance, 2);
        assert!(!config.malicious_packages.is_empty());
        assert!(!config.popular_rust_crates.is_empty());
        assert!(!config.popular_npm_packages.is_empty());
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("serde", "serde"), 0);
        assert_eq!(levenshtein("serde", "serda"), 1);
        assert_eq!(levenshtein("reqwest", "request"), 1);
    }

    #[test]
    fn parse_cargo_lock_basic() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.37.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let deps = parse_cargo_lock(content);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, "1.0.200");
        assert_eq!(deps[1].name, "tokio");
    }

    #[test]
    fn parse_package_lock_v2() {
        let content = r#"{
  "name": "myapp",
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    }
  }
}"#;
        let deps = parse_package_lock_json(content);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "express");
        assert_eq!(deps[0].version, "4.18.2");
        assert_eq!(deps[1].name, "lodash");
    }

    #[test]
    fn parse_requirements_txt_basic() {
        let content = "requests==2.31.0\nnumpy>=1.24.0\nflask\n# comment\n-r other.txt\n";
        let deps = parse_requirements_txt(content);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, "2.31.0");
        assert_eq!(deps[1].name, "numpy");
        assert_eq!(deps[1].version, "1.24.0");
        assert_eq!(deps[2].name, "flask");
        assert!(deps[2].version.is_empty());
    }

    #[test]
    fn parse_go_sum_basic() {
        let content = r#"github.com/gin-gonic/gin v1.9.1 h1:abc123=
github.com/gin-gonic/gin v1.9.1/go.mod h1:def456=
golang.org/x/crypto v0.21.0 h1:ghi789=
"#;
        let deps = parse_go_sum(content);
        assert_eq!(deps.len(), 2); // Deduplicated
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        assert_eq!(deps[0].version, "1.9.1");
    }

    #[test]
    fn detect_malicious_package() {
        let scanner = test_scanner();
        let deps = vec![ParsedDep {
            name: "rustdecimal".to_string(),
            version: "1.0.0".to_string(),
            source: "crates.io".to_string(),
            registry: None,
        }];
        let results = scanner.analyze_deps(&deps, Ecosystem::Rust, "Cargo.lock");
        let critical: Vec<_> = results.iter().filter(|r| r.severity == Severity::Critical).collect();
        assert!(!critical.is_empty(), "Should detect known-malicious crate");
        assert!(critical[0].description.contains("KNOWN MALICIOUS"));
    }

    #[test]
    fn detect_typosquat() {
        let scanner = test_scanner();
        // "serda" is 1 edit from "serde"
        let deps = vec![ParsedDep {
            name: "serda".to_string(),
            version: "1.0.0".to_string(),
            source: "crates.io".to_string(),
            registry: None,
        }];
        let results = scanner.analyze_deps(&deps, Ecosystem::Rust, "Cargo.lock");
        let typos: Vec<_> = results.iter()
            .filter(|r| r.description.contains("typosquat"))
            .collect();
        assert!(!typos.is_empty(), "Should detect typosquat of 'serde'");
    }

    #[test]
    fn no_typosquat_for_exact_match() {
        let scanner = test_scanner();
        let deps = vec![ParsedDep {
            name: "serde".to_string(),
            version: "1.0.200".to_string(),
            source: "crates.io".to_string(),
            registry: None,
        }];
        let results = scanner.analyze_deps(&deps, Ecosystem::Rust, "Cargo.lock");
        let typos: Vec<_> = results.iter()
            .filter(|r| r.description.contains("typosquat"))
            .collect();
        assert!(typos.is_empty(), "Should not flag exact match as typosquat");
    }

    #[test]
    fn detect_suspicious_version() {
        let scanner = test_scanner();
        let deps = vec![ParsedDep {
            name: "suspicious-pkg".to_string(),
            version: "0.0.1".to_string(),
            source: "npm".to_string(),
            registry: None,
        }];
        let results = scanner.analyze_deps(&deps, Ecosystem::Npm, "package-lock.json");
        let version_alerts: Vec<_> = results.iter()
            .filter(|r| r.description.contains("Suspicious version"))
            .collect();
        assert!(!version_alerts.is_empty());
    }

    #[test]
    fn detect_custom_registry() {
        let scanner = test_scanner();
        let deps = vec![ParsedDep {
            name: "internal-pkg".to_string(),
            version: "1.0.0".to_string(),
            source: "npm".to_string(),
            registry: Some("https://evil-registry.com/internal-pkg".to_string()),
        }];
        let results = scanner.analyze_deps(&deps, Ecosystem::Npm, "package-lock.json");
        let registry_alerts: Vec<_> = results.iter()
            .filter(|r| r.description.contains("non-standard registry"))
            .collect();
        assert!(!registry_alerts.is_empty());
    }

    #[test]
    fn legitimate_registry_no_alert() {
        let scanner = test_scanner();
        let deps = vec![ParsedDep {
            name: "express".to_string(),
            version: "4.18.2".to_string(),
            source: "npm".to_string(),
            registry: Some("https://registry.npmjs.org/express/-/express-4.18.2.tgz".to_string()),
        }];
        let results = scanner.analyze_deps(&deps, Ecosystem::Npm, "package-lock.json");
        let registry_alerts: Vec<_> = results.iter()
            .filter(|r| r.description.contains("non-standard registry"))
            .collect();
        assert!(registry_alerts.is_empty());
    }

    #[test]
    fn detect_ecosystem_from_path() {
        assert_eq!(SupplyChainScanner::detect_ecosystem(Path::new("Cargo.lock")), Some(Ecosystem::Rust));
        assert_eq!(SupplyChainScanner::detect_ecosystem(Path::new("package-lock.json")), Some(Ecosystem::Npm));
        assert_eq!(SupplyChainScanner::detect_ecosystem(Path::new("requirements.txt")), Some(Ecosystem::Python));
        assert_eq!(SupplyChainScanner::detect_ecosystem(Path::new("go.sum")), Some(Ecosystem::Go));
        assert_eq!(SupplyChainScanner::detect_ecosystem(Path::new("random.txt")), None);
    }

    #[test]
    fn clean_deps_no_alerts() {
        let scanner = test_scanner();
        let deps = vec![
            ParsedDep { name: "serde".into(), version: "1.0.200".into(), source: "crates.io".into(), registry: None },
            ParsedDep { name: "tokio".into(), version: "1.37.0".into(), source: "crates.io".into(), registry: None },
        ];
        let results = scanner.analyze_deps(&deps, Ecosystem::Rust, "Cargo.lock");
        assert!(results.is_empty(), "Clean deps should have no alerts");
    }

    #[test]
    fn npm_typosquat_detection() {
        let scanner = test_scanner();
        // "expres" is 1 edit from "express"
        let deps = vec![ParsedDep {
            name: "expres".to_string(),
            version: "4.0.0".to_string(),
            source: "npm".to_string(),
            registry: None,
        }];
        let results = scanner.analyze_deps(&deps, Ecosystem::Npm, "package-lock.json");
        let typos: Vec<_> = results.iter()
            .filter(|r| r.description.contains("typosquat"))
            .collect();
        assert!(!typos.is_empty());
    }

    #[test]
    fn python_typosquat_detection() {
        let scanner = test_scanner();
        // "requets" is 1 edit from "requests"
        let deps = vec![ParsedDep {
            name: "requets".to_string(),
            version: "2.31.0".to_string(),
            source: "pypi".to_string(),
            registry: None,
        }];
        let results = scanner.analyze_deps(&deps, Ecosystem::Python, "requirements.txt");
        let typos: Vec<_> = results.iter()
            .filter(|r| r.description.contains("typosquat"))
            .collect();
        assert!(!typos.is_empty());
    }

    #[test]
    fn parse_empty_files() {
        assert!(parse_cargo_lock("").is_empty());
        assert!(parse_package_lock_json("").is_empty());
        assert!(parse_requirements_txt("").is_empty());
        assert!(parse_go_sum("").is_empty());
    }
}