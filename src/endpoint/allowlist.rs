// ============================================================================
// File: endpoint/allowlist.rs
// Description: Developer-aware allowlist — auto-detects toolchains to eliminate false positives
// ============================================================================
//! Developer Allowlist — knows compilers, build tools, IDEs, and runtimes.
//!
//! Auto-detects installed dev environments (Rust, Node, Python, Go, Docker, Java,
//! C/C++) and builds an allowlist of paths and process names that should never be
//! flagged as threats. This is what makes NexusShield zero-false-positive on dev machines.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Configuration for the developer allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistConfig {
    /// Auto-detect installed dev environments on startup.
    pub auto_detect: bool,
    /// Additional path patterns to always skip (glob-like).
    pub custom_allow_paths: Vec<String>,
    /// Additional process names to always skip.
    pub custom_allow_processes: Vec<String>,
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        Self {
            auto_detect: true,
            custom_allow_paths: Vec::new(),
            custom_allow_processes: Vec::new(),
        }
    }
}

/// Developer-aware allowlist that auto-detects toolchains.
pub struct DeveloperAllowlist {
    config: AllowlistConfig,
    /// Path patterns to skip (component matches and extension matches).
    skip_paths: RwLock<Vec<String>>,
    /// Process names to skip.
    skip_processes: RwLock<HashSet<String>>,
}

impl DeveloperAllowlist {
    pub fn new(config: AllowlistConfig) -> Self {
        let al = Self {
            config: config.clone(),
            skip_paths: RwLock::new(Vec::new()),
            skip_processes: RwLock::new(HashSet::new()),
        };
        if config.auto_detect {
            al.detect_dev_environments();
        }
        // Always add custom overrides
        {
            let mut paths = al.skip_paths.write();
            for p in &config.custom_allow_paths {
                paths.push(p.clone());
            }
        }
        {
            let mut procs = al.skip_processes.write();
            for p in &config.custom_allow_processes {
                procs.insert(p.clone());
            }
        }
        al
    }

    /// Scan the filesystem for installed dev environments and populate allowlists.
    pub fn detect_dev_environments(&self) {
        let mut paths = self.skip_paths.write();
        let mut procs = self.skip_processes.write();

        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let home_path = PathBuf::from(&home);

        // === Build output (always skip — universal across languages) ===
        paths.push("target/debug".to_string());
        paths.push("target/release".to_string());

        // === Rust ===
        if home_path.join(".cargo/bin").exists() || home_path.join(".rustup").exists() {
            paths.push(".rustup".to_string());
            paths.push(".cargo/registry".to_string());
            for name in &["rustc", "cargo", "rust-analyzer", "clippy-driver", "rustfmt", "cargo-clippy", "rustup"] {
                procs.insert(name.to_string());
            }
        }

        // === Node.js ===
        if home_path.join(".nvm").exists()
            || home_path.join(".npm").exists()
            || Path::new("/usr/bin/node").exists()
            || Path::new("/usr/local/bin/node").exists()
        {
            paths.push("node_modules".to_string());
            paths.push(".npm".to_string());
            paths.push(".nvm".to_string());
            paths.push(".yarn".to_string());
            paths.push(".pnpm-store".to_string());
            for name in &["node", "npm", "npx", "yarn", "pnpm", "bun", "deno", "tsx", "ts-node"] {
                procs.insert(name.to_string());
            }
        }

        // === Python ===
        if Path::new("/usr/bin/python3").exists()
            || Path::new("/usr/local/bin/python3").exists()
            || home_path.join(".conda").exists()
        {
            paths.push("__pycache__".to_string());
            paths.push(".venv".to_string());
            paths.push("venv".to_string());
            paths.push(".conda".to_string());
            paths.push(".local/lib/python".to_string());
            for name in &["python", "python3", "pip", "pip3", "conda", "jupyter", "ipython", "poetry", "pdm"] {
                procs.insert(name.to_string());
            }
        }

        // === Go ===
        if home_path.join("go").exists() || std::env::var("GOPATH").is_ok() {
            paths.push("go/pkg".to_string());
            paths.push("go/bin".to_string());
            for name in &["go", "gopls", "dlv", "staticcheck"] {
                procs.insert(name.to_string());
            }
        }

        // === Docker ===
        if Path::new("/usr/bin/docker").exists() || Path::new("/usr/local/bin/docker").exists() {
            paths.push("/var/lib/docker".to_string());
            for name in &["docker", "dockerd", "containerd", "containerd-shim", "runc", "docker-compose", "podman", "buildah"] {
                procs.insert(name.to_string());
            }
        }

        // === Java / JVM ===
        if Path::new("/usr/bin/javac").exists()
            || Path::new("/usr/local/bin/javac").exists()
            || std::env::var("JAVA_HOME").is_ok()
        {
            paths.push(".gradle".to_string());
            paths.push(".m2/repository".to_string());
            for name in &["java", "javac", "gradle", "gradlew", "mvn", "mvnw", "kotlin", "kotlinc", "scala", "sbt"] {
                procs.insert(name.to_string());
            }
        }

        // === IDEs (always allow) ===
        for name in &[
            "code", "code-server", "codium",
            "idea", "idea64", "clion", "goland", "pycharm", "webstorm", "rider", "rustrover",
            "vim", "nvim", "emacs", "nano", "helix", "zed",
            "sublime_text", "atom",
        ] {
            procs.insert(name.to_string());
        }

        // === Compilers & debuggers (always allow) ===
        for name in &[
            "gcc", "g++", "cc", "c++", "clang", "clang++",
            "make", "cmake", "ninja", "meson",
            "gdb", "lldb", "strace", "ltrace", "perf", "valgrind",
            "ld", "as", "ar", "nm", "objdump", "strip",
        ] {
            procs.insert(name.to_string());
        }

        // === Git ===
        paths.push(".git/objects".to_string());
        paths.push(".git/pack".to_string());
        paths.push(".git/lfs".to_string());
        for name in &["git", "git-lfs", "gh", "hub"] {
            procs.insert(name.to_string());
        }

        // === Build artifacts & caches (always skip) ===
        // Use absolute path to avoid substring matching on random ".cache" in filenames
        let cache_dir = format!("{}/.cache", home);
        paths.push(cache_dir);
        paths.push(".local/share/Trash".to_string());

        // Extension-based skips — ONLY safe build artifacts, NOT executables
        // NOTE: .so, .a, .dylib are NOT skipped globally — they can contain malware.
        // They are only skipped when inside known dev paths (target/, .cargo/, node_modules/).
        paths.push("*.rlib".to_string());  // Rust intermediate (never standalone)
        paths.push("*.rmeta".to_string()); // Rust metadata (never standalone)
        paths.push("*.d".to_string());     // Dependency files (text)
        paths.push("*.pyc".to_string());   // Python bytecode
        paths.push("*.pyo".to_string());   // Python optimized bytecode
    }

    /// Check whether a file path should be skipped by scanners.
    pub fn should_skip_path(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        let patterns = self.skip_paths.read();

        for pattern in patterns.iter() {
            // Extension match: *.ext
            if let Some(ext_pattern) = pattern.strip_prefix("*.") {
                if let Some(ext) = path.extension() {
                    if ext.to_string_lossy().eq_ignore_ascii_case(ext_pattern) {
                        return true;
                    }
                }
                continue;
            }

            // Absolute path prefix match
            if pattern.starts_with('/') {
                if path_str.starts_with(pattern.as_str()) {
                    return true;
                }
                continue;
            }

            // Component match: check if any path component or segment contains the pattern
            // This handles "node_modules", "target/debug", ".git/objects", etc.
            if path_str.contains(pattern.as_str()) {
                return true;
            }
        }

        false
    }

    /// Check whether a process name should be skipped by the process monitor.
    pub fn should_skip_process(&self, name: &str) -> bool {
        self.skip_processes.read().contains(name)
    }

    /// Re-run environment detection (e.g., after installing new tools).
    pub fn refresh(&self) {
        {
            let mut paths = self.skip_paths.write();
            paths.clear();
        }
        {
            let mut procs = self.skip_processes.write();
            procs.clear();
        }
        if self.config.auto_detect {
            self.detect_dev_environments();
        }
        let mut paths = self.skip_paths.write();
        for p in &self.config.custom_allow_paths {
            paths.push(p.clone());
        }
        let mut procs = self.skip_processes.write();
        for p in &self.config.custom_allow_processes {
            procs.insert(p.clone());
        }
    }

    /// Get the number of path patterns in the allowlist.
    pub fn path_pattern_count(&self) -> usize {
        self.skip_paths.read().len()
    }

    /// Get the number of allowed process names.
    pub fn process_count(&self) -> usize {
        self.skip_processes.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_allowlist() -> DeveloperAllowlist {
        DeveloperAllowlist::new(AllowlistConfig::default())
    }

    #[test]
    fn node_modules_skipped() {
        let al = test_allowlist();
        assert!(al.should_skip_path(Path::new("/home/user/project/node_modules/express/index.js")));
        assert!(al.should_skip_path(Path::new("/tmp/app/node_modules/.package-lock.json")));
    }

    #[test]
    fn target_debug_skipped() {
        let al = test_allowlist();
        assert!(al.should_skip_path(Path::new("/home/user/project/target/debug/myapp")));
        assert!(al.should_skip_path(Path::new("/opt/project/target/release/libfoo.so")));
    }

    #[test]
    fn git_objects_skipped() {
        let al = test_allowlist();
        assert!(al.should_skip_path(Path::new("/home/user/repo/.git/objects/ab/cdef1234")));
        assert!(al.should_skip_path(Path::new("/home/user/repo/.git/pack/pack-abc.idx")));
    }

    #[test]
    fn build_artifacts_in_dev_paths_skipped() {
        let al = test_allowlist();
        // .o, .a, .so are NOT globally skipped anymore — only in dev paths
        assert!(!al.should_skip_path(Path::new("/tmp/build/main.o")));
        assert!(!al.should_skip_path(Path::new("/tmp/lib/libcrypto.a")));
        assert!(!al.should_skip_path(Path::new("/tmp/lib/libssl.so")));
        // But Rust intermediates are still skipped
        assert!(al.should_skip_path(Path::new("/tmp/build/dep.rlib")));
        assert!(al.should_skip_path(Path::new("/tmp/build/dep.rmeta")));
    }

    #[test]
    fn normal_files_not_skipped() {
        let al = test_allowlist();
        assert!(!al.should_skip_path(Path::new("/home/user/Downloads/invoice.pdf")));
        assert!(!al.should_skip_path(Path::new("/tmp/suspicious.exe")));
        assert!(!al.should_skip_path(Path::new("/home/user/document.txt")));
    }

    #[test]
    fn compiler_processes_skipped() {
        let al = test_allowlist();
        assert!(al.should_skip_process("gcc"));
        assert!(al.should_skip_process("clang"));
        assert!(al.should_skip_process("make"));
        assert!(al.should_skip_process("gdb"));
    }

    #[test]
    fn ide_processes_skipped() {
        let al = test_allowlist();
        assert!(al.should_skip_process("code"));
        assert!(al.should_skip_process("nvim"));
        assert!(al.should_skip_process("idea"));
    }

    #[test]
    fn unknown_process_not_skipped() {
        let al = test_allowlist();
        assert!(!al.should_skip_process("totally-not-malware"));
        assert!(!al.should_skip_process("xmrig"));
    }

    #[test]
    fn custom_overrides_work() {
        let config = AllowlistConfig {
            auto_detect: false,
            custom_allow_paths: vec!["my-special-dir".to_string()],
            custom_allow_processes: vec!["my-tool".to_string()],
        };
        let al = DeveloperAllowlist::new(config);
        assert!(al.should_skip_path(Path::new("/home/user/my-special-dir/file.bin")));
        assert!(al.should_skip_process("my-tool"));
    }

    #[test]
    fn refresh_redetects() {
        let al = test_allowlist();
        let count_before = al.path_pattern_count();
        al.refresh();
        let count_after = al.path_pattern_count();
        assert_eq!(count_before, count_after);
    }
}