// ============================================================================
// File: sanitizer.rs
// Description: Input sanitizer for connection strings, path traversal, and error messages
// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
//! Input Sanitizer — Connection string validation, path traversal prevention,
//! and error message sanitization.

/// Validate and sanitize a database connection string.
/// Blocks shell metacharacters, validates format, and checks file paths for traversal.
pub fn validate_connection_string(conn_str: &str) -> Result<String, String> {
    // Block empty strings
    if conn_str.trim().is_empty() {
        return Err("Connection string is empty".into());
    }

    // Block shell metacharacters that could enable command injection
    let shell_chars = ['`', '$', '|', '&', ';', '\n', '\r', '\0'];
    for ch in &shell_chars {
        if conn_str.contains(*ch) {
            return Err(format!(
                "Connection string contains forbidden character: '{}'",
                ch.escape_default()
            ));
        }
    }

    // Block $() and ${} command substitution
    if conn_str.contains("$(") || conn_str.contains("${") {
        return Err("Connection string contains shell command substitution".into());
    }

    // Determine type and validate format
    if conn_str.starts_with("postgresql://")
        || conn_str.starts_with("postgres://")
        || conn_str.starts_with("mysql://")
    {
        validate_database_url(conn_str)
    } else if conn_str.starts_with("http://") || conn_str.starts_with("https://") {
        // HTTP URLs are validated by ssrf_guard separately
        Ok(conn_str.to_string())
    } else {
        // Treat as a file path (SQLite)
        validate_file_path(conn_str)?;
        Ok(conn_str.to_string())
    }
}

fn validate_database_url(url: &str) -> Result<String, String> {
    // Check for SQL injection in connection parameters
    let dangerous_params = [
        "sslrootcert=/etc",
        "sslcert=/proc",
        "init_command=",
        "options=-c",
        "application_name=';",
    ];
    let lower = url.to_lowercase();
    for param in &dangerous_params {
        if lower.contains(param) {
            return Err(format!(
                "Connection URL contains suspicious parameter: {}",
                param
            ));
        }
    }

    // Validate the URL can be parsed
    if url::Url::parse(url).is_err() {
        return Err("Connection string is not a valid URL".into());
    }

    Ok(url.to_string())
}

/// Prevent path traversal attacks in file paths (primarily SQLite database paths).
pub fn validate_file_path(path: &str) -> Result<(), String> {
    // Block path traversal
    if path.contains("..") {
        return Err("Path contains '..' (path traversal)".into());
    }

    // Block null bytes (can truncate paths in C-based libraries)
    if path.contains('\0') {
        return Err("Path contains null byte".into());
    }

    // Block access to sensitive system directories
    let blocked_prefixes = [
        "/etc/", "/proc/", "/sys/", "/dev/", "/root/", "/boot/",
        "/var/run/", "/var/log/", "/tmp/.", "/home/",
        "C:\\Windows\\", "C:\\Users\\",
    ];
    let normalized = path.replace('\\', "/").to_lowercase();
    for prefix in &blocked_prefixes {
        if normalized.starts_with(&prefix.to_lowercase()) {
            return Err(format!("Access to '{}' is blocked", prefix));
        }
    }

    // Block access to sensitive files by name
    let blocked_names = [
        "passwd", "shadow", "id_rsa", "id_ed25519", "authorized_keys",
        ".ssh", ".env", ".git", "credentials", "secret", ".bash_history",
        ".pgpass", ".my.cnf", "wp-config.php",
    ];
    let lower_path = path.to_lowercase();
    for name in &blocked_names {
        if lower_path.contains(name) {
            return Err(format!(
                "Path contains sensitive filename pattern: '{}'",
                name
            ));
        }
    }

    // Verify path is absolute (relative paths could escape intended directories)
    if !path.starts_with('/') && !path.starts_with("C:\\") && !path.starts_with("D:\\") {
        return Err("File path must be absolute".into());
    }

    Ok(())
}

/// Sanitize error messages to prevent information leakage.
/// Strips internal paths, stack traces, and IP addresses from error output.
pub fn sanitize_error_message(err: &str) -> String {
    let mut result = err.to_string();

    // Remove file paths (Unix and Windows)
    result = redact_paths(&result);

    // Remove internal IP addresses (keep public-facing info vague)
    result = redact_internal_ips(&result);

    // Remove stack traces
    result = remove_stack_traces(&result);

    // Truncate overly long error messages
    if result.len() > 500 {
        result.truncate(500);
        result.push_str("...");
    }

    result
}

fn redact_paths(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut i = 0;
    let bytes = s.as_bytes();

    while i < bytes.len() {
        // Detect Unix paths
        if bytes[i] == b'/' && i + 1 < bytes.len() && (bytes[i + 1].is_ascii_alphanumeric() || bytes[i + 1] == b'.') {
            // Check if this looks like a file path (has directory separators)
            let path_end = find_path_end(s, i);
            if path_end > i + 3 && s[i..path_end].contains('/') && s[i..path_end].matches('/').count() >= 2 {
                result.push_str("[path redacted]");
                i = path_end;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }

    result
}

fn find_path_end(s: &str, start: usize) -> usize {
    let mut end = start;
    for (i, ch) in s[start..].char_indices() {
        if ch.is_whitespace() || ch == '\'' || ch == '"' || ch == ')' || ch == ']' {
            return start + i;
        }
        end = start + i + ch.len_utf8();
    }
    end
}

fn redact_internal_ips(s: &str) -> String {
    let mut result = s.to_string();
    // Redact 10.x.x.x, 172.16-31.x.x, 192.168.x.x patterns
    // Simple approach: scan for IP-like patterns
    for prefix in &["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168."] {
        while let Some(pos) = result.find(prefix) {
            // Find the end of the IP address
            let ip_end = result[pos..].find(|c: char| !c.is_ascii_digit() && c != '.').map(|i| pos + i).unwrap_or(result.len());
            let ip_candidate = &result[pos..ip_end];
            // Basic validation: should have at least 3 dots
            if ip_candidate.matches('.').count() >= 3 {
                result.replace_range(pos..ip_end, "[internal-ip]");
            } else {
                break;
            }
        }
    }
    result
}

fn remove_stack_traces(s: &str) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let mut result = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        // Skip lines that look like stack traces
        if trimmed.starts_with("at ") && trimmed.contains(':') {
            continue;
        }
        if trimmed.starts_with("thread '") && trimmed.contains("panicked at") {
            result.push("Internal error occurred");
            continue;
        }
        if trimmed.starts_with("stack backtrace:") {
            break; // Stop including lines after this
        }
        result.push(line);
    }
    result.join("\n")
}

/// Sanitize a value that will be used in a header to prevent header injection.
pub fn sanitize_header_value(value: &str) -> String {
    value.replace('\r', "").replace('\n', "").replace('\0', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_valid_postgres_url() {
        assert!(validate_connection_string("postgresql://user:pass@host:5432/db").is_ok());
    }

    #[test]
    fn allows_valid_mysql_url() {
        assert!(validate_connection_string("mysql://user:pass@host:3306/db").is_ok());
    }

    #[test]
    fn blocks_shell_metacharacters() {
        assert!(validate_connection_string("postgresql://host/db; rm -rf /").is_err());
        assert!(validate_connection_string("postgresql://host/db`whoami`").is_err());
        assert!(validate_connection_string("postgresql://host/$(cat /etc/passwd)").is_err());
    }

    #[test]
    fn blocks_path_traversal() {
        assert!(validate_file_path("/data/../etc/passwd").is_err());
        assert!(validate_file_path("/data/../../root/.ssh/id_rsa").is_err());
    }

    #[test]
    fn blocks_sensitive_paths() {
        assert!(validate_file_path("/etc/passwd").is_err());
        assert!(validate_file_path("/proc/self/environ").is_err());
        assert!(validate_file_path("/root/.ssh/id_rsa").is_err());
    }

    #[test]
    fn blocks_relative_paths() {
        assert!(validate_file_path("relative/path/db.sqlite").is_err());
    }

    #[test]
    fn allows_valid_sqlite_path() {
        assert!(validate_file_path("/opt/data/sensors.db").is_ok());
        assert!(validate_file_path("/var/lib/prometheus/datasets/imported.sqlite3").is_ok());
    }

    #[test]
    fn sanitizes_error_messages() {
        let raw = "Failed to connect to /opt/internal/db at 192.168.1.50:5432";
        let sanitized = sanitize_error_message(raw);
        assert!(!sanitized.contains("/opt/internal/db"), "Path should be redacted");
        assert!(!sanitized.contains("192.168.1.50"), "Internal IP should be redacted");
    }

    #[test]
    fn strips_header_injection() {
        assert_eq!(sanitize_header_value("value\r\nX-Injected: true"), "valueX-Injected: true");
    }
}