// ============================================================================
// File: quarantine.rs
// Description: Data quarantine validator checking imports for CSV injection and malicious content
// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
//! Data Quarantine — Validates imported data before it enters the system.
//!
//! Checks for CSV injection, embedded scripts, oversized payloads,
//! encoding issues, and other malicious content that could be smuggled
//! through the multi-source data connector.

use crate::config::QuarantineConfig;

/// Result of quarantine validation.
#[derive(Debug)]
pub struct QuarantineResult {
    pub passed: bool,
    pub violations: Vec<QuarantineViolation>,
}

#[derive(Debug, Clone)]
pub enum QuarantineViolation {
    /// Dataset exceeds maximum row count.
    TooManyRows { actual: usize, max: usize },
    /// Dataset exceeds maximum byte size.
    TooLarge { actual: usize, max: usize },
    /// Dataset exceeds maximum column count.
    TooManyColumns { actual: usize, max: usize },
    /// Cell contains formula injection character (=, +, -, @).
    FormulaInjection { row: usize, col: usize, prefix: char },
    /// Cell contains embedded script (<script>, javascript:, etc.).
    EmbeddedScript { row: usize, col: usize },
    /// Content contains null bytes.
    NullBytes,
    /// Suspicious repetitive pattern (possible padding attack).
    SuspiciousPattern { description: String },
}

/// Validate CSV content for malicious payloads before importing.
pub fn validate_csv(content: &str, config: &QuarantineConfig) -> QuarantineResult {
    let mut violations = Vec::new();

    // Check for null bytes
    if content.contains('\0') {
        violations.push(QuarantineViolation::NullBytes);
    }

    // Check total size
    if content.len() > config.max_size_bytes {
        violations.push(QuarantineViolation::TooLarge {
            actual: content.len(),
            max: config.max_size_bytes,
        });
        // Don't process further if too large
        return QuarantineResult {
            passed: false,
            violations,
        };
    }

    let lines: Vec<&str> = content.lines().collect();

    // Check row count
    if lines.len() > config.max_rows {
        violations.push(QuarantineViolation::TooManyRows {
            actual: lines.len(),
            max: config.max_rows,
        });
    }

    // Check column count from header
    if let Some(header) = lines.first() {
        let col_count = header.split(',').count();
        if col_count > config.max_columns {
            violations.push(QuarantineViolation::TooManyColumns {
                actual: col_count,
                max: config.max_columns,
            });
        }
    }

    // Check cells for injection
    // Only scan first 10000 rows for performance (attackers typically inject early)
    let scan_limit = lines.len().min(10_000);
    for (line_num, line) in lines.iter().enumerate().take(scan_limit) {
        for (col_num, cell) in line.split(',').enumerate() {
            let trimmed = cell.trim().trim_matches('"').trim_matches('\'');
            if trimmed.is_empty() {
                continue;
            }

            // Formula injection check
            if config.check_formula_injection {
                if let Some(first_char) = trimmed.chars().next() {
                    if matches!(first_char, '=' | '@' | '\t' | '\r') {
                        violations.push(QuarantineViolation::FormulaInjection {
                            row: line_num + 1,
                            col: col_num + 1,
                            prefix: first_char,
                        });
                    }
                    // + and - are only suspicious if not followed by a valid number
                    if matches!(first_char, '+' | '-') && trimmed.len() > 1 {
                        let rest = &trimmed[1..];
                        if rest.parse::<f64>().is_err() {
                            violations.push(QuarantineViolation::FormulaInjection {
                                row: line_num + 1,
                                col: col_num + 1,
                                prefix: first_char,
                            });
                        }
                    }
                }
            }

            // Embedded script check
            if config.check_embedded_scripts {
                let lower = trimmed.to_lowercase();
                if lower.contains("<script")
                    || lower.contains("javascript:")
                    || lower.contains("onerror=")
                    || lower.contains("onload=")
                    || lower.contains("onclick=")
                    || lower.contains("vbscript:")
                    || lower.contains("data:text/html")
                {
                    violations.push(QuarantineViolation::EmbeddedScript {
                        row: line_num + 1,
                        col: col_num + 1,
                    });
                }
            }
        }
    }

    // Check for suspicious repetitive patterns (padding/amplification attacks)
    if content.len() > 1000 {
        let sample = &content[..1000.min(content.len())];
        let unique_chars: std::collections::HashSet<char> = sample.chars().collect();
        // If the content has very low character diversity, it might be a padding attack
        if unique_chars.len() < 5 && content.len() > 10_000 {
            violations.push(QuarantineViolation::SuspiciousPattern {
                description: format!(
                    "Very low character diversity ({} unique chars in {} byte payload)",
                    unique_chars.len(),
                    content.len()
                ),
            });
        }
    }

    QuarantineResult {
        passed: violations.is_empty(),
        violations,
    }
}

/// Quick check if a JSON response from an external source looks safe.
/// Returns Err with reason if suspicious content is detected.
pub fn validate_json_response(json_str: &str, max_size: usize) -> Result<(), String> {
    if json_str.len() > max_size {
        return Err(format!(
            "JSON response too large: {} > {} bytes",
            json_str.len(),
            max_size
        ));
    }

    if json_str.contains('\0') {
        return Err("JSON response contains null bytes".into());
    }

    // Check for script injection in JSON values
    let lower = json_str.to_lowercase();
    if lower.contains("<script") || lower.contains("javascript:") {
        return Err("JSON response contains embedded script content".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> QuarantineConfig {
        QuarantineConfig::default()
    }

    #[test]
    fn allows_normal_csv() {
        let csv = "timestamp,temperature,humidity\n2026-01-01,72.5,45.2\n2026-01-02,71.8,46.1\n";
        let result = validate_csv(csv, &default_config());
        assert!(result.passed, "Normal CSV should pass: {:?}", result.violations);
    }

    #[test]
    fn allows_negative_numbers() {
        let csv = "timestamp,delta\n2026-01-01,-5.3\n2026-01-02,-0.1\n";
        let result = validate_csv(csv, &default_config());
        assert!(result.passed, "Negative numbers should be allowed");
    }

    #[test]
    fn blocks_formula_injection() {
        let csv = "name,value\n=CMD('calc'),100\n";
        let result = validate_csv(csv, &default_config());
        assert!(!result.passed);
        assert!(result.violations.iter().any(|v| matches!(v, QuarantineViolation::FormulaInjection { .. })));
    }

    #[test]
    fn blocks_embedded_scripts() {
        let csv = "name,value\n<script>alert('xss')</script>,100\n";
        let result = validate_csv(csv, &default_config());
        assert!(!result.passed);
        assert!(result.violations.iter().any(|v| matches!(v, QuarantineViolation::EmbeddedScript { .. })));
    }

    #[test]
    fn blocks_null_bytes() {
        let csv = "name,value\ntest\0,100\n";
        let result = validate_csv(csv, &default_config());
        assert!(!result.passed);
    }

    #[test]
    fn blocks_oversized_data() {
        let mut config = default_config();
        config.max_size_bytes = 100;
        let csv = "a".repeat(200);
        let result = validate_csv(&csv, &config);
        assert!(!result.passed);
    }

    #[test]
    fn blocks_too_many_columns() {
        let mut config = default_config();
        config.max_columns = 3;
        let csv = "a,b,c,d,e\n1,2,3,4,5\n";
        let result = validate_csv(&csv, &config);
        assert!(!result.passed);
    }
}