// ============================================================================
// File: email_guard.rs
// Description: Email endpoint protection against header injection, bombing, and abuse
// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
//! Email Guard — Protects email endpoints from abuse and injection attacks.
//!
//! Covers: header injection (CRLF), email bombing, HTML/template injection,
//! address validation, recipient abuse, content weaponization.

use std::collections::HashMap;
use std::time::Instant;
use parking_lot::Mutex;

/// Result of email guard validation.
#[derive(Debug)]
pub struct EmailGuardResult {
    pub allowed: bool,
    pub violations: Vec<EmailViolation>,
}

/// Types of email-specific violations detected.
#[derive(Debug, Clone)]
pub enum EmailViolation {
    /// CRLF/newline in header field (subject, name, etc.)
    HeaderInjection(String),
    /// Invalid email address format
    InvalidAddress(String),
    /// Dangerous domain (disposable, localhost, internal)
    BlockedDomain(String),
    /// Too many recipients (bombing attempt)
    ExcessiveRecipients(u32),
    /// Rate limit on email sends per recipient
    RecipientBombing(String),
    /// HTML/script injection in template parameters
    ContentInjection(String),
    /// Oversized field (subject, body, etc.)
    OversizedField { field: String, len: usize, max: usize },
    /// Encoded attack payload (base64, unicode confusables)
    EncodedPayload(String),
}

/// Configuration for the email guard.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailGuardConfig {
    /// Maximum emails per recipient per window.
    pub max_per_recipient: u32,
    /// Time window for rate limiting (seconds).
    pub rate_window_secs: u64,
    /// Maximum recipients per single email.
    pub max_recipients: u32,
    /// Maximum subject length.
    pub max_subject_len: usize,
    /// Maximum body/message field length.
    pub max_body_len: usize,
    /// Maximum username/name field length.
    pub max_name_len: usize,
    /// Blocked email domains.
    pub blocked_domains: Vec<String>,
}

impl Default for EmailGuardConfig {
    fn default() -> Self {
        Self {
            max_per_recipient: 5,
            rate_window_secs: 300, // 5 minutes
            max_recipients: 10,
            max_subject_len: 200,
            max_body_len: 10_000,
            max_name_len: 100,
            blocked_domains: vec![
                // Localhost / internal
                "localhost".into(),
                "127.0.0.1".into(),
                "0.0.0.0".into(),
                "[::1]".into(),
                "internal".into(),
                "local".into(),
                "corp".into(),
                // Common disposable email services
                "mailinator.com".into(),
                "guerrillamail.com".into(),
                "tempmail.com".into(),
                "throwaway.email".into(),
                "yopmail.com".into(),
                "sharklasers.com".into(),
                "guerrillamailblock.com".into(),
                "grr.la".into(),
                "dispostable.com".into(),
                "trashmail.com".into(),
            ],
        }
    }
}

/// Per-recipient send tracker for bombing prevention.
pub struct EmailRateLimiter {
    /// Map of email address -> list of send timestamps.
    sends: Mutex<HashMap<String, Vec<Instant>>>,
    config: EmailGuardConfig,
}

impl EmailRateLimiter {
    pub fn new(config: EmailGuardConfig) -> Self {
        Self {
            sends: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Check if sending to this recipient is allowed, and record the attempt.
    pub fn check_and_record(&self, recipient: &str) -> bool {
        let mut sends = self.sends.lock();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.config.rate_window_secs);

        let entry = sends
            .entry(recipient.to_lowercase())
            .or_insert_with(Vec::new);

        // Prune old entries
        entry.retain(|t| now.duration_since(*t) < window);

        if entry.len() >= self.config.max_per_recipient as usize {
            false
        } else {
            entry.push(now);
            true
        }
    }

    /// Prune stale entries across all recipients.
    pub fn prune(&self) {
        let mut sends = self.sends.lock();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.config.rate_window_secs);
        sends.retain(|_, timestamps| {
            timestamps.retain(|t| now.duration_since(*t) < window);
            !timestamps.is_empty()
        });
    }
}

// ─── Validation functions ───────────────────────────────────────

/// Validate an email address for format and domain safety.
pub fn validate_email_address(addr: &str, config: &EmailGuardConfig) -> Vec<EmailViolation> {
    let mut violations = Vec::new();

    // CRLF injection
    if has_crlf(addr) {
        violations.push(EmailViolation::HeaderInjection(
            "Email address contains newline characters".into(),
        ));
        return violations; // Stop early — address is weaponized
    }

    // Basic format check (must have exactly one @, non-empty local and domain)
    let parts: Vec<&str> = addr.splitn(2, '@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        violations.push(EmailViolation::InvalidAddress(
            format!("Invalid email format: {}", truncate(addr, 50)),
        ));
        return violations;
    }

    let domain = parts[1].to_lowercase();

    // Null bytes
    if addr.contains('\0') {
        violations.push(EmailViolation::InvalidAddress(
            "Email address contains null byte".into(),
        ));
    }

    // Length check
    if addr.len() > 254 {
        violations.push(EmailViolation::InvalidAddress(
            "Email address exceeds maximum length (254)".into(),
        ));
    }

    // Domain validation
    if domain.contains("..") {
        violations.push(EmailViolation::InvalidAddress(
            "Domain contains consecutive dots".into(),
        ));
    }

    // Check blocked domains
    for blocked in &config.blocked_domains {
        if domain == *blocked || domain.ends_with(&format!(".{}", blocked)) {
            violations.push(EmailViolation::BlockedDomain(
                format!("Email domain '{}' is blocked", domain),
            ));
            break;
        }
    }

    // IP address as domain (often used for bombing/scanning)
    if domain.starts_with('[') || domain.parse::<std::net::IpAddr>().is_ok() {
        violations.push(EmailViolation::BlockedDomain(
            "IP address domains are not allowed".into(),
        ));
    }

    violations
}

/// Validate a header field (subject, name, ticket_id) for injection.
pub fn validate_header_field(field_name: &str, value: &str, max_len: usize) -> Vec<EmailViolation> {
    let mut violations = Vec::new();

    // CRLF injection (the primary email header attack vector)
    if has_crlf(value) {
        violations.push(EmailViolation::HeaderInjection(
            format!("'{}' contains newline characters (header injection)", field_name),
        ));
    }

    // Null bytes
    if value.contains('\0') {
        violations.push(EmailViolation::HeaderInjection(
            format!("'{}' contains null byte", field_name),
        ));
    }

    // Length
    if value.len() > max_len {
        violations.push(EmailViolation::OversizedField {
            field: field_name.into(),
            len: value.len(),
            max: max_len,
        });
    }

    // Check for encoded attack payloads in header fields
    if has_encoded_attacks(value) {
        violations.push(EmailViolation::EncodedPayload(
            format!("'{}' contains suspicious encoded content", field_name),
        ));
    }

    violations
}

/// Validate content that will be interpolated into HTML templates.
/// Prevents XSS-in-email and template injection.
pub fn validate_template_content(field_name: &str, value: &str, max_len: usize) -> Vec<EmailViolation> {
    let mut violations = Vec::new();

    // Length check
    if value.len() > max_len {
        violations.push(EmailViolation::OversizedField {
            field: field_name.into(),
            len: value.len(),
            max: max_len,
        });
    }

    // HTML/script injection patterns
    let lower = value.to_lowercase();
    let injection_patterns = [
        "<script",
        "</script",
        "javascript:",
        "vbscript:",
        "data:text/html",
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "onfocus=",
        "onblur=",
        "eval(",
        "expression(",
        "url(data:",
        "<iframe",
        "<object",
        "<embed",
        "<form",
        "<input",
        "<meta",
        "<link",
        "<base",
        "<svg",
        "<!--",
        "srcdoc=",
    ];

    for pattern in &injection_patterns {
        if lower.contains(pattern) {
            violations.push(EmailViolation::ContentInjection(
                format!("'{}' contains prohibited HTML/script content", field_name),
            ));
            break;
        }
    }

    // CRLF in body is less critical but still flag it for content fields
    // that will appear in HTML (could break email structure)
    if has_crlf(value) && field_name != "message" && field_name != "response_body" {
        violations.push(EmailViolation::HeaderInjection(
            format!("'{}' contains newline characters", field_name),
        ));
    }

    violations
}

/// Sanitize text that will be placed inside HTML templates.
/// Escapes HTML special characters to prevent injection.
pub fn html_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#x27;"),
            '/' => result.push_str("&#x2F;"),
            '\0' => {} // strip null bytes
            _ => result.push(ch),
        }
    }
    result
}

/// Full validation for outbound email parameters.
/// Returns Ok(()) if all checks pass, or Err with a reason string.
pub fn validate_outbound_email(
    to: &[&str],
    subject: &str,
    body_fields: &[(&str, &str)],
    config: &EmailGuardConfig,
) -> Result<(), String> {
    let mut all_violations = Vec::new();

    // Recipient count
    if to.len() > config.max_recipients as usize {
        all_violations.push(EmailViolation::ExcessiveRecipients(to.len() as u32));
    }

    // Validate each recipient address
    for addr in to {
        all_violations.extend(validate_email_address(addr, config));
    }

    // Validate subject
    all_violations.extend(validate_header_field("subject", subject, config.max_subject_len));

    // Validate body fields
    for (name, value) in body_fields {
        all_violations.extend(validate_template_content(name, value, config.max_body_len));
    }

    if all_violations.is_empty() {
        Ok(())
    } else {
        let reasons: Vec<String> = all_violations.iter().map(|v| format!("{:?}", v)).collect();
        Err(reasons.join("; "))
    }
}

// ─── Internal helpers ───────────────────────────────────────────

/// Check for CRLF/newline characters (header injection vector).
fn has_crlf(s: &str) -> bool {
    s.contains('\r') || s.contains('\n')
}

/// Detect encoded attack payloads (base64-encoded scripts, unicode tricks).
fn has_encoded_attacks(s: &str) -> bool {
    let lower = s.to_lowercase();

    // Base64-encoded common attack strings
    // PHNjcmlwdD4= is base64 for "<script>"
    // amF2YXNjcmlwdDo= is base64 for "javascript:"
    let b64_patterns = [
        "phnjcmlwdd4",   // <script>
        "amf2yxnjcmlwddo", // javascript:
        "phn2zw",        // <svg
        "pgfszxj0k",     // >alert(
    ];
    for pattern in &b64_patterns {
        if lower.contains(pattern) {
            return true;
        }
    }

    // Unicode right-to-left override (used to disguise file extensions / email content)
    if s.contains('\u{202E}') || s.contains('\u{200F}') || s.contains('\u{200E}') {
        return true;
    }

    // Zero-width characters (can hide content)
    if s.contains('\u{200B}') || s.contains('\u{FEFF}') || s.contains('\u{200C}') || s.contains('\u{200D}') {
        return true;
    }

    false
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> EmailGuardConfig {
        EmailGuardConfig::default()
    }

    // ─── Address validation ─────────────────────────

    #[test]
    fn allows_valid_email() {
        let v = validate_email_address("user@example.com", &config());
        assert!(v.is_empty(), "Expected no violations: {:?}", v);
    }

    #[test]
    fn blocks_crlf_in_email() {
        let v = validate_email_address("user@example.com\r\nBcc: victim@evil.com", &config());
        assert!(!v.is_empty());
        assert!(matches!(v[0], EmailViolation::HeaderInjection(_)));
    }

    #[test]
    fn blocks_missing_at_sign() {
        let v = validate_email_address("not-an-email", &config());
        assert!(!v.is_empty());
        assert!(matches!(v[0], EmailViolation::InvalidAddress(_)));
    }

    #[test]
    fn blocks_empty_local_part() {
        let v = validate_email_address("@example.com", &config());
        assert!(!v.is_empty());
        assert!(matches!(v[0], EmailViolation::InvalidAddress(_)));
    }

    #[test]
    fn blocks_disposable_domain() {
        let v = validate_email_address("user@mailinator.com", &config());
        assert!(v.iter().any(|v| matches!(v, EmailViolation::BlockedDomain(_))));
    }

    #[test]
    fn blocks_localhost_domain() {
        let v = validate_email_address("admin@localhost", &config());
        assert!(v.iter().any(|v| matches!(v, EmailViolation::BlockedDomain(_))));
    }

    #[test]
    fn blocks_ip_domain() {
        let v = validate_email_address("admin@[127.0.0.1]", &config());
        assert!(v.iter().any(|v| matches!(v, EmailViolation::BlockedDomain(_))));
    }

    // ─── Header injection ───────────────────────────

    #[test]
    fn blocks_crlf_in_subject() {
        let v = validate_header_field("subject", "Hello\r\nBcc: hacker@evil.com", 200);
        assert!(v.iter().any(|v| matches!(v, EmailViolation::HeaderInjection(_))));
    }

    #[test]
    fn blocks_newline_in_name() {
        let v = validate_header_field("username", "John\nBcc: hack@evil.com", 100);
        assert!(v.iter().any(|v| matches!(v, EmailViolation::HeaderInjection(_))));
    }

    #[test]
    fn blocks_oversized_subject() {
        let long = "A".repeat(300);
        let v = validate_header_field("subject", &long, 200);
        assert!(v.iter().any(|v| matches!(v, EmailViolation::OversizedField { .. })));
    }

    // ─── Template injection ─────────────────────────

    #[test]
    fn blocks_script_in_content() {
        let v = validate_template_content("message", "Hello <script>alert('xss')</script>", 10000);
        assert!(v.iter().any(|v| matches!(v, EmailViolation::ContentInjection(_))));
    }

    #[test]
    fn blocks_javascript_protocol() {
        let v = validate_template_content("message", "Click javascript:alert(1)", 10000);
        assert!(v.iter().any(|v| matches!(v, EmailViolation::ContentInjection(_))));
    }

    #[test]
    fn blocks_event_handlers() {
        let v = validate_template_content("message", "<img onerror=alert(1) src=x>", 10000);
        assert!(v.iter().any(|v| matches!(v, EmailViolation::ContentInjection(_))));
    }

    #[test]
    fn blocks_svg_injection() {
        let v = validate_template_content("message", "<svg onload=fetch('evil.com')>", 10000);
        assert!(v.iter().any(|v| matches!(v, EmailViolation::ContentInjection(_))));
    }

    #[test]
    fn allows_normal_text_content() {
        let v = validate_template_content("message", "Hello, this is a normal support message!", 10000);
        assert!(v.is_empty());
    }

    // ─── Encoded attacks ────────────────────────────

    #[test]
    fn blocks_unicode_bidi_override() {
        let v = validate_header_field("username", "normal\u{202E}txe.exe", 100);
        assert!(v.iter().any(|v| matches!(v, EmailViolation::EncodedPayload(_))));
    }

    #[test]
    fn blocks_zero_width_chars() {
        let v = validate_header_field("username", "adm\u{200B}in", 100);
        assert!(v.iter().any(|v| matches!(v, EmailViolation::EncodedPayload(_))));
    }

    // ─── HTML escaping ──────────────────────────────

    #[test]
    fn escapes_html_special_chars() {
        assert_eq!(
            html_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2F;script&gt;"
        );
    }

    #[test]
    fn escapes_ampersand() {
        assert_eq!(html_escape("AT&T"), "AT&amp;T");
    }

    #[test]
    fn strips_null_bytes() {
        assert_eq!(html_escape("hel\0lo"), "hello");
    }

    // ─── Full outbound validation ───────────────────

    #[test]
    fn validates_good_outbound_email() {
        let result = validate_outbound_email(
            &["user@example.com"],
            "Welcome!",
            &[("message", "Thanks for joining")],
            &config(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_too_many_recipients() {
        let addrs: Vec<String> = (0..15).map(|i| format!("user{}@example.com", i)).collect();
        let refs: Vec<&str> = addrs.iter().map(|s| s.as_str()).collect();
        let result = validate_outbound_email(
            &refs,
            "Hi",
            &[],
            &config(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_injection_in_subject() {
        let result = validate_outbound_email(
            &["user@example.com"],
            "Subject\r\nBcc: evil@hacker.com",
            &[],
            &config(),
        );
        assert!(result.is_err());
    }

    // ─── Rate limiter ───────────────────────────────

    #[test]
    fn rate_limiter_allows_under_threshold() {
        let limiter = EmailRateLimiter::new(EmailGuardConfig {
            max_per_recipient: 3,
            rate_window_secs: 300,
            ..Default::default()
        });
        assert!(limiter.check_and_record("user@example.com"));
        assert!(limiter.check_and_record("user@example.com"));
        assert!(limiter.check_and_record("user@example.com"));
    }

    #[test]
    fn rate_limiter_blocks_over_threshold() {
        let limiter = EmailRateLimiter::new(EmailGuardConfig {
            max_per_recipient: 2,
            rate_window_secs: 300,
            ..Default::default()
        });
        assert!(limiter.check_and_record("user@example.com"));
        assert!(limiter.check_and_record("user@example.com"));
        assert!(!limiter.check_and_record("user@example.com")); // blocked
    }

    #[test]
    fn rate_limiter_tracks_per_recipient() {
        let limiter = EmailRateLimiter::new(EmailGuardConfig {
            max_per_recipient: 1,
            rate_window_secs: 300,
            ..Default::default()
        });
        assert!(limiter.check_and_record("a@example.com"));
        assert!(limiter.check_and_record("b@example.com"));
        assert!(!limiter.check_and_record("a@example.com")); // blocked
        assert!(!limiter.check_and_record("b@example.com")); // blocked
    }
}