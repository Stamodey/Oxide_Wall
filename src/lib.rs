// ============================================================================
// File: lib.rs
// Description: Adaptive zero-trust security engine with layered threat defense
// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
//! # NexusShield
//!
//! Adaptive zero-trust security engine for the Nexus platform.
//!
//! Protects services from SQL injection, SSRF, command injection, path traversal,
//! and automated attacks through a layered defense architecture:
//!
//! - **SQL Firewall** — AST-level SQL parsing (not regex) to detect injection
//! - **SSRF Guard** — IP/DNS validation blocking internal network probing
//! - **Rate Governor** — Adaptive rate limiting with behavioral escalation
//! - **Request Fingerprinting** — Bot detection via header/behavioral analysis
//! - **Data Quarantine** — Validates imported data for malicious payloads
//! - **Audit Chain** — Hash-chained tamper-evident security event log
//! - **Input Sanitizer** — Connection string and path traversal prevention
//! - **Threat Scoring** — Multi-signal adaptive threat assessment (0.0–1.0)

pub mod auth;
pub mod audit_chain;
pub mod compliance_report;
pub mod config;
pub mod credential_vault;
pub mod endpoint;
pub mod ferrum_integration;
pub mod fingerprint;
pub mod journal;
pub mod metrics;
pub mod nexuspulse_integration;
pub mod quarantine;
pub mod rate_governor;
pub mod sanitizer;
pub mod siem_export;
pub mod signature_updater;
pub mod sql_firewall;
pub mod sse_events;
pub mod ssrf_guard;
pub mod email_guard;
pub mod threat_score;
pub mod webhook;

use std::sync::Arc;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Extension;

pub use audit_chain::{AuditChain, AuditEvent, SecurityEventType};
pub use config::ShieldConfig;
pub use email_guard::{EmailGuardConfig, EmailRateLimiter};
pub use threat_score::{ThreatAction, ThreatAssessment};

/// Errors raised by the NexusShield security engine.
#[derive(Debug, thiserror::Error)]
pub enum ShieldError {
    #[error("SQL injection detected: {0}")]
    SqlInjectionDetected(String),

    #[error("Request blocked by SSRF guard: {0}")]
    SsrfBlocked(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded { retry_after: Option<u64> },

    #[error("Request blocked (threat score: {0:.3})")]
    ThreatScoreExceeded(f64),

    #[error("Malicious input detected: {0}")]
    MaliciousInput(String),

    #[error("Path traversal blocked: {0}")]
    PathTraversal(String),

    #[error("Invalid connection configuration: {0}")]
    InvalidConnectionString(String),

    #[error("Data quarantine failed: {0}")]
    QuarantineFailed(String),

    #[error("Email security violation: {0}")]
    EmailViolation(String),

    #[error("Email rate limit exceeded for {0}")]
    EmailBombing(String),

    #[error("Malware detected: {0}")]
    MalwareDetected(String),

    #[error("Endpoint protection error: {0}")]
    EndpointError(String),

    #[error("Quarantine vault error: {0}")]
    QuarantineVaultError(String),
}

impl IntoResponse for ShieldError {
    fn into_response(self) -> Response {
        // Deliberately vague error messages to avoid leaking security internals
        let (status, message) = match &self {
            Self::SqlInjectionDetected(_) => {
                (StatusCode::FORBIDDEN, "Request blocked by security policy")
            }
            Self::SsrfBlocked(_) => {
                (StatusCode::FORBIDDEN, "Request blocked by security policy")
            }
            Self::RateLimitExceeded { .. } => {
                (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded")
            }
            Self::ThreatScoreExceeded(_) => {
                (StatusCode::FORBIDDEN, "Request blocked by security policy")
            }
            Self::MaliciousInput(_) => (StatusCode::BAD_REQUEST, "Invalid input detected"),
            Self::PathTraversal(_) => {
                (StatusCode::FORBIDDEN, "Request blocked by security policy")
            }
            Self::InvalidConnectionString(_) => {
                (StatusCode::BAD_REQUEST, "Invalid connection configuration")
            }
            Self::QuarantineFailed(_) => {
                (StatusCode::BAD_REQUEST, "Data validation failed")
            }
            Self::EmailViolation(_) => {
                (StatusCode::BAD_REQUEST, "Email validation failed")
            }
            Self::EmailBombing(_) => {
                (StatusCode::TOO_MANY_REQUESTS, "Email rate limit exceeded")
            }
            Self::MalwareDetected(_) => {
                (StatusCode::FORBIDDEN, "Request blocked by security policy")
            }
            Self::EndpointError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Security engine error")
            }
            Self::QuarantineVaultError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Security engine error")
            }
        };
        (status, message).into_response()
    }
}

/// Core security engine that orchestrates all NexusShield components.
pub struct Shield {
    pub config: ShieldConfig,
    pub audit: Arc<AuditChain>,
    pub rate_governor: Arc<rate_governor::RateGovernor>,
    pub fingerprinter: Arc<fingerprint::Fingerprinter>,
    pub email_limiter: Arc<EmailRateLimiter>,
    pub endpoint: Option<Arc<endpoint::EndpointEngine>>,
}

impl Shield {
    pub fn new(config: ShieldConfig) -> Self {
        let audit = Arc::new(AuditChain::with_max_events(config.audit_max_events));
        let rate_governor = Arc::new(rate_governor::RateGovernor::new(&config));
        let fingerprinter = Arc::new(fingerprint::Fingerprinter::new());
        let email_limiter = Arc::new(EmailRateLimiter::new(config.email.clone()));
        Self {
            config,
            audit,
            rate_governor,
            fingerprinter,
            email_limiter,
            endpoint: None,
        }
    }

    // --- Convenience methods for direct validation from API handlers ---

    /// Validate a SQL query through the AST-based firewall.
    pub fn validate_sql(&self, sql: &str) -> Result<(), ShieldError> {
        let analysis = sql_firewall::analyze_query(sql, &self.config.sql);
        if analysis.allowed {
            Ok(())
        } else {
            let reason = analysis
                .violations
                .iter()
                .map(|v| format!("{:?}", v))
                .collect::<Vec<_>>()
                .join(", ");
            self.audit.record(
                SecurityEventType::SqlInjectionAttempt,
                "api",
                &reason,
                analysis.risk_score,
            );
            Err(ShieldError::SqlInjectionDetected(reason))
        }
    }

    /// Validate a URL through the SSRF guard.
    pub fn validate_url(&self, url: &str) -> Result<(), ShieldError> {
        ssrf_guard::validate_url(url, &self.config.ssrf).map_err(|reason| {
            self.audit.record(
                SecurityEventType::SsrfAttempt,
                "api",
                &reason,
                0.9,
            );
            ShieldError::SsrfBlocked(reason)
        })
    }

    /// Validate an IP address through the SSRF guard.
    pub fn validate_ip(&self, ip: &str) -> Result<(), ShieldError> {
        ssrf_guard::validate_ip_str(ip, &self.config.ssrf).map_err(|reason| {
            self.audit.record(
                SecurityEventType::SsrfAttempt,
                "api",
                &reason,
                0.9,
            );
            ShieldError::SsrfBlocked(reason)
        })
    }

    /// Validate and sanitize a database connection string.
    pub fn validate_connection_string(&self, conn_str: &str) -> Result<String, ShieldError> {
        sanitizer::validate_connection_string(conn_str).map_err(|reason| {
            self.audit.record(
                SecurityEventType::MaliciousPayload,
                "api",
                &reason,
                0.8,
            );
            ShieldError::InvalidConnectionString(reason)
        })
    }

    /// Validate a file path (SQLite database path).
    pub fn validate_file_path(&self, path: &str) -> Result<(), ShieldError> {
        sanitizer::validate_file_path(path).map_err(|reason| {
            self.audit.record(
                SecurityEventType::PathTraversalAttempt,
                "api",
                &reason,
                0.9,
            );
            ShieldError::PathTraversal(reason)
        })
    }

    /// Run imported CSV data through quarantine validation.
    pub fn quarantine_csv(&self, content: &str) -> Result<(), ShieldError> {
        let result = quarantine::validate_csv(content, &self.config.quarantine);
        if result.passed {
            Ok(())
        } else {
            let reason = result
                .violations
                .iter()
                .map(|v| format!("{:?}", v))
                .collect::<Vec<_>>()
                .join(", ");
            self.audit.record(
                SecurityEventType::DataQuarantined,
                "api",
                &reason,
                0.7,
            );
            Err(ShieldError::QuarantineFailed(reason))
        }
    }

    /// Validate a JSON response from an external source.
    pub fn quarantine_json(&self, json: &str) -> Result<(), ShieldError> {
        quarantine::validate_json_response(json, self.config.quarantine.max_size_bytes)
            .map_err(|reason| {
                self.audit.record(
                    SecurityEventType::DataQuarantined,
                    "api",
                    &reason,
                    0.6,
                );
                ShieldError::MaliciousInput(reason)
            })
    }

    // --- Email security methods ---

    /// Validate an email address for format, domain safety, and injection.
    pub fn validate_email_address(&self, addr: &str) -> Result<(), ShieldError> {
        let violations = email_guard::validate_email_address(addr, &self.config.email);
        if violations.is_empty() {
            Ok(())
        } else {
            let reason = violations.iter().map(|v| format!("{:?}", v)).collect::<Vec<_>>().join(", ");
            self.audit.record(
                SecurityEventType::MaliciousPayload,
                "email",
                &reason,
                0.7,
            );
            Err(ShieldError::EmailViolation(reason))
        }
    }

    /// Validate a header field (subject, name, ticket_id) for injection.
    pub fn validate_email_header(&self, field_name: &str, value: &str) -> Result<(), ShieldError> {
        let max_len = match field_name {
            "subject" => self.config.email.max_subject_len,
            _ => self.config.email.max_name_len,
        };
        let violations = email_guard::validate_header_field(field_name, value, max_len);
        if violations.is_empty() {
            Ok(())
        } else {
            let reason = violations.iter().map(|v| format!("{:?}", v)).collect::<Vec<_>>().join(", ");
            self.audit.record(
                SecurityEventType::MaliciousPayload,
                "email",
                &format!("header injection in {}: {}", field_name, reason),
                0.8,
            );
            Err(ShieldError::EmailViolation(reason))
        }
    }

    /// Validate content that will be interpolated into an HTML email template.
    pub fn validate_email_content(&self, field_name: &str, value: &str) -> Result<(), ShieldError> {
        let violations = email_guard::validate_template_content(
            field_name, value, self.config.email.max_body_len,
        );
        if violations.is_empty() {
            Ok(())
        } else {
            let reason = violations.iter().map(|v| format!("{:?}", v)).collect::<Vec<_>>().join(", ");
            self.audit.record(
                SecurityEventType::MaliciousPayload,
                "email",
                &format!("content injection in {}: {}", field_name, reason),
                0.8,
            );
            Err(ShieldError::EmailViolation(reason))
        }
    }

    /// Check per-recipient email rate limit (anti-bombing).
    pub fn check_email_rate(&self, recipient: &str) -> Result<(), ShieldError> {
        if self.email_limiter.check_and_record(recipient) {
            Ok(())
        } else {
            self.audit.record(
                SecurityEventType::RateLimitHit,
                "email",
                &format!("email bombing attempt to {}", recipient),
                0.9,
            );
            Err(ShieldError::EmailBombing(recipient.to_string()))
        }
    }

    /// Full outbound email validation: addresses, headers, content, and rate limits.
    pub fn validate_outbound_email(
        &self,
        to: &[&str],
        subject: &str,
        body_fields: &[(&str, &str)],
    ) -> Result<(), ShieldError> {
        // Validate all fields
        email_guard::validate_outbound_email(to, subject, body_fields, &self.config.email)
            .map_err(|reason| {
                self.audit.record(
                    SecurityEventType::MaliciousPayload,
                    "email",
                    &reason,
                    0.7,
                );
                ShieldError::EmailViolation(reason)
            })?;

        // Check per-recipient rate limits
        for addr in to {
            self.check_email_rate(addr)?;
        }

        Ok(())
    }

    /// HTML-escape user content for safe template interpolation.
    pub fn escape_email_content(value: &str) -> String {
        email_guard::html_escape(value)
    }
}

/// Axum middleware that performs per-request threat assessment.
///
/// Install via:
/// ```ignore
/// let shield = Arc::new(Shield::new(ShieldConfig::default()));
/// let app = Router::new()
///     .route(...)
///     .layer(Extension(shield.clone()))
///     .layer(axum::middleware::from_fn(shield_middleware));
/// ```
pub async fn shield_middleware(
    shield: Option<Extension<Arc<Shield>>>,
    request: Request,
    next: Next,
) -> Response {
    let shield = match shield {
        Some(Extension(s)) => s,
        None => return next.run(request).await,
    };

    let client_ip = extract_client_ip(&request);

    // 1. Rate limiting
    let rate_result = shield.rate_governor.check(&client_ip);
    if !rate_result.allowed {
        shield.audit.record(
            SecurityEventType::RateLimitHit,
            &client_ip,
            &format!(
                "escalation={:?}, violations={}",
                rate_result.escalation, rate_result.violations
            ),
            0.8,
        );
        let mut resp = (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
        if let Some(retry_after) = rate_result.retry_after {
            resp.headers_mut().insert(
                "Retry-After",
                retry_after.to_string().parse().unwrap(),
            );
        }
        return resp;
    }

    // 2. Request fingerprinting
    let fp = shield.fingerprinter.analyze(request.headers());

    // 3. Behavioral score
    let behavioral = shield.fingerprinter.behavioral_score(&client_ip);

    // 4. Check for recent violations
    let recent_violations = {
        let since = chrono::Utc::now() - chrono::Duration::minutes(5);
        shield
            .audit
            .count_since(&SecurityEventType::RequestBlocked, since)
            > 0
    };

    // 5. Compute threat score
    let assessment = threat_score::assess(
        &fp,
        &rate_result,
        behavioral,
        recent_violations,
        shield.config.warn_threshold,
        shield.config.block_threshold,
        &threat_score::WeightConfig::default(),
    );

    match assessment.action {
        ThreatAction::Block => {
            shield.audit.record(
                SecurityEventType::RequestBlocked,
                &client_ip,
                &format!(
                    "score={:.3}, fingerprint={:.3}, rate={:.3}, behavioral={:.3}",
                    assessment.score,
                    assessment.signals.fingerprint_anomaly,
                    assessment.signals.rate_pressure,
                    assessment.signals.behavioral_anomaly,
                ),
                assessment.score,
            );
            return (StatusCode::FORBIDDEN, "Request blocked by security policy").into_response();
        }
        ThreatAction::Warn => {
            tracing::warn!(
                ip = %client_ip,
                score = assessment.score,
                "NexusShield: elevated threat score"
            );
            shield.audit.record(
                SecurityEventType::RequestAllowed,
                &client_ip,
                &format!("WARN: score={:.3}", assessment.score),
                assessment.score,
            );
        }
        ThreatAction::Allow => {
            // Record silently for behavioral tracking
            shield.fingerprinter.record_request(&client_ip);
        }
    }

    // 6. Proceed to handler
    let response = next.run(request).await;

    // 7. Track errors for behavioral analysis
    if response.status().is_client_error() || response.status().is_server_error() {
        shield.fingerprinter.record_error(&client_ip);
    }

    response
}

/// Extract the client IP from the request, checking proxy headers first.
fn extract_client_ip(req: &Request) -> String {
    // X-Forwarded-For (first IP in chain)
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(value) = xff.to_str() {
            if let Some(first_ip) = value.split(',').next() {
                let ip = first_ip.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }

    // X-Real-IP
    if let Some(xri) = req.headers().get("x-real-ip") {
        if let Ok(value) = xri.to_str() {
            let ip = value.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }

    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, StatusCode};

    // ── ShieldError display messages ───────────────────────

    #[test]
    fn shield_error_sql_injection_display() {
        let err = ShieldError::SqlInjectionDetected("UNION attack".to_string());
        assert_eq!(err.to_string(), "SQL injection detected: UNION attack");
    }

    #[test]
    fn shield_error_ssrf_display() {
        let err = ShieldError::SsrfBlocked("private IP".to_string());
        assert_eq!(err.to_string(), "Request blocked by SSRF guard: private IP");
    }

    #[test]
    fn shield_error_rate_limit_display() {
        let err = ShieldError::RateLimitExceeded { retry_after: Some(60) };
        assert_eq!(err.to_string(), "Rate limit exceeded");
    }

    #[test]
    fn shield_error_threat_score_display() {
        let err = ShieldError::ThreatScoreExceeded(0.85);
        assert_eq!(err.to_string(), "Request blocked (threat score: 0.850)");
    }

    #[test]
    fn shield_error_malicious_input_display() {
        let err = ShieldError::MaliciousInput("script tag".to_string());
        assert_eq!(err.to_string(), "Malicious input detected: script tag");
    }

    #[test]
    fn shield_error_path_traversal_display() {
        let err = ShieldError::PathTraversal("../../etc/passwd".to_string());
        assert_eq!(err.to_string(), "Path traversal blocked: ../../etc/passwd");
    }

    #[test]
    fn shield_error_invalid_connection_display() {
        let err = ShieldError::InvalidConnectionString("bad string".to_string());
        assert_eq!(err.to_string(), "Invalid connection configuration: bad string");
    }

    #[test]
    fn shield_error_quarantine_display() {
        let err = ShieldError::QuarantineFailed("oversized".to_string());
        assert_eq!(err.to_string(), "Data quarantine failed: oversized");
    }

    #[test]
    fn shield_error_email_violation_display() {
        let err = ShieldError::EmailViolation("header injection".to_string());
        assert_eq!(err.to_string(), "Email security violation: header injection");
    }

    #[test]
    fn shield_error_email_bombing_display() {
        let err = ShieldError::EmailBombing("test@example.com".to_string());
        assert_eq!(err.to_string(), "Email rate limit exceeded for test@example.com");
    }

    // ── ShieldError -> HTTP status codes ───────────────────

    #[test]
    fn shield_error_sql_injection_returns_forbidden() {
        let err = ShieldError::SqlInjectionDetected("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn shield_error_ssrf_returns_forbidden() {
        let err = ShieldError::SsrfBlocked("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn shield_error_rate_limit_returns_429() {
        let err = ShieldError::RateLimitExceeded { retry_after: None };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn shield_error_threat_score_returns_forbidden() {
        let err = ShieldError::ThreatScoreExceeded(0.9);
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn shield_error_malicious_input_returns_bad_request() {
        let err = ShieldError::MaliciousInput("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn shield_error_path_traversal_returns_forbidden() {
        let err = ShieldError::PathTraversal("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn shield_error_invalid_conn_returns_bad_request() {
        let err = ShieldError::InvalidConnectionString("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn shield_error_quarantine_returns_bad_request() {
        let err = ShieldError::QuarantineFailed("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn shield_error_email_violation_returns_bad_request() {
        let err = ShieldError::EmailViolation("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn shield_error_email_bombing_returns_429() {
        let err = ShieldError::EmailBombing("test@test.com".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // ── Shield construction ────────────────────────────────

    #[test]
    fn shield_new_with_default_config() {
        let shield = Shield::new(ShieldConfig::default());
        assert!(shield.config.block_threshold > 0.0);
        assert!(shield.config.warn_threshold > 0.0);
    }

    #[test]
    fn shield_html_escape() {
        let escaped = Shield::escape_email_content("<script>alert('xss')</script>");
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("&lt;script&gt;"));
    }

    // ── extract_client_ip ──────────────────────────────────

    #[test]
    fn extract_ip_from_x_forwarded_for() {
        let mut req = Request::builder().body(axum::body::Body::empty()).unwrap();
        req.headers_mut().insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4, 5.6.7.8"));
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "1.2.3.4");
    }

    #[test]
    fn extract_ip_from_x_real_ip() {
        let mut req = Request::builder().body(axum::body::Body::empty()).unwrap();
        req.headers_mut().insert("x-real-ip", HeaderValue::from_static("10.0.0.1"));
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "10.0.0.1");
    }

    #[test]
    fn extract_ip_xff_takes_precedence_over_xri() {
        let mut req = Request::builder().body(axum::body::Body::empty()).unwrap();
        req.headers_mut().insert("x-forwarded-for", HeaderValue::from_static("1.1.1.1"));
        req.headers_mut().insert("x-real-ip", HeaderValue::from_static("2.2.2.2"));
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "1.1.1.1");
    }

    #[test]
    fn extract_ip_unknown_when_no_headers() {
        let req = Request::builder().body(axum::body::Body::empty()).unwrap();
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "unknown");
    }

    #[test]
    fn extract_ip_xff_trims_whitespace() {
        let mut req = Request::builder().body(axum::body::Body::empty()).unwrap();
        req.headers_mut().insert("x-forwarded-for", HeaderValue::from_static("  3.3.3.3  , 4.4.4.4"));
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "3.3.3.3");
    }

    #[test]
    fn extract_ip_xri_trims_whitespace() {
        let mut req = Request::builder().body(axum::body::Body::empty()).unwrap();
        req.headers_mut().insert("x-real-ip", HeaderValue::from_static("  5.5.5.5  "));
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "5.5.5.5");
    }
}