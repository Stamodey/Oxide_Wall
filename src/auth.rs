// ============================================================================
// File: auth.rs
// Description: API authentication middleware — Bearer token verification
// ============================================================================
//! Auth — protects sensitive API endpoints with Bearer token authentication.
//!
//! When `api_token` is configured, the following endpoints require
//! `Authorization: Bearer <token>`:
//! - /audit, /stats, /status, /report, /events
//! - /endpoint/* (all endpoint protection APIs)
//!
//! Endpoints that remain public:
//! - /health (load balancer probes)
//! - /dashboard, /logo.png (UI assets)

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

/// Axum middleware that enforces Bearer token authentication.
/// If `expected_token` is None, all requests pass through (auth disabled).
pub async fn auth_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get the expected token from the extension
    let expected = request
        .extensions()
        .get::<AuthToken>()
        .cloned();

    let token = match expected {
        Some(AuthToken(Some(t))) => t,
        _ => return Ok(next.run(request).await), // No token configured = auth disabled
    };

    let path = request.uri().path();

    // Public endpoints — no auth required
    if path == "/health" || path == "/dashboard" || path == "/logo.png" {
        return Ok(next.run(request).await);
    }

    // Check Authorization header
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Some(bearer) = auth_header.strip_prefix("Bearer ") {
        if bearer.trim() == token {
            return Ok(next.run(request).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Wrapper type for the auth token stored in request extensions.
#[derive(Clone)]
pub struct AuthToken(pub Option<String>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_token_clone() {
        let t = AuthToken(Some("test".to_string()));
        let t2 = t.clone();
        assert_eq!(t2.0, Some("test".to_string()));
    }

    #[test]
    fn auth_token_none() {
        let t = AuthToken(None);
        assert!(t.0.is_none());
    }
}