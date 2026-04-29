use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    Extension,
    extract::Request,
    middleware,
    response::{IntoResponse, Response, Html},
    http::StatusCode,
    routing::get,
};
use clap::Parser;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use http_body_util::BodyExt;
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, fmt};

use oxide_wall::{
    Shield, ShieldConfig, shield_middleware,
    audit_chain::SecurityEventType,
    endpoint::{EndpointConfig, EndpointEngine},
};

#[derive(Parser, Debug)]
#[command(name = "nexus-shield", about = "NexusShield Local Security Gateway")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Upstream target to proxy to (e.g., http://localhost:3000)
    #[arg(short, long)]
    upstream: Option<String>,

    /// Config file path
    #[arg(short, long, default_value = "/etc/nexus-shield/config.toml")]
    config: String,

    /// Block threshold (0.0-1.0)
    #[arg(long, default_value = "0.7")]
    block_threshold: f64,

    /// Warn threshold (0.0-1.0)
    #[arg(long, default_value = "0.4")]
    warn_threshold: f64,

    /// Requests per second per IP
    #[arg(long, default_value = "50")]
    rps: f64,

    /// Enable standalone mode (no upstream, just shield + status)
    #[arg(long, default_value = "false")]
    standalone: bool,

    /// Enable real-time endpoint protection (file/process/network monitoring)
    #[arg(long, default_value = "false")]
    endpoint: bool,

    /// Run a one-time full scan of a directory
    #[arg(long)]
    scan: Option<String>,

    /// Scan a single file
    #[arg(long)]
    scan_file: Option<String>,

    /// Endpoint data directory
    #[arg(long, default_value = "~/.nexus-shield")]
    endpoint_data_dir: String,
}

#[tokio::main]
async fn main() {
    // Initialize logging
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,nexus_shield=debug")),
        )
        .with_target(true)
        .with_thread_ids(false)
        .init();

    let args = Args::parse();

    tracing::info!(
        r#"
    ╔══════════════════════════════════════════════╗
    ║            NexusShield v0.4.2                ║
    ║     Adaptive Zero-Trust Security Gateway     ║
    ║      + Real-Time Endpoint Protection         ║
    ║          AutomataNexus Engineering            ║
    ╚══════════════════════════════════════════════╝
    "#
    );

    // Load config from file if it exists, otherwise use defaults
    let mut config = {
        let config_path = std::path::Path::new(&args.config);
        if config_path.exists() {
            match oxide_wall::config::load_config(config_path) {
                Ok(c) => {
                    tracing::info!(path = %args.config, "Configuration loaded from file");
                    c
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to load config, using defaults");
                    ShieldConfig::default()
                }
            }
        } else {
            ShieldConfig::default()
        }
    };

    // CLI args override config file values
    if args.block_threshold != 0.7 { config.block_threshold = args.block_threshold; }
    if args.warn_threshold != 0.4 { config.warn_threshold = args.warn_threshold; }
    if args.rps != 50.0 { config.rate.requests_per_second = args.rps; }

    let mut shield = Shield::new(config);

    // Initialize endpoint protection if requested
    let endpoint_engine: Option<Arc<EndpointEngine>> = if args.endpoint
        || args.scan.is_some()
        || args.scan_file.is_some()
    {
        let ep_config = EndpointConfig::default();
        let engine = Arc::new(EndpointEngine::new(ep_config));
        shield.endpoint = Some(engine.clone());
        Some(engine)
    } else {
        None
    };

    // Handle one-shot scan commands
    if let Some(ref file_path) = args.scan_file {
        let engine = endpoint_engine.as_ref().expect("Endpoint engine required");
        let path = std::path::Path::new(file_path);
        tracing::info!("Scanning file: {}", path.display());
        let results: Vec<oxide_wall::endpoint::ScanResult> = engine.scan_file(path).await;
        if results.is_empty() {
            println!("CLEAN: No threats detected in {}", path.display());
        } else {
            println!("THREATS FOUND in {}:", path.display());
            for r in &results {
                println!(
                    "  [{:?}] {} (confidence: {:.0}%) — {}",
                    r.severity,
                    r.scanner,
                    r.confidence * 100.0,
                    r.description
                );
            }
        }
        std::process::exit(if results.is_empty() { 0 } else { 1 });
    }

    if let Some(ref dir_path) = args.scan {
        let engine = endpoint_engine.as_ref().expect("Endpoint engine required");
        let path = std::path::Path::new(dir_path);
        tracing::info!("Scanning directory: {}", path.display());
        let results: Vec<oxide_wall::endpoint::ScanResult> = engine.scan_dir(path).await;
        if results.is_empty() {
            println!("CLEAN: No threats detected in {}", path.display());
        } else {
            println!("THREATS FOUND ({} detections):", results.len());
            for r in &results {
                println!(
                    "  [{:?}] {} — {} ({})",
                    r.severity, r.target, r.description, r.scanner
                );
            }
        }
        std::process::exit(if results.is_empty() { 0 } else { 1 });
    }

    let shield = Arc::new(shield);

    // Clone for background tasks
    let shield_bg = shield.clone();

    // Background: prune stale data every 60 seconds
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            shield_bg.rate_governor.prune_stale(Duration::from_secs(600));
            shield_bg.fingerprinter.prune_stale(600);
            shield_bg.email_limiter.prune();
            tracing::debug!("Pruned stale security state");
        }
    });

    // Background: journal + webhook event forwarding
    {
        let audit_fwd = shield.audit.clone();
        let journal_config = oxide_wall::journal::JournalConfig::default();
        let webhook_configs = shield.config.webhook_urls.clone();
        let ferrum_config = shield.config.ferrum_mail.clone();
        let pulse_config = shield.config.nexus_pulse.clone();

        tokio::spawn(async move {
            let mut last_count = audit_fwd.len();
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                let current_count = audit_fwd.len();
                if current_count > last_count {
                    let new_events = audit_fwd.recent(current_count - last_count);
                    for event in new_events.iter().rev() {
                        oxide_wall::journal::log_to_journal(event, &journal_config);
                        if !webhook_configs.is_empty() {
                            oxide_wall::webhook::fire_webhooks(event, &webhook_configs).await;
                        }
                        oxide_wall::ferrum_integration::maybe_send_alert(event, &ferrum_config).await;
                        oxide_wall::nexuspulse_integration::maybe_send_sms(event, &pulse_config).await;
                    }
                    last_count = current_count;
                }
            }
        });
    }

    // Start signature auto-updater if configured
    if let Some(ref sig_config) = shield.config.signature_update {
        let sig_path: std::path::PathBuf = std::path::PathBuf::from(
            std::env::var("HOME").unwrap_or("/tmp".to_string())
        ).join(".nexus-shield/signatures.ndjson");
        let (_sig_handle, _sig_shutdown) = oxide_wall::signature_updater::start_updater(
            sig_config.clone(),
            Arc::new(sig_path),
        ).expect("Failed to start signature updater");
        tracing::info!("Signature auto-updater enabled");
    }

    // Start endpoint protection monitors if enabled
    if let Some(ref engine) = endpoint_engine {
        if args.endpoint {
            let handles: Vec<tokio::task::JoinHandle<()>> = engine.start(shield.audit.clone()).await;
            tracing::info!(
                monitors = handles.len(),
                "Endpoint protection started"
            );
        }
    }

    // Clone for audit export
    let shield_status = shield.clone();
    let shield_audit = shield.clone();
    let shield_stats = shield.clone();
    let endpoint_for_routes = endpoint_engine.clone();
    let shield_events = shield.clone();
    let shield_report = shield.clone();
    let shield_metrics = shield.clone();
    let start_time = std::time::Instant::now();

    // Build endpoint routes if enabled
    let endpoint_routes = if let Some(engine) = endpoint_for_routes {
        let ep1 = engine.clone();
        let ep2 = engine.clone();
        let ep3 = engine.clone();
        let ep4 = engine.clone();
        Some(
            Router::new()
                .route("/endpoint/status", get(move || {
                    let e = ep1.clone();
                    async move { endpoint_status_handler(e).await }
                }))
                .route("/endpoint/detections", get(move || {
                    let e = ep2.clone();
                    async move { endpoint_detections_handler(e).await }
                }))
                .route("/endpoint/quarantine", get(move || {
                    let e = ep3.clone();
                    async move { endpoint_quarantine_handler(e).await }
                }))
                .route("/endpoint/scan", axum::routing::post(move |body: String| {
                    let e = ep4.clone();
                    async move { endpoint_scan_handler(e, body).await }
                }))
        )
    } else {
        None
    };

    let app = if args.standalone || args.upstream.is_none() {
        // Standalone mode: shield + status endpoints
        tracing::info!("Running in standalone mode (no upstream proxy)");
        let mut router = Router::new()
            .route("/health", get(|| async { "NexusShield OK" }))
            .route("/dashboard", get(dashboard_handler))
            .route("/logo.png", get(logo_handler))
            .route("/status", get(move || async move {
                status_handler(shield_status.clone()).await
            }))
            .route("/audit", get(move || async move {
                audit_handler(shield_audit.clone()).await
            }))
            .route("/stats", get(move || async move {
                stats_handler(shield_stats.clone()).await
            }))
            .route("/events", get(move || {
                let audit = shield_events.audit.clone();
                async move {
                    match oxide_wall::sse_events::audit_event_stream(audit) {
                        Some(sse) => sse.into_response(),
                        None => (StatusCode::SERVICE_UNAVAILABLE, "SSE connection limit reached").into_response(),
                    }
                }
            }))
            .route("/report", get(move || {
                let s = shield_report.clone();
                async move {
                    let config = oxide_wall::compliance_report::ReportConfig::default();
                    let modules = vec![
                        "sql_firewall".into(), "ssrf_guard".into(), "rate_governor".into(),
                        "fingerprint".into(), "quarantine".into(), "email_guard".into(),
                        "credential_vault".into(), "audit_chain".into(), "sanitizer".into(),
                        "threat_score".into(), "siem_export".into(), "journal".into(),
                        "sse_events".into(), "compliance_report".into(),
                        "signatures".into(), "heuristics".into(), "yara_engine".into(),
                        "watcher".into(), "process_monitor".into(), "network_monitor".into(),
                        "dns_filter".into(), "usb_monitor".into(), "fim".into(),
                        "container_scanner".into(), "supply_chain".into(),
                    ];
                    let shield_cfg = serde_json::json!({
                        "block_threshold": s.config.block_threshold,
                        "warn_threshold": s.config.warn_threshold,
                        "rate_rps": s.config.rate.requests_per_second,
                    });
                    let html = oxide_wall::compliance_report::generate_html_report(
                        &s.audit, &config, &modules, &shield_cfg,
                    );
                    Html(html)
                }
            }));

        router = router.route("/metrics", get(move || {
                let s = shield_metrics.clone();
                let uptime = start_time.elapsed().as_secs();
                async move {
                    let body = oxide_wall::metrics::render_metrics(&s.audit, uptime);
                    (StatusCode::OK, [("content-type", "text/plain; version=0.0.4")], body)
                }
            }));

        if let Some(ep_routes) = endpoint_routes {
            router = router.merge(ep_routes);
        }

        router
            .fallback(|| async {
                (StatusCode::OK, "NexusShield: request inspected and allowed")
            })
            .layer(middleware::from_fn(oxide_wall::auth::auth_middleware))
            .layer(Extension(oxide_wall::auth::AuthToken(shield.config.api_token.clone())))
            .layer(middleware::from_fn(shield_middleware))
            .layer(Extension(shield.clone()))
    } else {
        // Proxy mode: shield + reverse proxy to upstream
        let upstream = args.upstream.clone().unwrap();
        tracing::info!(upstream = %upstream, "Running in reverse proxy mode");

        let client = Client::builder(TokioExecutor::new()).build_http();
        let upstream = Arc::new(upstream);

        let proxy_upstream = upstream.clone();
        let proxy_client = Arc::new(client);

        Router::new()
            .route("/health", get(|| async { "NexusShield OK" }))
            .route("/dashboard", get(dashboard_handler))
            .route("/logo.png", get(logo_handler))
            .route("/status", get(move || async move {
                status_handler(shield_status.clone()).await
            }))
            .route("/audit", get(move || async move {
                audit_handler(shield_audit.clone()).await
            }))
            .route("/stats", get(move || async move {
                stats_handler(shield_stats.clone()).await
            }))
            .fallback(move |req: Request| {
                let upstream = proxy_upstream.clone();
                let client = proxy_client.clone();
                async move {
                    proxy_handler(req, &upstream, &client).await
                }
            })
            .layer(middleware::from_fn(oxide_wall::auth::auth_middleware))
            .layer(Extension(oxide_wall::auth::AuthToken(shield.config.api_token.clone())))
            .layer(middleware::from_fn(shield_middleware))
            .layer(Extension(shield.clone()))
    };

    let addr = format!("0.0.0.0:{}", args.port);
    tracing::info!(listen = %addr, "NexusShield gateway starting");

    // Check for TLS configuration
    let tls_cert = shield.config.tls_cert.clone();
    let tls_key = shield.config.tls_key.clone();

    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        // TLS mode
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .expect("Failed to load TLS certificate/key");

        tracing::info!(
            cert = %cert_path,
            key = %key_path,
            "NexusShield active — HTTPS on port {}",
            args.port
        );

        axum_server::bind_rustls(addr.parse().expect("Invalid address"), tls_config)
            .serve(app.into_make_service())
            .await
            .expect("TLS server failed");
    } else {
        // Plain HTTP mode
        let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
        tracing::info!(
            "NexusShield active — HTTP on port {}",
            args.port
        );

        axum::serve(listener, app)
            .await
            .expect("Server failed");
    }
}

async fn proxy_handler(
    mut req: Request,
    upstream: &str,
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, axum::body::Body>,
) -> Response {
    let path = req.uri().path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let upstream_uri = format!("{}{}", upstream, path);

    match upstream_uri.parse::<hyper::Uri>() {
        Ok(uri) => {
            *req.uri_mut() = uri;
            match client.request(req).await {
                Ok(resp) => {
                    let (parts, body) = resp.into_parts();
                    let bytes = body.collect().await
                        .map(|b| b.to_bytes())
                        .unwrap_or_default();
                    Response::from_parts(parts, axum::body::Body::from(bytes))
                }
                Err(e) => {
                    tracing::error!(error = %e, "Upstream request failed");
                    (StatusCode::BAD_GATEWAY, "Upstream unavailable").into_response()
                }
            }
        }
        Err(_) => {
            (StatusCode::BAD_REQUEST, "Invalid upstream URI").into_response()
        }
    }
}

async fn dashboard_handler() -> Html<&'static str> {
    Html(include_str!("../../widget/index.html"))
}

async fn logo_handler() -> impl IntoResponse {
    let bytes: &'static [u8] = b"PNG";  // Placeholder - asset file not present
    (
        StatusCode::OK,
        [("content-type", "image/png"), ("cache-control", "public, max-age=86400")],
        bytes,
    )
}

async fn status_handler(shield: Arc<Shield>) -> impl IntoResponse {
    let chain_verification = shield.audit.verify_chain();
    let audit_count = shield.audit.len();

    let status = serde_json::json!({
        "service": "NexusShield",
        "version": "0.4.2",
        "status": "active",
        "config": {
            "block_threshold": shield.config.block_threshold,
            "warn_threshold": shield.config.warn_threshold,
            "rate_rps": shield.config.rate.requests_per_second,
            "rate_burst": shield.config.rate.burst_capacity,
        },
        "audit_chain": {
            "total_events": audit_count,
            "chain_valid": chain_verification.valid,
        },
        "modules": {
            "gateway": [
                "sql_firewall",
                "ssrf_guard",
                "rate_governor",
                "fingerprint",
                "quarantine",
                "email_guard",
                "credential_vault",
                "audit_chain",
                "sanitizer",
                "threat_score",
                "siem_export",
                "journal",
                "sse_events",
                "compliance_report",
            ],
            "endpoint": [
                "signatures",
                "heuristics",
                "yara_engine",
                "watcher",
                "process_monitor",
                "network_monitor",
                "memory_scanner",
                "rootkit_detector",
                "dns_filter",
                "usb_monitor",
                "fim",
                "container_scanner",
                "supply_chain",
                "allowlist",
                "threat_intel",
                "file_quarantine",
            ]
        }
    });

    (StatusCode::OK, axum::Json(status))
}

async fn audit_handler(shield: Arc<Shield>) -> impl IntoResponse {
    let recent = shield.audit.recent(50);
    let events: Vec<serde_json::Value> = recent.iter().map(|e| {
        serde_json::json!({
            "id": e.id,
            "timestamp": e.timestamp.to_rfc3339(),
            "event_type": format!("{:?}", e.event_type),
            "source_ip": e.source_ip,
            "details": e.details,
            "threat_score": e.threat_score,
        })
    }).collect();

    (StatusCode::OK, axum::Json(serde_json::json!({
        "recent_events": events,
        "total": shield.audit.len(),
        "chain_valid": shield.audit.verify_chain().valid,
    })))
}

async fn stats_handler(shield: Arc<Shield>) -> impl IntoResponse {
    let now = chrono::Utc::now();
    let last_hour = now - chrono::Duration::hours(1);
    let last_5min = now - chrono::Duration::minutes(5);

    let stats = serde_json::json!({
        "last_5min": {
            "blocked": shield.audit.count_since(&SecurityEventType::RequestBlocked, last_5min),
            "rate_limited": shield.audit.count_since(&SecurityEventType::RateLimitHit, last_5min),
            "sql_injection": shield.audit.count_since(&SecurityEventType::SqlInjectionAttempt, last_5min),
            "ssrf": shield.audit.count_since(&SecurityEventType::SsrfAttempt, last_5min),
        },
        "last_hour": {
            "blocked": shield.audit.count_since(&SecurityEventType::RequestBlocked, last_hour),
            "rate_limited": shield.audit.count_since(&SecurityEventType::RateLimitHit, last_hour),
            "sql_injection": shield.audit.count_since(&SecurityEventType::SqlInjectionAttempt, last_hour),
            "ssrf": shield.audit.count_since(&SecurityEventType::SsrfAttempt, last_hour),
        },
        "total_audit_events": shield.audit.len(),
    });

    (StatusCode::OK, axum::Json(stats))
}

// =============================================================================
// Endpoint Protection API Handlers
// =============================================================================

async fn endpoint_status_handler(engine: Arc<EndpointEngine>) -> impl IntoResponse {
    let stats = engine.stats();
    (StatusCode::OK, axum::Json(serde_json::json!({
        "endpoint_protection": "active",
        "total_files_scanned": stats.total_files_scanned,
        "total_threats_detected": stats.total_threats_detected,
        "active_monitors": stats.active_monitors,
        "scanners_active": stats.scanners_active,
        "quarantined_files": stats.quarantined_files,
        "last_scan_time": stats.last_scan_time.map(|t| t.to_rfc3339()),
    })))
}

async fn endpoint_detections_handler(engine: Arc<EndpointEngine>) -> impl IntoResponse {
    let detections = engine.recent_detections(100);
    let events: Vec<serde_json::Value> = detections.iter().map(|d| {
        serde_json::json!({
            "id": d.id,
            "timestamp": d.timestamp.to_rfc3339(),
            "scanner": d.scanner,
            "target": d.target,
            "severity": format!("{}", d.severity),
            "description": d.description,
            "confidence": d.confidence,
            "action": format!("{}", d.action),
            "artifact_hash": d.artifact_hash,
        })
    }).collect();

    (StatusCode::OK, axum::Json(serde_json::json!({
        "detections": events,
        "total": detections.len(),
    })))
}

async fn endpoint_quarantine_handler(engine: Arc<EndpointEngine>) -> impl IntoResponse {
    let entries = engine.quarantine.list_entries();
    let items: Vec<serde_json::Value> = entries.iter().map(|e| {
        serde_json::json!({
            "id": e.id,
            "original_path": e.original_path.to_string_lossy(),
            "sha256": e.sha256,
            "detection_reason": e.detection_reason,
            "scanner": e.scanner,
            "severity": format!("{}", e.severity),
            "quarantined_at": e.quarantined_at.to_rfc3339(),
            "file_size": e.file_size,
        })
    }).collect();

    (StatusCode::OK, axum::Json(serde_json::json!({
        "quarantined_files": items,
        "total": entries.len(),
        "vault_size_bytes": engine.quarantine.vault_size(),
    })))
}

async fn endpoint_scan_handler(engine: Arc<EndpointEngine>, body: String) -> impl IntoResponse {
    let path = std::path::Path::new(body.trim());
    if !path.exists() {
        return (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({
            "error": "Path does not exist",
            "path": body.trim(),
        })));
    }

    let results = if path.is_dir() {
        engine.scan_dir(path).await
    } else {
        engine.scan_file(path).await
    };

    let detections: Vec<serde_json::Value> = results.iter().map(|r| {
        serde_json::json!({
            "scanner": r.scanner,
            "target": r.target,
            "severity": format!("{}", r.severity),
            "description": r.description,
            "confidence": r.confidence,
            "artifact_hash": r.artifact_hash,
        })
    }).collect();

    (StatusCode::OK, axum::Json(serde_json::json!({
        "path": body.trim(),
        "clean": results.is_empty(),
        "threats_found": results.len(),
        "detections": detections,
    })))
}