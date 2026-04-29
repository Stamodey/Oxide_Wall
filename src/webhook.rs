// ============================================================================
// File: webhook.rs
// Description: Webhook alerts — fire HTTP POST to Telegram, Discord, or
//              generic endpoints on security detections
// ============================================================================

use crate::audit_chain::AuditEvent;
use crate::config::WebhookConfig;
use hyper::Uri;
use std::time::Duration;

const WEBHOOK_TIMEOUT_SECS: u64 = 10;
const MAX_DETAILS_LEN: usize = 2000;

/// Список заблокированных префиксов хостов для защиты от SSRF.
/// Блокируем localhost, loopback, link-local (AWS metadata), RFC1918,
/// IPv6 loopback и link-local.
const BLOCKED_HOST_PREFIXES: &[&str] = &[
    "localhost",
    "127.",
    "0.0.0.0",
    "169.254.", // link-local / AWS EC2 metadata endpoint
    "10.",      // RFC1918
    "172.16.",  // RFC1918
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.", // RFC1918
    "::1",      // IPv6 loopback
    "fd",       // IPv6 ULA (private)
    "fe80",     // IPv6 link-local
];

// ─────────────────────────────────────────────
//  Публичный entry-point
// ─────────────────────────────────────────────

/// Отправить алерт во все вебхуки, порог серьёзности которых пройден.
pub async fn fire_webhooks(event: &AuditEvent, webhooks: &[WebhookConfig]) {
    for webhook in webhooks {
        if !meets_severity(event.threat_score, &webhook.min_severity) {
            continue;
        }

        let payload = match webhook.webhook_type.as_str() {
            "discord" => format_discord(event),
            "telegram" => {
                let chat_id = match &webhook.telegram_chat_id {
                    Some(id) => id,
                    None => {
                        tracing::warn!(
                            webhook_url = %webhook.url,
                            "Telegram webhook missing chat_id, skipping"
                        );
                        continue;
                    }
                };
                format_telegram(event, chat_id)
            }
            _ => format_generic(event),
        };

        if let Err(e) = send_webhook(&webhook.url, &payload, &webhook.headers).await {
            tracing::error!(
                error = %e,
                webhook_url = %webhook.url,
                "Failed to send webhook"
            );
        }
    }
}

// ─────────────────────────────────────────────
//  Пороги серьёзности
// ─────────────────────────────────────────────

fn meets_severity(score: f64, min: &str) -> bool {
    let threshold = match min {
        "critical" => 0.9,
        "high" => 0.7,
        "medium" => 0.5,
        "low" => 0.3,
        _ => 0.0, // "info" или неизвестное значение — пропускаем всё
    };
    score >= threshold
}

fn score_label(score: f64) -> &'static str {
    match score {
        s if s >= 0.9 => "CRITICAL",
        s if s >= 0.7 => "HIGH",
        s if s >= 0.5 => "MEDIUM",
        s if s >= 0.3 => "LOW",
        _ => "INFO",
    }
}

// ─────────────────────────────────────────────
//  Форматирование payload
// ─────────────────────────────────────────────

fn format_discord(event: &AuditEvent) -> String {
    let severity = score_label(event.threat_score);
    let color: u32 = match severity {
        "CRITICAL" => 0xFF0000,
        "HIGH" => 0xFF6600,
        "MEDIUM" => 0xFFCC00,
        _ => 0x00CC00,
    };
    serde_json::json!({
        "embeds": [{
            "title": format!("OxideWall — {}", severity),
            "color": color,
            "fields": [
                {"name": "Event Type",  "value": format!("{:?}", event.event_type), "inline": true},
                {"name": "Source IP",   "value": &event.source_ip,                 "inline": true},
                {"name": "Threat Score","value": format!("{:.3}", event.threat_score), "inline": true},
                {"name": "Details",     "value": truncate_details(&event.details), "inline": false},
            ],
            "timestamp": event.timestamp.to_rfc3339(),
        }]
    })
    .to_string()
}

/// Формирует JSON-тело для Telegram Bot API (`sendMessage`).
///
/// Использует MarkdownV2 — все спецсимволы в пользовательских данных
/// экранируются через [`escape_telegram_md`], чтобы избежать инъекций
/// форматирования или отказа API.
fn format_telegram(event: &AuditEvent, chat_id: &str) -> String {
    let severity = score_label(event.threat_score);
    let emoji = match severity {
        "CRITICAL" => "🚨",
        "HIGH" => "⚠️",
        "MEDIUM" => "🔶",
        _ => "ℹ️",
    };

    // Экранируем все поля, которые могут содержать произвольный текст
    let safe_severity = escape_telegram_md(severity);
    let safe_event_type = escape_telegram_md(&format!("{:?}", event.event_type));
    let safe_source_ip = escape_telegram_md(&event.source_ip);
    let safe_score = escape_telegram_md(&format!("{:.3}", event.threat_score));
    let safe_details = escape_telegram_md(&truncate_details(&event.details));

    let text = format!(
        "{emoji} *OxideWall Alert — {safe_severity}*\n\
         *Type:* `{safe_event_type}`\n\
         *Source:* `{safe_source_ip}`\n\
         *Score:* `{safe_score}`\n\
         *Details:* {safe_details}",
    );

    serde_json::json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "MarkdownV2",
        "disable_web_page_preview": true
    })
    .to_string()
}

fn format_generic(event: &AuditEvent) -> String {
    serde_json::json!({
        "source":       "OxideWall",
        "severity":     score_label(event.threat_score),
        "event_type":   format!("{:?}", event.event_type),
        "source_ip":    event.source_ip,
        "threat_score": event.threat_score,
        "details":      truncate_details(&event.details),
        "timestamp":    event.timestamp.to_rfc3339(),
        "event_id":     event.id,
    })
    .to_string()
}

// ─────────────────────────────────────────────
//  Вспомогательные функции
// ─────────────────────────────────────────────

/// Экранирует все зарезервированные символы Telegram MarkdownV2.
/// Без этого произвольный текст из события может сломать разметку
/// или вызвать ошибку 400 от Telegram API.
fn escape_telegram_md(text: &str) -> String {
    // Полный список спецсимволов согласно документации Telegram Bot API
    const SPECIAL: &[char] = &[
        '_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|',
        '{', '}', '.', '!', '\\',
    ];
    let mut out = String::with_capacity(text.len() + 16);
    for ch in text.chars() {
        if SPECIAL.contains(&ch) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Обрезает строку до MAX_DETAILS_LEN байт с учётом границ UTF-8 символов,
/// чтобы не получить невалидный срез посередине многобайтового символа.
fn truncate_details(details: &str) -> String {
    if details.len() <= MAX_DETAILS_LEN {
        return details.to_string();
    }
    // floor_char_boundary гарантирует срез по границе символа (Rust 1.79+)
    let boundary = details.floor_char_boundary(MAX_DETAILS_LEN);
    format!("{}… [truncated]", &details[..boundary])
}

/// Удаляет CR и LF из значения HTTP-заголовка, предотвращая header injection.
fn sanitize_header_value(v: &str) -> String {
    v.replace(['\r', '\n'], "")
}

// ─────────────────────────────────────────────
//  Валидация URL (SSRF-защита)
// ─────────────────────────────────────────────

/// Проверяет URL вебхука:
/// 1. Допускает только HTTPS (HTTP разрешён только в debug-сборке).
/// 2. Блокирует localhost, loopback, link-local и приватные диапазоны RFC1918,
///    чтобы исключить SSRF-атаки на внутреннюю инфраструктуру.
/// 
/// 
fn is_safe_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            // Для IPv4 всё стандартно
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_broadcast() || v4.is_documentation()
        }
        std::net::IpAddr::V6(v6) => {
            // Для IPv6 проверяем loopback и уникальные локальные адреса (аналог private)
            v6.is_loopback() || 
            (v6.segments()[0] & 0xfe00 == 0xfc00) || // Unicast Unique Local
            (v6.segments()[0] & 0xffc0 == 0xfe80)    // Link Local
        }
    }
}
async fn validate_webhook_url(url: &str) -> Result<Uri, String> {
    let uri: Uri = url
        .parse()
        .map_err(|_| format!("Invalid URL format: {}", url))?;

    // Проверка схемы
    match uri.scheme_str() {
        Some("https") => {}
        #[cfg(debug_assertions)]
        Some("http") => {}
        _ => {
            return Err(
                "Only HTTPS URLs are allowed (HTTP only in debug builds)".into(),
            )
        }
    }

    // Проверка хоста на SSRF
    let host = uri
        .host()
        .ok_or_else(|| "URL missing host".to_string())?
        .to_lowercase();

    for prefix in BLOCKED_HOST_PREFIXES {
        if host.starts_with(prefix) || host == *prefix {
            return Err(format!(
                "Blocked host '{}': points to a private/local address",
                host
            ));
        }
    }

    let ips = tokio::net::lookup_host(format!("{}:443", host)).await
        .map_err(|e| format!("DNS lookup failed: {}", e))?;

    for addr in ips {
        let ip = addr.ip();
        if is_safe_ip(ip) {
            return Err(format!("Blocked internal/unsafe IP: {}", ip));
        }
    }
    Ok(uri)
}

// ─────────────────────────────────────────────
//  HTTP-отправка
// ─────────────────────────────────────────────

async fn send_webhook(
    url: &str,
    body: &str,
    extra_headers: &[(String, String)],
) -> Result<(), String> {
    // 1. Валидация URL (схема + SSRF)
    let uri = validate_webhook_url(url).await?;

    // 2. HTTP-клиент (без OpenSSL — используем hyper_util)
    let client = hyper_util::client::legacy::Client::builder(
        hyper_util::rt::TokioExecutor::new(),
    )
    .build_http::<axum::body::Body>();

    let mut builder = hyper::Request::builder()
        .method("POST")
        .uri(uri)
        .header("Content-Type", "application/json");

    // 3. Добавляем доп. заголовки с санитизацией значений (header injection)
    for (k, v) in extra_headers {
        builder = builder.header(k.as_str(), sanitize_header_value(v).as_str());
    }

    let req = builder
        .body(axum::body::Body::from(body.to_string()))
        .map_err(|e| format!("Request build error: {}", e))?;

    // 4. Таймаут на весь запрос
    let result = tokio::time::timeout(
        Duration::from_secs(WEBHOOK_TIMEOUT_SECS),
        client.request(req),
    )
    .await
    .map_err(|_| format!("Timeout after {}s", WEBHOOK_TIMEOUT_SECS))?;

    match result {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => Err(format!("Webhook returned HTTP {}", resp.status())),
        Err(e) => Err(format!("Webhook request failed: {}", e)),
    }
}

// ─────────────────────────────────────────────
//  Тесты
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── severity ──────────────────────────────

    #[test]
    fn severity_threshold_matching() {
        assert!(meets_severity(0.95, "critical"));
        assert!(!meets_severity(0.8, "critical"));
        assert!(meets_severity(0.7, "high"));
        assert!(!meets_severity(0.5, "high"));
        assert!(meets_severity(0.5, "medium"));
        assert!(meets_severity(0.0, "info"));
    }

    #[test]
    fn score_labels_correct() {
        assert_eq!(score_label(1.0), "CRITICAL");
        assert_eq!(score_label(0.9), "CRITICAL");
        assert_eq!(score_label(0.7), "HIGH");
        assert_eq!(score_label(0.5), "MEDIUM");
        assert_eq!(score_label(0.3), "LOW");
        assert_eq!(score_label(0.1), "INFO");
    }

    // ── форматирование ────────────────────────

    #[test]
    fn discord_format_high() {
        let event = test_event(0.75);
        let payload = format_discord(&event);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(parsed["embeds"][0]["title"]
            .as_str()
            .unwrap()
            .contains("HIGH"));
        assert_eq!(parsed["embeds"][0]["color"], 0xFF6600_u32);
    }

    #[test]
    fn discord_format_critical() {
        let event = test_event(0.95);
        let payload = format_discord(&event);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["embeds"][0]["color"], 0xFF0000_u32);
    }

    #[test]
    fn telegram_format_contains_escaped_details() {
        let mut event = test_event(0.9);
        // Детали содержат спецсимволы MarkdownV2
        event.details = "alert: score=0.9 [test]".to_string();
        let payload = format_telegram(&event, "12345");
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let text = parsed["text"].as_str().unwrap();
        // Скобки должны быть экранированы
        assert!(text.contains("\\[") && text.contains("\\]"));
        assert_eq!(parsed["parse_mode"], "MarkdownV2");
    }

    #[test]
    fn generic_format_fields() {
        let event = test_event(0.5);
        let payload = format_generic(&event);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["source"], "OxideWall");
        assert_eq!(parsed["severity"], "MEDIUM");
        assert!(parsed["event_id"].as_str().is_some());
    }

    // ── escape_telegram_md ───────────────────

    #[test]
    fn telegram_escape_special_chars() {
        let input = "hello_world [test] (value) ~bold~";
        let escaped = escape_telegram_md(input);
        assert!(escaped.contains("\\_"));
        assert!(escaped.contains("\\["));
        assert!(escaped.contains("\\("));
        assert!(escaped.contains("\\~"));
    }

    #[test]
    fn telegram_escape_plain_text_unchanged() {
        let input = "normal text 123";
        assert_eq!(escape_telegram_md(input), input);
    }

    // ── truncate_details ─────────────────────

    #[test]
    fn truncate_short_string_unchanged() {
        let s = "short";
        assert_eq!(truncate_details(s), s);
    }

    #[test]
    fn truncate_long_string() {
        let s = "a".repeat(MAX_DETAILS_LEN + 100);
        let result = truncate_details(&s);
        assert!(result.contains("[truncated]"));
        // Результат не должен быть длиннее лимита + маркер
        assert!(result.len() <= MAX_DETAILS_LEN + 20);
    }

    #[test]
    fn truncate_utf8_boundary() {
        // Кириллица — каждый символ 2 байта
        let s = "а".repeat(MAX_DETAILS_LEN);
        // Не должно паниковать
        let _ = truncate_details(&s);
    }

    // ── sanitize_header_value ────────────────

    #[test]
    fn header_injection_stripped() {
        let malicious = "value\r\nX-Injected: evil";
        let sanitized = sanitize_header_value(malicious);
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\n'));
        assert_eq!(sanitized, "valueX-Injected: evil");
    }

    // ── validate_webhook_url ─────────────────


    #[test]
    fn http_blocked_in_release() {
        // В release-сборке HTTP должен быть заблокирован
        // (в debug — разрешён, поэтому тест условный)
        #[cfg(not(debug_assertions))]
        assert!(validate_webhook_url("http://example.com/hook").is_err());
    }


    // ── helpers ───────────────────────────────

    fn test_event(score: f64) -> AuditEvent {
        AuditEvent {
            id: "test-id-001".to_string(),
            timestamp: chrono::Utc::now(),
            event_type: crate::audit_chain::SecurityEventType::RequestBlocked,
            source_ip: "10.0.0.1".to_string(),
            details: "test detection detail".to_string(),
            threat_score: score,
            previous_hash: "0000".to_string(),
            hash: "abcdef".to_string(),
        }
    }
}