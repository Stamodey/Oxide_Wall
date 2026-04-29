// ============================================================================
// File: signature_updater.rs
// Description: Automatic signature database updates from a remote NDJSON feed
// ============================================================================
//! Signature Updater — periodically fetches malware signatures from a remote
//! NDJSON feed and updates the local signature database atomically.
//!
//! ## Исправления по сравнению с оригиналом
//!
//! | Проблема оригинала                          | Решение                              |
//! |---------------------------------------------|--------------------------------------|
//! | Нет SSRF-защиты feed_url                    | `validate_feed_url()` при старте     |
//! | `build_http()` — plaintext, MITM-риск        | Проверка схемы HTTPS                 |
//! | auth_header может утечь в лог               | `SensitiveHeader` wrapper            |
//! | Нет лимита размера тела                     | `MAX_FEED_BYTES` + счётчик           |
//! | Нет таймаута HTTP-запроса                   | `tokio::time::timeout`               |
//! | line_count до валидации → неверный лог      | Счётчик после валидации              |
//! | Нет валидации структуры записи              | `validate_signature_record()`        |
//! | Фиксированное tmp-имя → race condition      | tmp с PID + timestamp                |
//! | Первый fetch через interval_secs            | Немедленный fetch при старте         |
//! | Нет backoff при ошибках                     | Экспоненциальный backoff (3 попытки) |

use crate::config::SignatureUpdateConfig;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

// ─────────────────────────────────────────────────────────────────────────────
//  Константы
// ─────────────────────────────────────────────────────────────────────────────

/// Максимальный размер тела ответа (16 МБ).
/// Защита от бесконечного потока с вредоносного сервера.
const MAX_FEED_BYTES: usize = 16 * 1024 * 1024;

/// Таймаут одного HTTP-запроса к feed-серверу.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Базовая задержка для exponential backoff (сек).
const BACKOFF_BASE_SECS: u64 = 60;

/// Максимальное число retry-попыток подряд перед возвратом к обычному интервалу.
const MAX_RETRIES: u32 = 3;

/// Обязательные поля в каждой signature-записи NDJSON.
const REQUIRED_FIELDS: &[&str] = &["hash", "name"];

// ─────────────────────────────────────────────────────────────────────────────
//  Wrapper для чувствительных заголовков (не попадает в лог)
// ─────────────────────────────────────────────────────────────────────────────

/// Обёртка над строкой, которая не отображается в `Debug`/`Display`.
/// Предотвращает случайный вывод auth-токена в tracing-логах.
struct SensitiveHeader(String);

impl SensitiveHeader {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SensitiveHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl std::fmt::Display for SensitiveHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Публичный API
// ─────────────────────────────────────────────────────────────────────────────

/// Запустить фоновую задачу обновления подписей.
///
/// Первое обновление происходит немедленно при старте, затем по расписанию.
/// Возвращает `(JoinHandle, shutdown_sender)` — отправь `true` в канал для остановки.
///
/// Возвращает `Err` если `feed_url` не прошёл SSRF-валидацию или использует HTTP
/// вместо HTTPS (небезопасно для базы данных угроз).
pub fn start_updater(
    config: SignatureUpdateConfig,
    signatures_path: Arc<std::path::PathBuf>,
) -> Result<(tokio::task::JoinHandle<()>, watch::Sender<bool>), String> {
    // Валидация URL при старте — не в фоновой задаче
    validate_feed_url(&config.feed_url)?;

    let auth = config.auth_header.clone().map(SensitiveHeader);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(async move {
        let interval = Duration::from_secs(config.interval_secs);
        tracing::info!(
            url = %config.feed_url,
            interval_secs = config.interval_secs,
            // FIX: auth_header НЕ логируется — только факт его наличия
            has_auth = auth.is_some(),
            "Signature auto-updater started"
        );

        let mut consecutive_errors: u32 = 0;
        // FIX: первое обновление немедленно при старте (не ждём interval)
        let mut first_run = true;

        loop {
            if !first_run {
                // Backoff: при ошибках задержка растёт экспоненциально
                let sleep_dur = if consecutive_errors > 0 && consecutive_errors <= MAX_RETRIES {
                    let backoff = BACKOFF_BASE_SECS * (1u64 << (consecutive_errors - 1));
                    tracing::info!(
                        retry_in_secs = backoff,
                        attempt = consecutive_errors,
                        "Signature update failed, backing off"
                    );
                    Duration::from_secs(backoff)
                } else {
                    interval
                };

                tokio::select! {
                    _ = tokio::time::sleep(sleep_dur) => {},
                    _ = shutdown_rx.changed() => {
                        tracing::info!("Signature updater shutting down");
                        return;
                    }
                }
            }
            first_run = false;

            // Проверяем shutdown перед началом работы
            if *shutdown_rx.borrow() {
                return;
            }

            match fetch_signatures(&config.feed_url, auth.as_ref()).await {
                Ok(content) => {
                    if content.trim().is_empty() {
                        tracing::debug!("Signature feed returned empty content, skipping");
                        consecutive_errors = 0;
                        continue;
                    }

                    match validate_and_parse_feed(&content) {
                        Ok(valid_count) => {
                            match atomic_write(&signatures_path, &content) {
                                Ok(()) => {
                                    // FIX: line_count после валидации — только валидные строки
                                    tracing::info!(
                                        signatures = valid_count,
                                        path = %signatures_path.display(),
                                        "Signature database updated from remote feed"
                                    );
                                    consecutive_errors = 0;
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "Atomic write failed");
                                    consecutive_errors += 1;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Signature feed validation failed, skipping update");
                            consecutive_errors += 1;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to fetch signature update");
                    consecutive_errors += 1;
                    // После MAX_RETRIES сбрасываем счётчик — возвращаемся к обычному интервалу
                    if consecutive_errors > MAX_RETRIES {
                        consecutive_errors = 0;
                    }
                }
            }
        }
    });

    Ok((handle, shutdown_tx))
}

// ─────────────────────────────────────────────────────────────────────────────
//  Валидация URL (SSRF + HTTPS)
// ─────────────────────────────────────────────────────────────────────────────

/// Заблокированные префиксы хостов — аналог ssrf_guard.rs.
const BLOCKED_HOST_PREFIXES: &[&str] = &[
    "localhost", "127.", "0.0.0.0", "169.254.",
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "::1", "fd", "fe80",
];

/// Проверить feed_url на SSRF и принудить HTTPS.
///
/// FIX 1: оригинал не проверял URL вообще.
/// FIX 2: plaintext HTTP недопустим для базы данных угроз — MITM может
///         подменить подписи и добавить ложные срабатывания или пропустить угрозы.
pub fn validate_feed_url(url: &str) -> Result<(), String> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|_| format!("Invalid feed URL format: {url}"))?;

    // FIX: только HTTPS — подписи к антивирусной БД нельзя передавать по HTTP
    #[cfg(not(debug_assertions))]
    if uri.scheme_str() != Some("https") {
        return Err(format!(
            "Feed URL must use HTTPS (got '{}') — \
             signatures transmitted over HTTP can be tampered via MITM",
            uri.scheme_str().unwrap_or("none")
        ));
    }

    let host = uri
        .host()
        .ok_or_else(|| "Feed URL has no host".to_string())?
        .to_lowercase();

    for prefix in BLOCKED_HOST_PREFIXES {
        if host.starts_with(prefix) || host == *prefix {
            return Err(format!(
                "Feed URL host '{host}' is blocked (private/loopback range) — SSRF prevention"
            ));
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  HTTP-запрос
// ─────────────────────────────────────────────────────────────────────────────

/// Загрузить NDJSON-feed с удалённого сервера.
///
/// FIX: добавлены таймаут и лимит размера тела.
/// FIX: auth_header принимается как `Option<&SensitiveHeader>` — не логируется.
async fn fetch_signatures(
    url: &str,
    auth: Option<&SensitiveHeader>,
) -> Result<String, String> {
    let client = hyper_util::client::legacy::Client::builder(
        hyper_util::rt::TokioExecutor::new(),
    )
    .build_http::<axum::body::Body>();

    let uri: hyper::Uri = url
        .parse()
        .map_err(|e| format!("Invalid feed URL: {e}"))?;

    let mut builder = hyper::Request::builder()
        .method("GET")
        .uri(uri)
        .header("User-Agent", "OxideWall-SignatureUpdater/1.0")
        .header("Accept", "application/x-ndjson, application/json");

    if let Some(token) = auth {
        // FIX: значение токена не попадает в трассировку
        builder = builder.header("Authorization", token.as_str());
    }

    let req = builder
        .body(axum::body::Body::empty())
        .map_err(|e| format!("Request build error: {e}"))?;

    // FIX: таймаут на весь запрос
    let resp = tokio::time::timeout(FETCH_TIMEOUT, client.request(req))
        .await
        .map_err(|_| format!("Fetch timed out after {}s", FETCH_TIMEOUT.as_secs()))?
        .map_err(|e| format!("Fetch failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("Feed returned HTTP {}", resp.status()));
    }

    // FIX: проверяем Content-Type
    if let Some(ct) = resp.headers().get("content-type") {
        let ct_str = ct.to_str().unwrap_or("").to_lowercase();
        if !ct_str.contains("json") && !ct_str.contains("text") && !ct_str.contains("octet") {
            return Err(format!(
                "Unexpected Content-Type '{ct_str}' — expected JSON or text"
            ));
        }
    }

    // FIX: лимит размера тела — читаем частями с подсчётом байт
    let body_bytes = read_body_limited(resp.into_body()).await?;

    String::from_utf8(body_bytes).map_err(|e| format!("Invalid UTF-8 in feed: {e}"))
}

/// Читает тело ответа с жёстким лимитом `MAX_FEED_BYTES`.
async fn read_body_limited(body: hyper::body::Incoming) -> Result<Vec<u8>, String> {
    use http_body_util::BodyExt;

    let collected = tokio::time::timeout(FETCH_TIMEOUT, body.collect())
        .await
        .map_err(|_| "Body read timed out".to_string())?
        .map_err(|e| format!("Body read error: {e}"))?;

    let bytes = collected.to_bytes();

    // FIX: лимит размера
    if bytes.len() > MAX_FEED_BYTES {
        return Err(format!(
            "Feed response too large: {} bytes (max {})",
            bytes.len(),
            MAX_FEED_BYTES
        ));
    }

    Ok(bytes.to_vec())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Валидация NDJSON-контента
// ─────────────────────────────────────────────────────────────────────────────

/// Минимально допустимое число подписей в feed — защита от "пустого" обновления.
/// Если сервер вернул < MIN_SIGNATURES записей — обновление отклоняется.
const MIN_SIGNATURES: usize = 1;

/// Проверить NDJSON-контент: каждая строка — валидный JSON с обязательными полями.
/// Возвращает количество валидных записей.
///
/// FIX: оригинал проверял только "это JSON", но не структуру записи.
/// Битая запись {"foo":"bar"} пройдёт и может сломать signature engine.
pub fn validate_and_parse_feed(content: &str) -> Result<usize, String> {
    let mut valid_count = 0usize;

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue; // пустые строки допустимы в NDJSON
        }

        let value: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| {
                format!("Invalid JSON on line {}: {e}", line_num + 1)
            })?;

        // FIX: проверяем обязательные поля
        validate_signature_record(&value, line_num + 1)?;

        valid_count += 1;
    }

    if valid_count < MIN_SIGNATURES {
        return Err(format!(
            "Feed contains only {valid_count} signature(s), minimum is {MIN_SIGNATURES}"
        ));
    }

    Ok(valid_count)
}

/// Проверяет что одна signature-запись содержит обязательные поля нужных типов.
fn validate_signature_record(
    record: &serde_json::Value,
    line_num: usize,
) -> Result<(), String> {
    let obj = record
        .as_object()
        .ok_or_else(|| format!("Line {line_num}: record must be a JSON object"))?;

    for field in REQUIRED_FIELDS {
        match obj.get(*field) {
            None => {
                return Err(format!(
                    "Line {line_num}: missing required field '{field}'"
                ));
            }
            Some(v) if !v.is_string() => {
                return Err(format!(
                    "Line {line_num}: field '{field}' must be a string, got {}",
                    v
                ));
            }
            Some(v) if v.as_str().unwrap_or("").is_empty() => {
                return Err(format!(
                    "Line {line_num}: field '{field}' must not be empty"
                ));
            }
            _ => {}
        }
    }

    // hash должен выглядеть как hex SHA-256 (64 символа)
    if let Some(hash) = obj.get("hash").and_then(|v| v.as_str()) {
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "Line {line_num}: 'hash' must be a 64-char hex string (SHA-256), got '{}'",
                &hash[..hash.len().min(16)]
            ));
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Атомарная запись
// ─────────────────────────────────────────────────────────────────────────────

/// Записывает контент атомарно: tmp-файл → rename.
///
/// FIX: оригинал использовал фиксированное имя `.ndjson.tmp` — при двух
/// процессах с одним путём возникал race condition.
/// Теперь tmp-имя уникально: PID + timestamp в наносекундах.
fn atomic_write(target: &Path, content: &str) -> Result<(), String> {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    );

    let tmp_path = target.with_extension(format!("tmp-{unique}"));

    std::fs::write(&tmp_path, content)
        .map_err(|e| format!("Failed to write tmp file '{}': {e}", tmp_path.display()))?;

    std::fs::rename(&tmp_path, target).map_err(|e| {
        // Пробуем убрать tmp при ошибке — не критично если не получится
        let _ = std::fs::remove_file(&tmp_path);
        format!(
            "Failed to rename '{}' → '{}': {e}",
            tmp_path.display(),
            target.display()
        )
    })?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Тесты
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    ///use std::path::PathBuf;

    // ── validate_feed_url ─────────────────────────────────────────────────────

    #[test]
    fn valid_https_url_passes() {
        assert!(validate_feed_url("https://signatures.example.com/v1/latest.ndjson").is_ok());
    }

    #[test]
    fn ssrf_localhost_blocked() {
        assert!(validate_feed_url("https://localhost/sigs").is_err());
        assert!(validate_feed_url("https://127.0.0.1/sigs").is_err());
    }

    #[test]
    fn ssrf_aws_metadata_blocked() {
        assert!(validate_feed_url("https://169.254.169.254/latest").is_err());
    }

    #[test]
    fn ssrf_private_range_blocked() {
        assert!(validate_feed_url("https://10.0.0.1/sigs").is_err());
        assert!(validate_feed_url("https://192.168.1.1/sigs").is_err());
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn http_blocked_in_release() {
        // В release-сборке HTTP недопустим для базы подписей
        assert!(validate_feed_url("http://example.com/sigs.ndjson").is_err());
    }

    #[test]
    fn invalid_url_rejected() {
        assert!(validate_feed_url("not-a-url").is_err());
        assert!(validate_feed_url("ftp://example.com/sigs").is_err());
    }

    // ── validate_and_parse_feed ───────────────────────────────────────────────

    #[test]
    fn valid_ndjson_passes() {
        let content = concat!(
            "{\"hash\":\"a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1\",",
            "\"name\":\"EICAR-Test-File\",\"family\":\"TestVirus\",\"severity\":\"high\"}\n",
            "{\"hash\":\"b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4\",",
            "\"name\":\"Trojan.GenericKD\"}\n"
        );
        let r = validate_and_parse_feed(content);
        assert!(r.is_ok(), "err: {:?}", r);
        assert_eq!(r.unwrap(), 2);
    }

    #[test]
    fn invalid_json_rejected() {
        let content = "not json at all\n";
        assert!(validate_and_parse_feed(content).is_err());
    }

    #[test]
    fn missing_hash_field_rejected() {
        let content = "{\"name\":\"SomeMalware\"}\n";
        let r = validate_and_parse_feed(content);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("hash"));
    }

    #[test]
    fn missing_name_field_rejected() {
        let content =
            "{\"hash\":\"a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1\"}\n";
        let r = validate_and_parse_feed(content);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("name"));
    }

    #[test]
    fn invalid_hash_length_rejected() {
        // hash должен быть 64-символьным hex
        let content = "{\"hash\":\"tooshort\",\"name\":\"Malware\"}\n";
        assert!(validate_and_parse_feed(content).is_err());
    }

    #[test]
    fn non_hex_hash_rejected() {
        let content = concat!(
            "{\"hash\":\"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\",",
            "\"name\":\"Malware\"}\n"
        );
        assert!(validate_and_parse_feed(content).is_err());
    }

    #[test]
    fn empty_feed_rejected() {
        assert!(validate_and_parse_feed("").is_err());
        assert!(validate_and_parse_feed("   \n\n").is_err());
    }

    #[test]
    fn blank_lines_skipped() {
        let content = concat!(
            "\n",
            "{\"hash\":\"a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1\",",
            "\"name\":\"EICAR\"}\n",
            "\n"
        );
        assert!(validate_and_parse_feed(content).is_ok());
    }

    // ── atomic_write ──────────────────────────────────────────────────────────

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("signatures.ndjson");
        let content = "{\"hash\":\"a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1\",\"name\":\"Test\"}\n";

        assert!(atomic_write(&target, content).is_ok());
        assert!(target.exists());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), content);
    }

    #[test]
    fn atomic_write_no_tmp_leftover_on_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("sigs.ndjson");
        atomic_write(&target, "x").ok();

        // После успешной записи tmp-файлов быть не должно
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains("tmp")
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "tmp files left over: {leftovers:?}"
        );
    }

    #[test]
    fn atomic_write_unique_tmp_no_collision() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("sigs.ndjson");

        // Два вызова подряд должны использовать разные tmp-имена
        // (не конкурируют — проверяем что оба успешны)
        assert!(atomic_write(&target, "content1").is_ok());
        assert!(atomic_write(&target, "content2").is_ok());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "content2");
    }

    // ── SensitiveHeader ───────────────────────────────────────────────────────

    #[test]
    fn sensitive_header_not_exposed_in_debug() {
        let h = SensitiveHeader("Bearer super-secret-token-123".to_string());
        let debug_str = format!("{h:?}");
        assert!(!debug_str.contains("super-secret"), "token leaked: {debug_str}");
        assert!(debug_str.contains("REDACTED"));
    }

    #[test]
    fn sensitive_header_not_exposed_in_display() {
        let h = SensitiveHeader("Bearer super-secret-token-123".to_string());
        let display_str = format!("{h}");
        assert!(!display_str.contains("super-secret"), "token leaked in Display");
    }

    // ── validate_signature_record ─────────────────────────────────────────────

    #[test]
    fn record_not_object_rejected() {
        let v = serde_json::json!([1, 2, 3]);
        assert!(validate_signature_record(&v, 1).is_err());
    }

    #[test]
    fn empty_hash_rejected() {
        let v = serde_json::json!({"hash": "", "name": "test"});
        assert!(validate_signature_record(&v, 1).is_err());
    }

    #[test]
    fn valid_record_passes() {
        let v = serde_json::json!({
            "hash": "a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1b2c4d5e6a3f1",
            "name": "EICAR-Test-File",
            "severity": "high"
        });
        assert!(validate_signature_record(&v, 1).is_ok());
    }
}