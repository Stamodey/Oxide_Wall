// ============================================================================
// File: ssrf_guard.rs
// Description: SSRF prevention with URL validation, IP blocking, and DNS rebinding defense
// ============================================================================
//! SSRF Guard — Server-Side Request Forgery prevention.
//!
//! Validates URLs and IP addresses to prevent internal network probing,
//! cloud metadata endpoint access, and DNS rebinding attacks.
//!
//! ## Покрытые векторы атак
//!
//! | Вектор                        | Защита                              |
//! |-------------------------------|-------------------------------------|
//! | Loopback (127.x, ::1)         | `validate_ipv4` / `validate_ipv6`   |
//! | RFC1918 private ranges        | `validate_ipv4`                     |
//! | Link-local / AWS metadata     | `validate_ipv4` (169.254.x.x)       |
//! | IPv6 ULA (fc00::/7)           | `validate_ipv6`                     |
//! | IPv4-mapped IPv6              | `validate_ipv6` → `validate_ipv4`   |
//! | Decimal IP (2130706433)       | `try_parse_alternative_ip`          |
//! | Octal IP (0177.0.0.1)         | `try_parse_alternative_ip`          |
//! | Hex IP (0x7f000001)           | `try_parse_alternative_ip`          |
//! | Localhost hostname variants   | `validate_hostname`                 |
//! | Cloud metadata hostnames      | `validate_hostname`                 |
//! | Internal TLDs (.local/.corp)  | `validate_hostname`                 |
//! | Userinfo в URL (user@host)    | `validate_url` pre-check            |
//! | Заблокированные порты         | `validate_url` port check           |
//! | Длинные hostname в ошибках    | `truncate_host` в сообщениях        |

use crate::config::SsrfConfig;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

/// Максимальная длина hostname в сообщениях об ошибках.
/// Защита от раздутых логов при атаках с очень длинными URL.
const MAX_HOST_IN_ERR: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
//  Публичные функции
// ─────────────────────────────────────────────────────────────────────────────

/// Проверить URL на SSRF-безопасность.
/// Возвращает `Ok(())` если URL безопасен, `Err(reason)` — если нужно заблокировать.
pub fn validate_url(raw_url: &str, config: &SsrfConfig) -> Result<(), String> {
    let parsed = Url::parse(raw_url).map_err(|e| format!("Invalid URL: {e}"))?;

    // ── Схема ──────────────────────────────────────────────────────────────────
    let scheme = parsed.scheme().to_lowercase();
    if !config.allowed_schemes.contains(&scheme) {
        return Err(format!(
            "URL scheme '{scheme}' is not allowed. Allowed: {:?}",
            config.allowed_schemes
        ));
    }

    // ── Userinfo (user:pass@host) ───────────────────────────────────────────
    // Userinfo в URL — классический вектор обхода: http://evil@169.254.169.254/
    // Некоторые парсеры трактуют всё до '@' как credentials, другие — как хост.
    // Блокируем безусловно: легитимные webhook-URL userinfo не используют.
    if parsed.username() != "" || parsed.password().is_some() {
        return Err("URL with userinfo (user:pass@host) is not allowed".to_string());
    }

    // ── Хост ───────────────────────────────────────────────────────────────────
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    // Явный blocklist
    if config.blocklist.contains(host) {
        return Err(format!("Host '{}' is in the blocklist", truncate_host(host)));
    }

    // Явный allowlist — пропускает оставшиеся проверки
    if config.allowlist.contains(host) {
        return Ok(());
    }

    // ── Порт ───────────────────────────────────────────────────────────────────
    if let Some(port) = parsed.port() {
        if config.blocked_ports.contains(&port) {
            return Err(format!(
                "Port {port} is blocked (common internal service port)"
            ));
        }
    }

    // ── IP или hostname ────────────────────────────────────────────────────────
    if let Ok(ip) = host.parse::<IpAddr>() {
        validate_ip(&ip, config)?;
    } else {
        // Hostname: проверяем нестандартные IP-нотации ДО hostname-валидации
        if let Some(ip) = try_parse_alternative_ip(host) {
            return Err(format!(
                "Alternative IP notation '{}' resolves to blocked address {}",
                truncate_host(host),
                ip
            ));
        }
        validate_hostname(host, config)?;
    }

    Ok(())
}

/// Проверить сырую IP-строку (для полей connection_string, controller_ip и т.д.)
pub fn validate_ip_str(ip_str: &str, config: &SsrfConfig) -> Result<(), String> {
    if config.allowlist.contains(ip_str) {
        return Ok(());
    }
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| format!("Invalid IP address: {}", truncate_host(ip_str)))?;
    validate_ip(&ip, config)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Валидация IP
// ─────────────────────────────────────────────────────────────────────────────

fn validate_ip(ip: &IpAddr, config: &SsrfConfig) -> Result<(), String> {
    match ip {
        IpAddr::V4(v4) => validate_ipv4(v4, config),
        IpAddr::V6(v6) => validate_ipv6(v6, config),
    }
}

fn validate_ipv4(ip: &Ipv4Addr, config: &SsrfConfig) -> Result<(), String> {
    let octets = ip.octets();

    // Loopback (127.0.0.0/8)
    if config.block_loopback && octets[0] == 127 {
        return Err(format!("Loopback address {ip} is blocked"));
    }

    // Приватные диапазоны RFC1918
    if config.block_private_ips {
        if octets[0] == 10 {
            return Err(format!("Private IP {ip} (10.0.0.0/8) is blocked"));
        }
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return Err(format!("Private IP {ip} (172.16.0.0/12) is blocked"));
        }
        if octets[0] == 192 && octets[1] == 168 {
            return Err(format!("Private IP {ip} (192.168.0.0/16) is blocked"));
        }
    }

    // Link-local (169.254.0.0/16) — включает AWS EC2 metadata endpoint
    if config.block_link_local && octets[0] == 169 && octets[1] == 254 {
        // Выделяем конкретный metadata endpoint в отдельное сообщение
        if config.block_metadata_endpoints && octets[2] == 169 && octets[3] == 254 {
            return Err(format!(
                "Cloud metadata endpoint {ip} is blocked (CVE-class SSRF target)"
            ));
        }
        return Err(format!("Link-local address {ip} is blocked"));
    }

    // Broadcast
    if octets == [255, 255, 255, 255] {
        return Err("Broadcast address 255.255.255.255 is blocked".to_string());
    }

    // Unspecified
    if octets == [0, 0, 0, 0] {
        return Err("Unspecified address 0.0.0.0 is blocked".to_string());
    }

    // Shared address space (100.64.0.0/10 — RFC6598, carrier-grade NAT)
    // Часто доступен во внутренних сетях провайдеров
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return Err(format!("Shared address space {ip} (100.64.0.0/10, RFC6598) is blocked"));
    }

    Ok(())
}

fn validate_ipv6(ip: &Ipv6Addr, config: &SsrfConfig) -> Result<(), String> {
    let segments = ip.segments();

    // Loopback (::1)
    if config.block_loopback && ip.is_loopback() {
        return Err(format!("IPv6 loopback {ip} is blocked"));
    }

    // Unspecified (::)
    if segments == [0; 8] {
        return Err("IPv6 unspecified address :: is blocked".to_string());
    }

    // Link-local (fe80::/10)
    if config.block_link_local && (segments[0] & 0xffc0) == 0xfe80 {
        return Err(format!("IPv6 link-local address {ip} is blocked"));
    }

    // Unique Local Address (fc00::/7) — RFC4193, аналог RFC1918 для IPv6
    // Охватывает fc00::/8 и fd00::/8
    if config.block_private_ips && (segments[0] & 0xfe00) == 0xfc00 {
        return Err(format!("IPv6 ULA address {ip} (fc00::/7) is blocked"));
    }

    // IPv4-mapped (::ffff:x.x.x.x) — проверяем встроенный IPv4
    if let Some(v4) = ip.to_ipv4_mapped() {
        return validate_ipv4(&v4, config).map_err(|e| {
            format!("IPv4-mapped IPv6 {ip} rejected: {e}")
        });
    }

    // IPv4-compatible (::x.x.x.x, deprecated RFC4291)
    // to_ipv4() возвращает Some для ::x.x.x.x, но to_ipv4_mapped() — нет
    if let Some(v4) = ip.to_ipv4() {
        return validate_ipv4(&v4, config).map_err(|e| {
            format!("IPv4-compatible IPv6 {ip} rejected: {e}")
        });
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Валидация hostname
// ─────────────────────────────────────────────────────────────────────────────

fn validate_hostname(hostname: &str, config: &SsrfConfig) -> Result<(), String> {
    let lower = hostname.to_lowercase();

    // ── Localhost-варианты ─────────────────────────────────────────────────
    if config.block_loopback
        && (lower == "localhost"
            || lower == "localhost.localdomain"
            || lower.ends_with(".localhost"))
    {
        return Err(format!(
            "Hostname '{}' resolves to loopback",
            truncate_host(hostname)
        ));
    }

    // ── Cloud metadata hostnames ────────────────────────────────────────────
    if config.block_metadata_endpoints {
        const METADATA_HOSTS: &[&str] = &[
            "metadata.google.internal",
            "metadata.google",
            "169.254.169.254",
            "metadata",
            "instance-data",        // AWS альтернативное имя
            "169.254.170.2",        // AWS ECS metadata
            "fd00:ec2::254",        // AWS IMDSv2 IPv6
        ];
        for mh in METADATA_HOSTS {
            if lower == *mh || lower.ends_with(&format!(".{mh}")) {
                return Err(format!(
                    "Cloud metadata hostname '{}' is blocked",
                    truncate_host(hostname)
                ));
            }
        }
    }

    // ── Внутренние TLD ──────────────────────────────────────────────────────
    const INTERNAL_TLDS: &[&str] = &[
        ".internal", ".local", ".corp", ".home", ".lan",
        ".intranet", ".private", ".localdomain",
    ];
    for tld in INTERNAL_TLDS {
        if lower.ends_with(tld) {
            return Err(format!(
                "Hostname '{}' uses an internal TLD which is blocked",
                truncate_host(hostname)
            ));
        }
    }

    // ── Punycode / IDN проверка ─────────────────────────────────────────────
    // Punycode-encoded hostnames (xn--...) могут маскировать внутренние имена.
    // Блокируем labels начинающиеся с "xn--" чтобы исключить IDN bypass.
    // Легитимные внешние сервисы обычно не используют punycode в webhook URL.
    for label in lower.split('.') {
        if label.starts_with("xn--") {
            return Err(format!(
                "Punycode/IDN hostname '{}' is blocked (potential bypass attempt)",
                truncate_host(hostname)
            ));
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Нестандартные IP-нотации
// ─────────────────────────────────────────────────────────────────────────────

/// Пытается разобрать нестандартные IP-нотации, которые браузеры и HTTP-клиенты
/// принимают, но `IpAddr::from_str` — нет.
///
/// Если строка декодируется в заблокированный IP — возвращает `Some(ip)`.
/// Если строка безопасна или не является нестандартным IP — `None`.
///
/// Покрытые форматы:
/// - Decimal: `2130706433` → `127.0.0.1`
/// - Hex: `0x7f000001` → `127.0.0.1`
/// - Octal dotted: `0177.0.0.1` → `127.0.0.1`
/// - Mixed: `0x7f.0.0.01` → `127.0.0.1`
fn try_parse_alternative_ip(host: &str) -> Option<IpAddr> {
    let lower = host.trim().to_lowercase();

    // Decimal: чистое число без точек (напр. 2130706433 = 127.0.0.1)
    if !lower.contains('.') && !lower.contains(':') {
        if let Ok(n) = lower.parse::<u64>() {
            if n <= u32::MAX as u64 {
                let ip = Ipv4Addr::from(n as u32);
                if is_blocked_ipv4_quick(&ip) {
                    return Some(IpAddr::V4(ip));
                }
            }
        }
        // Hex без точек: 0x7f000001
        if lower.starts_with("0x") {
            if let Ok(n) = u32::from_str_radix(&lower[2..], 16) {
                let ip = Ipv4Addr::from(n);
                if is_blocked_ipv4_quick(&ip) {
                    return Some(IpAddr::V4(ip));
                }
            }
        }
    }

    // Dotted нотации с нестандартными октетами (octal / hex per octet)
    if lower.contains('.') {
        if let Some(ip) = parse_dotted_nonstandard(&lower) {
            if is_blocked_ipv4_quick(&ip) {
                return Some(IpAddr::V4(ip));
            }
        }
    }

    None
}

/// Разбирает дотted-нотацию где каждый октет может быть octal (0177) или hex (0xff).
fn parse_dotted_nonstandard(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }

    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        let val = parse_octet(part)?;
        if val > 255 {
            return None;
        }
        octets[i] = val as u8;
    }
    Some(Ipv4Addr::from(octets))
}

/// Разбирает один октет в десятичной, восьмеричной или шестнадцатеричной записи.
fn parse_octet(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        u32::from_str_radix(&s[2..], 16).ok()
    } else if s.starts_with('0') && s.len() > 1 {
        // Octal
        u32::from_str_radix(&s[1..], 8).ok()
    } else {
        s.parse().ok()
    }
}

/// Быстрая проверка что IPv4 попадает в заблокированные диапазоны.
/// Используется только внутри `try_parse_alternative_ip` —
/// не зависит от конфига намеренно (все эти диапазоны всегда опасны).
fn is_blocked_ipv4_quick(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 127                                       // loopback
    || o[0] == 10                                     // RFC1918
    || (o[0] == 172 && (16..=31).contains(&o[1]))     // RFC1918
    || (o[0] == 192 && o[1] == 168)                   // RFC1918
    || (o[0] == 169 && o[1] == 254)                   // link-local / AWS metadata
    || o == [0, 0, 0, 0]                              // unspecified
    || o == [255, 255, 255, 255]                      // broadcast
    || (o[0] == 100 && (64..=127).contains(&o[1]))    // RFC6598 CGN
}

// ─────────────────────────────────────────────────────────────────────────────
//  Утилиты
// ─────────────────────────────────────────────────────────────────────────────

/// Обрезает hostname до MAX_HOST_IN_ERR символов для безопасного включения
/// в сообщения об ошибках — защита от раздутых логов при атаках длинными URL.
fn truncate_host(host: &str) -> String {
    if host.len() <= MAX_HOST_IN_ERR {
        host.to_string()
    } else {
        format!("{}…", &host[..MAX_HOST_IN_ERR])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Тесты
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SsrfConfig {
        SsrfConfig::default()
    }

    // ── Базовые разрешения ────────────────────────────────────────────────────

    #[test]
    fn allows_public_url() {
        assert!(validate_url("https://influxdb.example.com:8086/api/v3/query", &cfg()).is_ok());
    }

    #[test]
    fn allows_public_ip() {
        assert!(validate_url("https://203.0.113.50:8086/query", &cfg()).is_ok());
    }

    // ── Loopback ──────────────────────────────────────────────────────────────

    #[test]
    fn blocks_localhost_hostname() {
        assert!(validate_url("http://localhost:8086/query", &cfg()).is_err());
        assert!(validate_url("http://localhost.localdomain/query", &cfg()).is_err());
    }

    #[test]
    fn blocks_loopback_ipv4() {
        assert!(validate_url("http://127.0.0.1:8086/query", &cfg()).is_err());
        assert!(validate_url("http://127.255.255.255/", &cfg()).is_err());
    }

    #[test]
    fn blocks_loopback_ipv6() {
        assert!(validate_ip_str("::1", &cfg()).is_err());
    }

    // ── Private / RFC1918 ─────────────────────────────────────────────────────

    #[test]
    fn blocks_private_ipv4() {
        assert!(validate_url("http://10.0.0.1:8086/", &cfg()).is_err());
        assert!(validate_url("http://172.16.0.1:8086/", &cfg()).is_err());
        assert!(validate_url("http://172.31.255.255/", &cfg()).is_err());
        assert!(validate_url("http://192.168.1.1/", &cfg()).is_err());
    }

    #[test]
    fn allows_172_15_not_private() {
        // 172.15.x.x — НЕ RFC1918 (диапазон 172.16-172.31)
        assert!(validate_url("http://172.15.0.1/api", &cfg()).is_ok());
    }

    // ── Link-local / Metadata ─────────────────────────────────────────────────

    #[test]
    fn blocks_aws_metadata() {
        assert!(validate_url("http://169.254.169.254/latest/meta-data/", &cfg()).is_err());
    }

    #[test]
    fn blocks_link_local_range() {
        assert!(validate_url("http://169.254.1.1/", &cfg()).is_err());
    }

    #[test]
    fn blocks_google_metadata_hostname() {
        assert!(validate_url("http://metadata.google.internal/computeMetadata/v1/", &cfg()).is_err());
    }

    #[test]
    fn blocks_ecs_metadata() {
        assert!(validate_url("http://169.254.170.2/v2/metadata", &cfg()).is_err());
    }

    // ── IPv6 ──────────────────────────────────────────────────────────────────

    #[test]
    fn blocks_ipv4_mapped_ipv6_loopback() {
        assert!(validate_ip_str("::ffff:127.0.0.1", &cfg()).is_err());
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_private() {
        assert!(validate_ip_str("::ffff:192.168.1.1", &cfg()).is_err());
        assert!(validate_ip_str("::ffff:10.0.0.1", &cfg()).is_err());
    }

    #[test]
    fn blocks_ipv6_ula() {
        // fc00::/7 — Unique Local Address
        assert!(validate_ip_str("fd00::1", &cfg()).is_err());
        assert!(validate_ip_str("fc00::dead:beef", &cfg()).is_err());
    }

    #[test]
    fn blocks_ipv6_link_local() {
        assert!(validate_ip_str("fe80::1", &cfg()).is_err());
        assert!(validate_ip_str("fe80::dead:beef:cafe", &cfg()).is_err());
    }

    #[test]
    fn blocks_ipv6_unspecified() {
        assert!(validate_ip_str("::", &cfg()).is_err());
    }

    // ── Нестандартные IP-нотации ──────────────────────────────────────────────

    #[test]
    fn blocks_decimal_ip_loopback() {
        // 2130706433 = 127.0.0.1
        assert!(validate_url("http://2130706433/", &cfg()).is_err());
    }

    #[test]
    fn blocks_hex_ip_loopback() {
        // 0x7f000001 = 127.0.0.1
        assert!(validate_url("http://0x7f000001/", &cfg()).is_err());
    }

    #[test]
    fn blocks_octal_dotted_loopback() {
        // 0177.0.0.1 = 127.0.0.1
        assert!(validate_url("http://0177.0.0.1/", &cfg()).is_err());
    }

    #[test]
    fn blocks_decimal_ip_aws_metadata() {
        // 2852039166 = 169.254.169.254
        assert!(validate_url("http://2852039166/latest/meta-data/", &cfg()).is_err());
    }

    #[test]
    fn blocks_hex_ip_private() {
        // 0xc0a80101 = 192.168.1.1
        assert!(validate_url("http://0xc0a80101/api", &cfg()).is_err());
    }

    // ── Userinfo bypass ───────────────────────────────────────────────────────

    #[test]
    fn blocks_userinfo_in_url() {
        // Классический bypass: http://evil@169.254.169.254/
        assert!(validate_url("http://evil@169.254.169.254/", &cfg()).is_err());
        assert!(validate_url("http://user:pass@example.com/", &cfg()).is_err());
    }

    // ── Internal TLD ──────────────────────────────────────────────────────────

    #[test]
    fn blocks_internal_tlds() {
        assert!(validate_url("http://database.internal:5432/query", &cfg()).is_err());
        assert!(validate_url("http://redis.local:6379/", &cfg()).is_err());
        assert!(validate_url("http://api.corp/internal", &cfg()).is_err());
        assert!(validate_url("http://service.intranet/", &cfg()).is_err());
    }

    // ── Punycode / IDN ────────────────────────────────────────────────────────

    #[test]
    fn blocks_punycode_hostname() {
        assert!(validate_url("http://xn--bcher-kva.example.com/", &cfg()).is_err());
        assert!(validate_url("http://sub.xn--nxasmq6b.com/", &cfg()).is_err());
    }

    // ── Схема ─────────────────────────────────────────────────────────────────

    #[test]
    fn blocks_file_scheme() {
        assert!(validate_url("file:///etc/passwd", &cfg()).is_err());
    }

    #[test]
    fn blocks_ftp_scheme() {
        assert!(validate_url("ftp://example.com/file", &cfg()).is_err());
    }

    // ── Порты ─────────────────────────────────────────────────────────────────

    #[test]
    fn blocks_internal_ports() {
        assert!(validate_url("http://203.0.113.50:22/exploit", &cfg()).is_err());
        assert!(validate_url("http://203.0.113.50:6379/CONFIG", &cfg()).is_err());
    }

    // ── Allowlist ─────────────────────────────────────────────────────────────

    #[test]
    fn respects_allowlist_for_private_ip() {
        let mut config = cfg();
        config.allowlist.insert("10.0.0.5".into());
        assert!(validate_url("http://10.0.0.5:9090/api", &config).is_ok());
    }

    #[test]
    fn allowlist_does_not_bypass_scheme_check() {
        // Allowlist обходит IP-проверки, но схема проверяется до allowlist
        let mut config = cfg();
        config.allowlist.insert("10.0.0.5".into());
        assert!(validate_url("file://10.0.0.5/etc/passwd", &config).is_err());
    }

    // ── Blocklist ─────────────────────────────────────────────────────────────

    #[test]
    fn respects_blocklist() {
        let mut config = cfg();
        config.blocklist.insert("evil.example.com".into());
        assert!(validate_url("https://evil.example.com/hook", &config).is_err());
    }

    // ── RFC6598 CGN ───────────────────────────────────────────────────────────

    #[test]
    fn blocks_cgn_shared_space() {
        assert!(validate_url("http://100.64.0.1/api", &cfg()).is_err());
        assert!(validate_url("http://100.127.255.255/api", &cfg()).is_err());
    }

    // ── truncate_host ─────────────────────────────────────────────────────────

    #[test]
    fn truncate_host_short_unchanged() {
        assert_eq!(truncate_host("example.com"), "example.com");
    }

    #[test]
    fn truncate_host_long_truncated() {
        let long = "a".repeat(MAX_HOST_IN_ERR + 10);
        let r = truncate_host(&long);
        assert!(r.len() <= MAX_HOST_IN_ERR + 4); // +4 для "…"
        assert!(r.ends_with('…'));
    }

    // ── parse_octet ───────────────────────────────────────────────────────────

    #[test]
    fn parse_octet_decimal() {
        assert_eq!(parse_octet("255"), Some(255));
        assert_eq!(parse_octet("0"), Some(0));
    }

    #[test]
    fn parse_octet_hex() {
        assert_eq!(parse_octet("0xff"), Some(255));
        assert_eq!(parse_octet("0x7f"), Some(127));
    }

    #[test]
    fn parse_octet_octal() {
        assert_eq!(parse_octet("0177"), Some(127));
        assert_eq!(parse_octet("010"), Some(8));
    }

    #[test]
    fn parse_octet_invalid() {
        assert_eq!(parse_octet(""), None);
        assert_eq!(parse_octet("xyz"), None);
    }
}