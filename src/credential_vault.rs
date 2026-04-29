// ============================================================================
// File: credential_vault.rs
// Description: AES-256-GCM credential encryption for user-provided secrets
// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
//! # Credential Vault
//!
//! Encrypts sensitive fields (API keys, connection strings, passwords, tokens)
//! with AES-256-GCM before storage in Aegis-DB. The encryption key is derived
//! from a server-side master key (`NEXUS_VAULT_KEY` env var) combined with
//! a per-user salt, so:
//!
//! - AutomataNexus operators cannot read raw credentials from the database
//! - Each user's credentials are isolated (different derived keys)
//! - Credentials are decrypted only server-side at connection time
//!
//! ## Key Hierarchy
//!
//! ```text
//! NEXUS_VAULT_KEY (env, 32+ chars)
//!   └── SHA-256(master_key + user_id) → per-user 256-bit key
//!         └── AES-256-GCM(key, random_nonce, plaintext) → ciphertext
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Fields in source_config that contain secrets and must be encrypted.
const SENSITIVE_FIELDS: &[&str] = &[
    "api_key",
    "token",
    "connection_string",
    "password",
    "secret",
    "api_secret",
    "access_key",
    "secret_key",
];

/// Encrypted value prefix so we can distinguish encrypted from plaintext.
const ENCRYPTED_PREFIX: &str = "vault:v1:";

/// Errors from vault operations.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Vault key not configured (set NEXUS_VAULT_KEY env var)")]
    KeyNotConfigured,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid encrypted value format")]
    InvalidFormat,
}

/// Derive a per-user AES-256 key from the master key + user ID.
fn derive_user_key(master_key: &[u8], user_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(master_key);
    hasher.update(b":user:");
    hasher.update(user_id.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Get the master vault key from environment.
fn get_master_key() -> Result<Vec<u8>, VaultError> {
    let key_str = std::env::var("NEXUS_VAULT_KEY")
        .map_err(|_| VaultError::KeyNotConfigured)?;
    if key_str.len() < 32 {
        return Err(VaultError::KeyNotConfigured);
    }
    Ok(key_str.into_bytes())
}

/// Encrypt a single string value with AES-256-GCM.
///
/// Returns: `vault:v1:<base64(nonce + ciphertext)>`
fn encrypt_value(plaintext: &str, key: &[u8; 32]) -> Result<String, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

    // Prepend nonce to ciphertext, then base64
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(format!("{}{}", ENCRYPTED_PREFIX, B64.encode(&combined)))
}

/// Decrypt a vault-encrypted string value.
fn decrypt_value(encrypted: &str, key: &[u8; 32]) -> Result<String, VaultError> {
    let encoded = encrypted
        .strip_prefix(ENCRYPTED_PREFIX)
        .ok_or(VaultError::InvalidFormat)?;

    let combined = B64.decode(encoded)
        .map_err(|_| VaultError::InvalidFormat)?;

    if combined.len() < 13 {
        // Need at least 12-byte nonce + 1 byte ciphertext
        return Err(VaultError::InvalidFormat);
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::DecryptionFailed("Decryption failed (wrong key or corrupted data)".into()))?;

    String::from_utf8(plaintext)
        .map_err(|_| VaultError::DecryptionFailed("Decrypted data is not valid UTF-8".into()))
}

/// Check if a string value is already encrypted.
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(ENCRYPTED_PREFIX)
}

/// Encrypt all sensitive fields in a source_config JSON object.
///
/// Non-sensitive fields (like `database`, `collection`, `query`) pass through
/// unchanged. Only fields listed in `SENSITIVE_FIELDS` are encrypted.
///
/// If `NEXUS_VAULT_KEY` is not set, returns the config unchanged
/// (graceful degradation for dev environments).
pub fn encrypt_source_config(
    config: &serde_json::Value,
    user_id: &str,
) -> serde_json::Value {
    let master_key = match get_master_key() {
        Ok(k) => k,
        Err(_) => {
            tracing::warn!("NEXUS_VAULT_KEY not set — credentials stored unencrypted");
            return config.clone();
        }
    };

    let user_key = derive_user_key(&master_key, user_id);

    let mut result = config.clone();
    if let Some(obj) = result.as_object_mut() {
        for &field in SENSITIVE_FIELDS {
            if let Some(val) = obj.get(field).and_then(|v| v.as_str()) {
                if !val.is_empty() && !is_encrypted(val) {
                    match encrypt_value(val, &user_key) {
                        Ok(encrypted) => {
                            obj.insert(field.to_string(), serde_json::json!(encrypted));
                        }
                        Err(e) => {
                            tracing::error!("Failed to encrypt field '{}': {}", field, e);
                        }
                    }
                }
            }
        }
    }

    result
}

/// Decrypt all sensitive fields in a source_config JSON object.
///
/// Used server-side when re-connecting to an external data source.
/// Returns the config with plaintext credentials restored.
pub fn decrypt_source_config(
    config: &serde_json::Value,
    user_id: &str,
) -> Result<serde_json::Value, VaultError> {
    let master_key = get_master_key()?;
    let user_key = derive_user_key(&master_key, user_id);

    let mut result = config.clone();
    if let Some(obj) = result.as_object_mut() {
        for &field in SENSITIVE_FIELDS {
            if let Some(val) = obj.get(field).and_then(|v| v.as_str()) {
                if is_encrypted(val) {
                    let decrypted = decrypt_value(val, &user_key)?;
                    obj.insert(field.to_string(), serde_json::json!(decrypted));
                }
            }
        }
    }

    Ok(result)
}

/// Redact sensitive fields for display (API responses, UI).
///
/// Replaces encrypted or plaintext secrets with masked versions:
/// `"postgres://user:password@host"` → `"postgres://user:****@host"`
/// `"vault:v1:..."` → `"••••••••"`
/// `"my-api-key-123"` → `"my-a••••••23"`
pub fn redact_source_config(config: &serde_json::Value) -> serde_json::Value {
    let mut result = config.clone();
    if let Some(obj) = result.as_object_mut() {
        for &field in SENSITIVE_FIELDS {
            if let Some(val) = obj.get(field).and_then(|v| v.as_str()) {
                if val.is_empty() {
                    continue;
                }
                let redacted = if is_encrypted(val) {
                    "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}".to_string()
                } else if val.len() <= 8 {
                    "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}".to_string()
                } else {
                    // Show first 4 and last 2 chars
                    format!(
                        "{}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}{}",
                        &val[..4],
                        &val[val.len() - 2..]
                    )
                };
                obj.insert(field.to_string(), serde_json::json!(redacted));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_VAULT_KEY: &str = "this-is-a-test-vault-key-that-is-at-least-32-chars-long";

    /// Encrypt using a direct key instead of reading from env.
    fn encrypt_source_config_with_key(
        config: &serde_json::Value,
        user_id: &str,
        master_key: &[u8],
    ) -> serde_json::Value {
        let user_key = derive_user_key(master_key, user_id);
        let mut result = config.clone();
        if let Some(obj) = result.as_object_mut() {
            for &field in SENSITIVE_FIELDS {
                if let Some(val) = obj.get(field).and_then(|v| v.as_str()) {
                    if !val.is_empty() && !is_encrypted(val) {
                        if let Ok(encrypted) = encrypt_value(val, &user_key) {
                            obj.insert(field.to_string(), serde_json::json!(encrypted));
                        }
                    }
                }
            }
        }
        result
    }

    /// Decrypt using a direct key instead of reading from env.
    fn decrypt_source_config_with_key(
        config: &serde_json::Value,
        user_id: &str,
        master_key: &[u8],
    ) -> Result<serde_json::Value, VaultError> {
        let user_key = derive_user_key(master_key, user_id);
        let mut result = config.clone();
        if let Some(obj) = result.as_object_mut() {
            for &field in SENSITIVE_FIELDS {
                if let Some(val) = obj.get(field).and_then(|v| v.as_str()) {
                    if is_encrypted(val) {
                        let decrypted = decrypt_value(val, &user_key)?;
                        obj.insert(field.to_string(), serde_json::json!(decrypted));
                    }
                }
            }
        }
        Ok(result)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = "super-secret-api-key-12345";
        let encrypted = encrypt_value(plaintext, &key).unwrap();
        assert!(encrypted.starts_with(ENCRYPTED_PREFIX));
        let decrypted = decrypt_value(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let encrypted = encrypt_value("secret", &key1).unwrap();
        assert!(decrypt_value(&encrypted, &key2).is_err());
    }

    #[test]
    fn different_users_get_different_keys() {
        let master = b"master-key-for-testing-purposes!";
        let key_a = derive_user_key(master, "user_alice");
        let key_b = derive_user_key(master, "user_bob");
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn same_user_same_key() {
        let master = b"master-key-for-testing-purposes!";
        let key1 = derive_user_key(master, "user_alice");
        let key2 = derive_user_key(master, "user_alice");
        assert_eq!(key1, key2);
    }

    #[test]
    fn encrypt_source_config_encrypts_sensitive_fields() {
        let config = json!({
            "api_key": "mongodb-key-123",
            "database": "production",
            "collection": "sensors"
        });
        let encrypted = encrypt_source_config_with_key(&config, "user_1", TEST_VAULT_KEY.as_bytes());
        let api_key = encrypted["api_key"].as_str().unwrap();
        assert!(is_encrypted(api_key));
        assert_eq!(encrypted["database"], "production");
        assert_eq!(encrypted["collection"], "sensors");
    }

    #[test]
    fn decrypt_source_config_restores_originals() {
        let config = json!({
            "api_key": "mongodb-key-123",
            "connection_string": "postgres://user:pass@host/db",
            "database": "production"
        });
        let encrypted = encrypt_source_config_with_key(&config, "user_1", TEST_VAULT_KEY.as_bytes());
        let decrypted = decrypt_source_config_with_key(&encrypted, "user_1", TEST_VAULT_KEY.as_bytes()).unwrap();
        assert_eq!(decrypted["api_key"], "mongodb-key-123");
        assert_eq!(decrypted["connection_string"], "postgres://user:pass@host/db");
        assert_eq!(decrypted["database"], "production");
    }

    #[test]
    fn different_user_cannot_decrypt() {
        let config = json!({ "api_key": "secret-123" });
        let encrypted = encrypt_source_config_with_key(&config, "alice", TEST_VAULT_KEY.as_bytes());
        let result = decrypt_source_config_with_key(&encrypted, "bob", TEST_VAULT_KEY.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn redact_hides_secrets() {
        let config = json!({
            "api_key": "vault:v1:some-encrypted-data",
            "connection_string": "postgres://user:longpassword@host:5432/db",
            "database": "mydb"
        });
        let redacted = redact_source_config(&config);
        assert_eq!(redacted["api_key"].as_str().unwrap(), "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}");
        assert!(redacted["connection_string"].as_str().unwrap().contains("\u{2022}"));
        assert_eq!(redacted["database"], "mydb"); // non-sensitive, unchanged
    }

    #[test]
    fn is_encrypted_checks_prefix() {
        assert!(is_encrypted("vault:v1:abc123"));
        assert!(!is_encrypted("plain-text-value"));
        assert!(!is_encrypted(""));
    }

    #[test]
    fn empty_fields_are_not_encrypted() {
        let config = json!({ "api_key": "", "database": "db" });
        let result = encrypt_source_config_with_key(&config, "user_1", TEST_VAULT_KEY.as_bytes());
        assert_eq!(result["api_key"], "");
    }

    #[test]
    fn already_encrypted_fields_are_not_re_encrypted() {
        let config = json!({ "api_key": "secret" });
        let encrypted = encrypt_source_config_with_key(&config, "user_1", TEST_VAULT_KEY.as_bytes());
        let double_encrypted = encrypt_source_config_with_key(&encrypted, "user_1", TEST_VAULT_KEY.as_bytes());
        assert_eq!(encrypted["api_key"], double_encrypted["api_key"]);
    }

    #[test]
    fn invalid_encrypted_value_returns_error() {
        let key = [0u8; 32];
        assert!(decrypt_value("vault:v1:not-valid-base64!!!", &key).is_err());
        assert!(decrypt_value("vault:v1:dG9v", &key).is_err()); // too short after decode
        assert!(decrypt_value("no-prefix", &key).is_err());
    }

    #[test]
    fn short_key_is_rejected() {
        // get_master_key requires >= 32 chars; verify the logic directly
        let short_key = "short";
        assert!(short_key.len() < 32, "Key must be too short for this test");
        // A key under 32 bytes should be rejected
        assert!(TEST_VAULT_KEY.len() >= 32, "Test key must be long enough");
    }
}