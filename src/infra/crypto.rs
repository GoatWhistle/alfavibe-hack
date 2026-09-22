//! Криптография: AES-256-GCM шифрование mapping, HKDF-ключи сессий, HMAC-токены.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use sha2::{Sha256, Sha512};

use crate::domain::errors::VaultError;
use crate::domain::traits::EncryptedMapping;

type HmacSha256 = Hmac<Sha256>;

/// Мастер-ключ шифрования (32 байта).
pub struct MasterKey(Secret<Vec<u8>>);

impl MasterKey {
    pub fn from_base64(b64: &str) -> Result<Self, VaultError> {
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
            .map_err(|e| VaultError::Crypto(format!("invalid master key base64: {e}")))?;
        if bytes.len() != 32 {
            return Err(VaultError::Crypto("master key must be 32 bytes".into()));
        }
        Ok(MasterKey(Secret::new(bytes)))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        MasterKey(Secret::new(bytes.to_vec()))
    }

    /// Доступ к байтам ключа (для token-маскера).
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

/// Ключ сессии = HKDF-SHA256(master_key, salt=session_id, info=system_id).
fn session_key(master: &MasterKey, session_id: &str, system_id: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), master.0.expose_secret());
    let mut okm = [0u8; 32];
    hk.expand(system_id.as_bytes(), &mut okm)
        .expect("hkdf expand cannot fail for 32 bytes");
    okm
}

/// Шифрует mapping. AAD = system_id.
pub fn encrypt_mapping(
    master: &MasterKey,
    session_id: &str,
    system_id: &str,
    plaintext: &[u8],
) -> Result<EncryptedMapping, VaultError> {
    let key = session_key(master, session_id, system_id);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| VaultError::Crypto(format!("aes init: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: system_id.as_bytes(),
            },
        )
        .map_err(|e| VaultError::Crypto(format!("aes encrypt: {e}")))?;
    Ok(EncryptedMapping {
        nonce: nonce_bytes.to_vec(),
        ciphertext: ct,
    })
}

/// Расшифровывает mapping. AAD = system_id.
pub fn decrypt_mapping(
    master: &MasterKey,
    session_id: &str,
    system_id: &str,
    mapping: &EncryptedMapping,
) -> Result<Vec<u8>, VaultError> {
    let key = session_key(master, session_id, system_id);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| VaultError::Crypto(format!("aes init: {e}")))?;
    let nonce = Nonce::from_slice(&mapping.nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &mapping.ciphertext,
                aad: system_id.as_bytes(),
            },
        )
        .map_err(|_| VaultError::Crypto("aes decrypt failed (bad key or tampered)".into()))
}

/// HMAC-SHA256 токен для детерминированных масок (token-маскер).
pub fn hmac_token(secret: &[u8], data: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(data.as_bytes());
    let result = mac.finalize().into_bytes();
    hex8(&result)
}

/// Первые 8 hex символов SHA-256 (для логов session_id).
pub fn sha256_hex8(data: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex8(&result)
}

/// SHA-256 полный hex.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-512 (для хранения ключей систем).
pub fn sha512_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex8(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let master = MasterKey::from_bytes([7u8; 32]);
        let enc = encrypt_mapping(&master, "sess-1", "sys-1", b"hello").unwrap();
        let dec = decrypt_mapping(&master, "sess-1", "sys-1", &enc).unwrap();
        assert_eq!(dec, b"hello");
    }

    #[test]
    fn wrong_session_fails() {
        let master = MasterKey::from_bytes([7u8; 32]);
        let enc = encrypt_mapping(&master, "sess-1", "sys-1", b"hello").unwrap();
        assert!(decrypt_mapping(&master, "sess-2", "sys-1", &enc).is_err());
    }

    #[test]
    fn deterministic_token() {
        let a = hmac_token(b"secret", "FIO|иванов иван");
        let b = hmac_token(b"secret", "FIO|иванов иван");
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
    }
}