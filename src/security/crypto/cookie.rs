//! Cookie encryption and signing.
//!
//! Implements secure session storage using XChaCha20-Poly1305.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

#[derive(Clone)]
/// Cookie cryptography handler.
pub struct CookieCrypto {
    cipher: XChaCha20Poly1305,
}

impl CookieCrypto {
    #[must_use]
    /// New crypto from secret.
    pub fn new(secret: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let result = hasher.finalize();
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&result);

        Self {
            cipher: XChaCha20Poly1305::new(Key::from_slice(&master_key)),
        }
    }

    /// Encrypts data.
    ///
    /// # Errors
    /// Returns an error if XChaCha20-Poly1305 encryption fails.
    pub fn try_encrypt(&self, plaintext: &[u8]) -> Result<String> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| Error::Crypto("XChaCha20-Poly1305 encryption failed".to_string()))?;

        let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(URL_SAFE_NO_PAD.encode(&combined))
    }

    #[must_use]
    /// Decrypts data.
    pub fn decrypt(&self, encoded: &str) -> Option<Vec<u8>> {
        let combined = URL_SAFE_NO_PAD.decode(encoded).ok()?;

        if combined.len() < NONCE_LEN + TAG_LEN + 1 {
            return None;
        }

        let nonce_slice = combined.get(0..NONCE_LEN)?;
        let ciphertext = combined.get(NONCE_LEN..)?;

        let nonce = XNonce::from_slice(nonce_slice);

        self.cipher.decrypt(nonce, ciphertext).ok()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_integrity() {
        let cc = CookieCrypto::new("master-secret-key");
        let pt = b"session_id|circuit_id|1700000000|0|0|0";

        let enc = cc.try_encrypt(pt).unwrap();
        let dec = cc.decrypt(&enc).unwrap();
        assert_eq!(dec, pt);

        let enc2 = cc.try_encrypt(pt).unwrap();
        assert_ne!(enc, enc2);

        let mut tampered = enc.as_bytes().to_vec();
        if let Some(byte) = tampered.get_mut(enc.len() / 2) {
            *byte ^= 0xFF;
        }
        let tampered_str = String::from_utf8_lossy(&tampered).to_string();
        assert!(cc.decrypt(&tampered_str).is_none());

        let truncated = enc.get(..enc.len() / 2).unwrap();
        assert!(cc.decrypt(truncated).is_none());

        let cc2 = CookieCrypto::new("alternative-secret-key");
        assert!(cc2.decrypt(&enc).is_none());

        assert!(cc.decrypt("").is_none());
        assert!(cc.decrypt("invalid-base64-data").is_none());
    }
}
