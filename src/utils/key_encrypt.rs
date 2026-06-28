/// AES-256-GCM encryption helpers for OAuth2 signing key storage.
///
/// Each key PEM is encrypted independently with a randomly generated 12-byte nonce.
/// The master key (`OAUTH2_KEY_ENCRYPTION_KEY`) is a 32-byte value, base64-encoded.
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64ct::{Base64, Encoding};
use crate::errors::{AppError, AppResult};

pub struct KeyEncryptionKey {
    cipher: Aes256Gcm,
}

impl KeyEncryptionKey {
    /// Decode the base64-encoded 32-byte master key from an env-var string.
    pub fn from_base64(b64: &str) -> AppResult<Self> {
        let bytes = Base64::decode_vec(b64.trim())
            .map_err(|e| AppError::Internal(format!("OAUTH2_KEY_ENCRYPTION_KEY is not valid base64: {e}")))?;
        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AppError::Internal(
                "OAUTH2_KEY_ENCRYPTION_KEY must decode to exactly 32 bytes".into(),
            ))?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        Ok(Self { cipher: Aes256Gcm::new(key) })
    }

    /// Encrypt a PEM string. Returns (ciphertext, nonce).
    pub fn encrypt(&self, pem: &str) -> AppResult<(Vec<u8>, Vec<u8>)> {
        use aes_gcm::aead::rand_core::RngCore;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self.cipher.encrypt(nonce, pem.as_bytes())
            .map_err(|e| AppError::Internal(format!("key encryption failed: {e}")))?;
        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    /// Decrypt ciphertext using the stored nonce. Returns the PEM string.
    pub fn decrypt(&self, ciphertext: &[u8], nonce_bytes: &[u8]) -> AppResult<String> {
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self.cipher.decrypt(nonce, ciphertext)
            .map_err(|e| AppError::Internal(format!("key decryption failed: {e}")))?;
        String::from_utf8(plaintext)
            .map_err(|e| AppError::Internal(format!("decrypted key is not valid UTF-8: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> KeyEncryptionKey {
        // 32 zero bytes, standard base64-encoded — test only, no security value.
        KeyEncryptionKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .expect("test KEK should load")
    }

    #[test]
    fn round_trip_encrypt_decrypt() {
        let kek = test_kek();
        let pem = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----";
        let (ct, nonce) = kek.encrypt(pem).unwrap();
        let recovered = kek.decrypt(&ct, &nonce).unwrap();
        assert_eq!(recovered, pem);
    }

    #[test]
    fn different_encryptions_of_same_pem_differ() {
        let kek = test_kek();
        let pem = "test pem";
        let (ct1, nonce1) = kek.encrypt(pem).unwrap();
        let (ct2, nonce2) = kek.encrypt(pem).unwrap();
        assert_ne!(nonce1, nonce2);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let kek = test_kek();
        let (mut ct, nonce) = kek.encrypt("secret pem").unwrap();
        ct[0] ^= 0xFF;
        assert!(kek.decrypt(&ct, &nonce).is_err());
    }

    #[test]
    fn from_base64_rejects_wrong_length() {
        // 31 bytes → too short
        let b64_31 = Base64::encode_string(&[0u8; 31]);
        assert!(KeyEncryptionKey::from_base64(&b64_31).is_err());
    }
}
