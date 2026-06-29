use base64ct::{Base64UrlUnpadded, Encoding};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Algorithm};
use rsa::{
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
    traits::PublicKeyParts,
    RsaPrivateKey,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::errors::AppError;

/// Loaded RSA-2048 signing key with precomputed JWKS document and kid.
#[derive(Clone)]
pub struct RsaKeyPair {
    inner: Arc<Inner>,
}

struct Inner {
    encoding_key: EncodingKey,
    /// Base64url-encoded public key modulus (n).
    pub_n: String,
    /// Base64url-encoded public key exponent (e).
    pub_e: String,
    /// Key identifier — SHA-256 of DER-encoded public key, first 16 hex chars.
    kid: String,
}

impl RsaKeyPair {
    /// Generate a new RSA-2048 key pair. Returns the pair and its PKCS#8 PEM.
    pub fn generate() -> Result<(Self, String), AppError> {
        use rand_core::OsRng;
        let key = RsaPrivateKey::new(&mut OsRng, 2048)
            .map_err(|e| AppError::Internal(format!("RSA key generation failed: {e}")))?;
        let pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| AppError::Internal(format!("failed to encode generated key: {e}")))?
            .to_string();
        let pair = Self::from_rsa_private_key(pem.trim(), key)?;
        Ok((pair, pem))
    }

    /// Load from a PKCS#8 or PKCS#1 PEM string.
    pub fn from_pem(pem: &str) -> Result<Self, AppError> {
        let pem_trimmed = pem.trim();

        let private_key = if pem_trimmed.contains("BEGIN RSA PRIVATE KEY") {
            RsaPrivateKey::from_pkcs1_pem(pem_trimmed)
                .map_err(|e| AppError::Validation(format!("invalid RSA PKCS#1 PEM: {e}")))?
        } else {
            RsaPrivateKey::from_pkcs8_pem(pem_trimmed)
                .map_err(|e| AppError::Validation(format!("invalid RSA PKCS#8 PEM: {e}")))?
        };

        Self::from_rsa_private_key(pem_trimmed, private_key)
    }

    fn from_rsa_private_key(pem: &str, key: RsaPrivateKey) -> Result<Self, AppError> {
        let pub_key = key.to_public_key();

        let n_bytes = pub_key.n().to_bytes_be();
        let e_bytes = pub_key.e().to_bytes_be();

        let pub_n = Base64UrlUnpadded::encode_string(&n_bytes);
        let pub_e = Base64UrlUnpadded::encode_string(&e_bytes);

        // kid: first 16 hex chars of SHA-256 of the concatenated n||e bytes
        let mut hasher = Sha256::new();
        hasher.update(&n_bytes);
        hasher.update(&e_bytes);
        let digest = hasher.finalize();
        let kid = hex::encode(&digest[..8]);

        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| AppError::Validation(format!("jsonwebtoken rejected RSA PEM: {e}")))?;

        Ok(Self {
            inner: Arc::new(Inner { encoding_key, pub_n, pub_e, kid }),
        })
    }

    pub fn kid(&self) -> &str {
        &self.inner.kid
    }

    pub fn encoding_key(&self) -> &EncodingKey {
        &self.inner.encoding_key
    }

    /// Build a [`DecodingKey`] for validating RS256 tokens signed with this key pair.
    pub fn decoding_key(&self) -> Result<DecodingKey, crate::errors::AppError> {
        DecodingKey::from_rsa_components(&self.inner.pub_n, &self.inner.pub_e)
            .map_err(|e| crate::errors::AppError::Internal(
                format!("failed to build RS256 decoding key: {e}")
            ))
    }

    /// A JWT `Header` with alg=RS256 and the correct kid.
    pub fn jwt_header(&self) -> Header {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some(self.inner.kid.clone());
        h
    }

    /// A single JWK entry (without the `keys` wrapper) for building multi-key JWKS.
    pub fn jwk_entry(&self) -> Value {
        json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.inner.kid,
            "n":   self.inner.pub_n,
            "e":   self.inner.pub_e,
        })
    }

    /// The full JWKS document (`{"keys": [...]}`) for a single key.
    pub fn jwks(&self) -> Value {
        json!({ "keys": [self.jwk_entry()] })
    }
}

/// Build a multi-key JWKS document from a slice of key pairs.
pub fn jwks_for_keys(keys: &[RsaKeyPair]) -> Value {
    json!({ "keys": keys.iter().map(|k| k.jwk_entry()).collect::<Vec<_>>() })
}
