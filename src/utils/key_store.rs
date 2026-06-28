/// OAuth2 signing key store startup logic.
///
/// At startup, this module decides where to load signing keys from:
///
/// 1. If `OAUTH2_KEY_ENCRYPTION_KEY` is set → DB-backed mode:
///    - Load all active keys from `oauth2_signing_keys`.
///    - If the table is empty and `OAUTH2_SIGNING_KEY` is set → import it as the primary key.
///    - If the table is empty and `OAUTH2_SIGNING_KEY` is not set → generate a new key.
///
/// 2. If `OAUTH2_KEY_ENCRYPTION_KEY` is NOT set → single-key mode (Phase 1 compat):
///    - Load the single key from `OAUTH2_SIGNING_KEY` env var (or `_FILE` variant).
///    - No DB interaction.
use deadpool_postgres::Pool;

use crate::{
    db::oauth2 as db_oauth2,
    errors::{AppError, AppResult},
    utils::{
        key_encrypt::KeyEncryptionKey,
        rs256::{jwks_for_keys, RsaKeyPair},
    },
};

/// Loaded signing keys, ready for use.
#[derive(Clone)]
pub struct KeyStore {
    /// All active (non-retired) signing keys — used to build the JWKS endpoint response.
    pub keys: Vec<RsaKeyPair>,
    /// The kid of the key that should be used to sign new tokens.
    pub primary_kid: String,
}

impl KeyStore {
    /// Find the primary key pair by kid.
    pub fn primary_key(&self) -> &RsaKeyPair {
        self.keys
            .iter()
            .find(|k| k.kid() == self.primary_kid)
            .expect("primary_kid must be present in keys")
    }

    /// Build the full JWKS document including all active keys.
    pub fn jwks(&self) -> serde_json::Value {
        jwks_for_keys(&self.keys)
    }
}

/// Initialise the key store at startup. Reads env vars and optionally the database.
pub async fn init_key_store(pool: &Pool) -> AppResult<KeyStore> {
    let kek_b64 = std::env::var("OAUTH2_KEY_ENCRYPTION_KEY").ok();

    if let Some(ref kek_b64) = kek_b64 {
        init_db_backed(pool, kek_b64).await
    } else {
        init_single_key()
    }
}

fn init_single_key() -> AppResult<KeyStore> {
    let pem = super::resolve_secret("OAUTH2_SIGNING_KEY")
        .ok_or_else(|| AppError::Internal(
            "Neither OAUTH2_KEY_ENCRYPTION_KEY nor OAUTH2_SIGNING_KEY is set".into(),
        ))?;
    let key = RsaKeyPair::from_pem(&pem)?;
    let kid = key.kid().to_owned();
    log::info!("OAuth2: single-key mode — kid: {kid}");
    Ok(KeyStore { keys: vec![key], primary_kid: kid })
}

async fn init_db_backed(pool: &Pool, kek_b64: &str) -> AppResult<KeyStore> {
    let kek = KeyEncryptionKey::from_base64(kek_b64)?;
    let rows = db_oauth2::load_active_signing_keys(pool).await?;

    if rows.is_empty() {
        return seed_first_key(pool, &kek).await;
    }

    let mut keys = Vec::new();
    let mut primary_kid = None;

    for row in rows {
        let pem = kek.decrypt(&row.key_pem_enc, &row.nonce)?;
        let pair = RsaKeyPair::from_pem(&pem)?;
        if row.is_primary {
            primary_kid = Some(pair.kid().to_owned());
        }
        keys.push(pair);
    }

    let primary_kid = primary_kid.ok_or_else(|| AppError::Internal(
        "No primary OAuth2 signing key found in database — promote one with the admin API".into(),
    ))?;

    log::info!(
        "OAuth2: DB-backed key mode — {} active key(s), primary kid: {}",
        keys.len(),
        primary_kid
    );

    Ok(KeyStore { keys, primary_kid })
}

async fn seed_first_key(pool: &Pool, kek: &KeyEncryptionKey) -> AppResult<KeyStore> {
    let (pair, pem) = match super::resolve_secret("OAUTH2_SIGNING_KEY") {
        Some(env_pem) => {
            let p = RsaKeyPair::from_pem(&env_pem)?;
            log::info!("OAuth2: importing OAUTH2_SIGNING_KEY into DB — kid: {}", p.kid());
            (p, env_pem)
        }
        None => {
            log::info!("OAuth2: generating new RSA-2048 signing key");
            RsaKeyPair::generate()?
        }
    };

    let kid = pair.kid().to_owned();
    let (enc, nonce) = kek.encrypt(pem.trim())?;
    db_oauth2::store_signing_key(pool, &kid, &enc, &nonce, true).await?;
    log::info!("OAuth2: primary key stored in DB — kid: {kid}");

    Ok(KeyStore { keys: vec![pair], primary_kid: kid })
}
