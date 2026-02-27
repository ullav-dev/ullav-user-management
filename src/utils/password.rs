use crate::errors::AppError;
use argon2::{self, Config as Argon2Config, ThreadMode, Variant, Version};
use rand::RngCore;

/// Hash a plain-text password using Argon2id.
pub fn hash_password(password: &str) -> Result<String, AppError> {
    let mut salt = [0u8; 32];
    rand::rng().fill_bytes(&mut salt);

    let config = Argon2Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: 65536,
        time_cost: 3,
        lanes: 4,
        thread_mode: ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };

    argon2::hash_encoded(password.as_bytes(), &salt, &config)
        .map_err(|e| AppError::Hashing(e.to_string()))
}

/// Verify a plain-text password against a stored Argon2 hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
    argon2::verify_encoded(hash, password.as_bytes())
        .map_err(|e| AppError::Hashing(e.to_string()))
}

/// Generate a cryptographically secure random hex token.
pub fn generate_secure_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Validate that a password meets minimum requirements.
pub fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < 8 {
        return Err(AppError::Validation(
            "password must be at least 8 characters".into(),
        ));
    }
    Ok(())
}
