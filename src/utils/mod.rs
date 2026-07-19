pub mod app_url;
pub mod email;
pub mod jwt;
pub mod key_encrypt;
pub mod key_store;
pub mod password;
pub mod rate_limit;
pub mod rs256;
pub mod token;

/// Check an internal-service shared-secret header (e.g. the header lagan-server
/// sends when calling `/pat/exchange` or `/ssh-keys/resolve`) against the
/// configured expected value.
///
/// When `configured` is `None` (the env var isn't set), the gate is open —
/// acceptable for local/dev, but any production deployment exposing these
/// endpoints on a reachable network must set the corresponding secret.
pub fn check_service_secret(
    configured: &Option<String>,
    provided: Option<&str>,
) -> Result<(), crate::errors::AppError> {
    match (configured, provided) {
        (None, _) => Ok(()),
        (Some(expected), Some(got)) if expected == got => Ok(()),
        _ => Err(crate::errors::AppError::Forbidden),
    }
}

/// Resolve a secret value, preferring the Docker-secrets `_FILE` convention.
///
/// If `{name}_FILE` is set, the file at that path is read and its contents
/// trimmed (Docker writes a trailing newline). Falls back to the plain `{name}`
/// env var. Returns `None` when neither is present.
pub fn resolve_secret(name: &str) -> Option<String> {
    let file_key = format!("{name}_FILE");
    if let Ok(path) = std::env::var(&file_key) {
        match std::fs::read_to_string(&path) {
            Ok(contents) => return Some(contents.trim().to_string()),
            Err(e) => log::warn!(
                "{file_key} points to {path:?} but the file could not be read: {e} — falling back to {name}"
            ),
        }
    }
    std::env::var(name).ok()
}
