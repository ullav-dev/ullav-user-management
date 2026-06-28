pub mod app_url;
pub mod email;
pub mod jwt;
pub mod key_encrypt;
pub mod key_store;
pub mod password;
pub mod rate_limit;
pub mod rs256;

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
