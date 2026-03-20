use crate::errors::AppError;

/// Resolve the base URL to use when building email links.
///
/// Rules:
/// - If `ALLOWED_APP_URLS` is **not configured** (empty slice), any caller-supplied
///   `app_url` is ignored and `fallback` (`APP_BASE_URL`) is always used. This keeps
///   single-tenant deployments secure with no extra configuration.
/// - If `ALLOWED_APP_URLS` **is configured**, a caller-supplied `app_url` must be
///   present in that list or the request is rejected with a 400. Omitting `app_url`
///   falls back to `APP_BASE_URL`.
pub fn resolve_app_url(
    requested: Option<&str>,
    allowed: &[String],
    fallback: &str,
) -> Result<String, AppError> {
    match requested {
        Some(url) if !allowed.is_empty() => {
            if allowed.iter().any(|a| a == url) {
                Ok(url.to_string())
            } else {
                Err(AppError::Validation(format!(
                    "app_url '{}' is not in the list of allowed URLs",
                    url
                )))
            }
        }
        // No allowlist configured — ignore caller-supplied URL.
        Some(_) | None => Ok(fallback.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(urls: &[&str]) -> Vec<String> {
        urls.iter().map(|s| s.to_string()).collect()
    }

    const FALLBACK: &str = "https://default.example.com";

    // --- allowlist not configured (empty) ---

    #[test]
    fn no_allowlist_no_request_returns_fallback() {
        let result = resolve_app_url(None, &[], FALLBACK).unwrap();
        assert_eq!(result, FALLBACK);
    }

    #[test]
    fn no_allowlist_ignores_requested_url() {
        // When ALLOWED_APP_URLS is not set, any app_url in the request is ignored.
        let result = resolve_app_url(Some("https://attacker.example.com"), &[], FALLBACK).unwrap();
        assert_eq!(result, FALLBACK);
    }

    // --- allowlist configured ---

    #[test]
    fn allowlist_accepts_listed_url() {
        let list = allowed(&["https://app1.example.com", "https://app2.example.com"]);
        let result = resolve_app_url(Some("https://app2.example.com"), &list, FALLBACK).unwrap();
        assert_eq!(result, "https://app2.example.com");
    }

    #[test]
    fn allowlist_rejects_unlisted_url() {
        let list = allowed(&["https://app1.example.com"]);
        let err = resolve_app_url(Some("https://evil.example.com"), &list, FALLBACK).unwrap_err();
        assert!(err.to_string().contains("not in the list of allowed URLs"));
    }

    #[test]
    fn allowlist_configured_no_request_returns_fallback() {
        let list = allowed(&["https://app1.example.com"]);
        let result = resolve_app_url(None, &list, FALLBACK).unwrap();
        assert_eq!(result, FALLBACK);
    }

    #[test]
    fn allowlist_with_multiple_entries_accepts_each() {
        let list = allowed(&["https://a.example.com", "https://b.example.com", "https://c.example.com"]);
        for url in &["https://a.example.com", "https://b.example.com", "https://c.example.com"] {
            let result = resolve_app_url(Some(url), &list, FALLBACK).unwrap();
            assert_eq!(&result, url);
        }
    }

    #[test]
    fn allowlist_match_is_exact_no_prefix_bypass() {
        // "https://app1.example.com.evil.com" must not match "https://app1.example.com"
        let list = allowed(&["https://app1.example.com"]);
        let err = resolve_app_url(
            Some("https://app1.example.com.evil.com"),
            &list,
            FALLBACK,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not in the list of allowed URLs"));
    }
}
