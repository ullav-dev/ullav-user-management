//! OAuth2 Authorization Server endpoints.
//!
//! Implements:
//! - RFC 6749  — OAuth 2.0
//! - RFC 7636  — PKCE (S256 only)
//! - RFC 7591  — Dynamic Client Registration
//! - RFC 7009  — Token Revocation
//! - RFC 8414  — Authorization Server Metadata
//! - RFC 8707  — Resource Indicators (audience binding)
//! - draft-ietf-oauth-client-id-metadata-document — CIMD (for Claude Desktop/Code)

use crate::{
    db,
    errors::AppError,
    utils::jwt::{build_identity_claims, SubscriptionClaim, TeamClaim},
    AppState,
};
use actix_web::{
    cookie::{Cookie, SameSite},
    get, post,
    web::{self, Form, Json, Query},
    HttpRequest, HttpResponse,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{Duration, Utc};
use jsonwebtoken::encode;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url::Url;
use uuid::Uuid;

// ── Config constants ──────────────────────────────────────────────────────────

const AUTH_CODE_TTL_MINUTES: i64 = 10;
const ACCESS_TOKEN_TTL_SECONDS: i64 = 3600;
const REFRESH_TOKEN_TTL_DAYS: i64 = 30;
const SESSION_TTL_DAYS: i64 = 30;
const SESSION_COOKIE_NAME: &str = "ullav_session";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn secure_hex_token(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn sha256_hex(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    hex::encode(h.finalize())
}

fn session_token_from_req(req: &HttpRequest) -> Option<String> {
    req.cookie(SESSION_COOKIE_NAME).map(|c| c.value().to_owned())
}

fn make_session_cookie(raw: &str) -> Cookie<'static> {
    Cookie::build(SESSION_COOKIE_NAME, raw.to_owned())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(actix_web::cookie::time::Duration::days(SESSION_TTL_DAYS))
        .finish()
}

/// RFC 8252 §7.3 loopback redirect URI matching.
///
/// `pub(crate)` so unit tests in `src/tests.rs` can call it directly.
///
/// For `http://localhost` and `http://127.0.0.1` URIs, the port is ignored and
/// only the path is compared.  All other URIs require an exact string match.
pub(crate) fn redirect_uri_allowed(client_uris: &[String], requested: &str) -> bool {
    let Ok(req_url) = Url::parse(requested) else { return false; };
    let is_loopback = req_url.scheme() == "http"
        && matches!(req_url.host_str(), Some("localhost") | Some("127.0.0.1"));

    for registered in client_uris {
        if is_loopback {
            let Ok(reg_url) = Url::parse(registered) else { continue };
            let reg_is_loopback = reg_url.scheme() == "http"
                && matches!(reg_url.host_str(), Some("localhost") | Some("127.0.0.1"));
            if reg_is_loopback && reg_url.path() == req_url.path() {
                return true;
            }
        } else if req_url.scheme() == "https" && registered == requested {
            return true;
        }
    }
    false
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#x27;")
}

// ── OAuth2 RS256 JWT claims ───────────────────────────────────────────────────

/// `pub(crate)` (rather than private) so `src/tests.rs` can construct/decode it directly.
#[derive(Serialize, Deserialize)]
pub(crate) struct OAuth2Claims {
    pub(crate) iss: String,
    pub(crate) sub: String,
    pub(crate) aud: String,
    pub(crate) iat: i64,
    pub(crate) exp: i64,
    pub(crate) scope: String,
    pub(crate) client_id: String,
    pub(crate) username: String,
    /// Roles assigned to the user. Defaults to empty so tokens minted before this
    /// field was added still decode.
    #[serde(default)]
    pub(crate) roles: Vec<String>,
    /// Active subscriptions keyed by product slug. Defaults to an empty map so
    /// tokens minted before this field was added still decode.
    #[serde(default)]
    pub(crate) subscriptions: HashMap<String, SubscriptionClaim>,
    /// Active team memberships keyed by team UUID string. Defaults to an empty map
    /// so tokens minted before this field was added still decode.
    #[serde(default)]
    pub(crate) teams: HashMap<String, TeamClaim>,
}

async fn mint_access_token(
    state: &AppState,
    user_id: Uuid,
    username: &str,
    scope: &str,
    resource: &str,
    client_id: &str,
) -> Result<String, AppError> {
    // Embed the same identity data `/auth/login` embeds, so MCP resource servers
    // can apply the same plan-based quota/access logic as the REST APIs.
    let (roles, _permissions, subscriptions, teams) =
        build_identity_claims(&state.pool, user_id).await?;

    let now = Utc::now();
    let claims = OAuth2Claims {
        iss: state.oauth2_issuer.clone(),
        sub: user_id.to_string(),
        aud: resource.to_owned(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(ACCESS_TOKEN_TTL_SECONDS)).timestamp(),
        scope: scope.to_owned(),
        client_id: client_id.to_owned(),
        username: username.to_owned(),
        roles,
        subscriptions,
        teams,
    };
    let keys = state.oauth2_keys.read().await;
    let signing_key = keys.primary_key();
    encode(&signing_key.jwt_header(), &claims, signing_key.encoding_key())
        .map_err(|e| AppError::Jwt(e.to_string()))
}

fn token_json_response(access_token: &str, scope: &str, refresh_token: Option<&str>) -> HttpResponse {
    let mut body = serde_json::json!({
        "access_token": access_token,
        "token_type":   "Bearer",
        "expires_in":   ACCESS_TOKEN_TTL_SECONDS,
        "scope":        scope,
    });
    if let Some(rt) = refresh_token {
        body["refresh_token"] = serde_json::Value::String(rt.to_owned());
    }
    HttpResponse::Ok()
        .content_type("application/json")
        .append_header(("Cache-Control", "no-store"))
        .json(body)
}

// ── JWKS ──────────────────────────────────────────────────────────────────────

/// `GET /oauth2/jwks` — Public JWKS document (unauthenticated).
#[get("/oauth2/jwks")]
pub async fn jwks(state: web::Data<AppState>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/json")
        .json(state.oauth2_keys.read().await.jwks())
}

// ── AS Metadata (RFC 8414) ────────────────────────────────────────────────────

/// `GET /.well-known/oauth-authorization-server`
#[get("/.well-known/oauth-authorization-server")]
pub async fn as_metadata(state: web::Data<AppState>) -> HttpResponse {
    let iss = &state.oauth2_issuer;
    HttpResponse::Ok()
        .content_type("application/json")
        .json(serde_json::json!({
            "issuer":                                iss,
            "authorization_endpoint":                format!("{iss}/oauth2/authorize"),
            "token_endpoint":                        format!("{iss}/oauth2/token"),
            "jwks_uri":                              format!("{iss}/oauth2/jwks"),
            "registration_endpoint":                 format!("{iss}/oauth2/register"),
            "revocation_endpoint":                   format!("{iss}/oauth2/revoke"),
            "response_types_supported":              ["code"],
            "grant_types_supported":                 ["authorization_code", "refresh_token", "client_credentials"],
            "code_challenge_methods_supported":      ["S256"],
            // "none" — existing public/DCR clients (PKCE only, e.g. Claude Desktop/Code).
            // "client_secret_post" — confidential service clients using client_credentials.
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            "scopes_supported":                      ["mcp:tools", "obair:tools", "cunav:tools", "dam:tools", "collection:tools"],
            "subject_types_supported":               ["public"],
        }))
}

// ── Product access gate ───────────────────────────────────────────────────────

/// Maps a resource URI to the product scope that should be stamped in the
/// access token when the user is entitled.  Returns `None` for resources that
/// have no product gate.
///
/// Unique paths win without ambiguity (`/cunav/mcp`, `/togra/mcp`).  For `/mcp`
/// — which is used by multiple servers on different hosts — the hostname is
/// checked for a product keyword.  On localhost the port disambiguates:
///   - :8085 → obair (awe-server default)
///   - :8080 → dam  (ullav-dam-server default)
///   - :8087 → collection (ullav-collection-server MCP default)
fn resource_to_product_gate(resource: &str) -> Option<(&'static str, &'static str)> {
    let url = url::Url::parse(resource).ok()?;
    let host = url.host_str().unwrap_or("").to_lowercase();
    let port = url.port().unwrap_or(0);
    let path = url.path();

    // Unique paths are unambiguous regardless of host.
    if path == "/cunav/mcp" || host.contains("cunav") {
        return Some(("cunav", "cunav:tools"));
    }
    if path == "/togra/mcp" {
        return Some(("obair", "obair:tools"));
    }

    if path == "/mcp" {
        // Staging/prod: distinguish by hostname keyword.
        if host.contains("comad") || host.contains("dam") || port == 8080 {
            return Some(("comad", "dam:tools"));
        }
        // Checked before the collection/port==8087 fallback below, since
        // tack-server also defaults to port 8087 locally — hostname (real in
        // staging/prod) disambiguates the two; in local dev, where both would
        // otherwise share "localhost", give the `resource` a host containing
        // "tack" (it doesn't need to be reachable, just parseable) to hit
        // this branch instead of the collection one.
        if host.contains("tack") {
            return Some(("tack", "tack:tools"));
        }
        if host.contains("collection") || port == 8087 {
            return Some(("collection", "collection:tools"));
        }
        // Default /mcp with no other distinguishing marker → obair.
        return Some(("obair", "obair:tools"));
    }

    None
}

// ── Dynamic Client Registration (RFC 7591 + CIMD) ────────────────────────────

#[derive(Deserialize)]
pub struct DcrRequest {
    /// Optional: if this is a CIMD URL, the AS fetches the metadata from it.
    client_id: Option<String>,
    client_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    scope: Option<String>,
    #[serde(flatten)]
    _extra: HashMap<String, serde_json::Value>,
}

/// `POST /oauth2/register` — Dynamic Client Registration.
///
/// Supports both classic DCR (client supplies name + redirect_uris) and
/// Client ID Metadata Documents (CIMD) where `client_id` is a URL the AS
/// fetches to discover the client's metadata.  Public clients only.
#[post("/oauth2/register")]
pub async fn register(
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    body: Json<DcrRequest>,
) -> Result<HttpResponse, AppError> {
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_owned();
    if !state.register_rate_limiter.check(&ip) {
        return Err(AppError::OAuth2("rate limit exceeded — try again later".into()));
    }

    let (client_id, client_name, redirect_uris) =
        resolve_client_metadata(&state, &body).await?;

    // Validate redirect URIs.
    for uri in &redirect_uris {
        let Ok(parsed) = Url::parse(uri) else {
            return Err(AppError::Validation(format!("invalid redirect_uri: {uri}")));
        };
        let is_loopback_http = parsed.scheme() == "http"
            && matches!(parsed.host_str(), Some("localhost") | Some("127.0.0.1"));
        if parsed.scheme() != "https" && !is_loopback_http {
            return Err(AppError::Validation(format!(
                "redirect_uri must use https or loopback http: {uri}"
            )));
        }
    }

    let allowed_scopes = vec!["mcp:tools".to_owned()];
    let granted_scopes: Vec<String> = body.scope
        .as_deref()
        .unwrap_or("mcp:tools")
        .split_whitespace()
        .filter(|s| allowed_scopes.contains(&s.to_string()))
        .map(str::to_owned)
        .collect();

    let client = db::oauth2::register_oauth2_client(
        &state.pool,
        &client_id,
        &client_name,
        &redirect_uris,
        &granted_scopes,
        None,
    )
    .await?;

    db::oauth2::audit_log(
        &state.pool, "register", None, Some(&client.client_id),
        Some(&client.allowed_scopes.join(" ")), None, Some(&ip), None,
    ).await;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "client_id":                  client.client_id,
        "client_name":                client.client_name,
        "redirect_uris":              client.redirect_uris,
        "scope":                      client.allowed_scopes.join(" "),
        "token_endpoint_auth_method": "none",
        "grant_types":                ["authorization_code", "refresh_token"],
        "response_types":             ["code"],
        "code_challenge_method":      "S256",
    })))
}

/// Resolve the client_id, client_name, and redirect_uris for a DCR request.
///
/// If `client_id` is a URL, fetches the CIMD document from it and extracts
/// the metadata.  Otherwise uses the fields from the request body directly.
async fn resolve_client_metadata(
    state: &AppState,
    body: &DcrRequest,
) -> Result<(String, String, Vec<String>), AppError> {
    if let Some(ref cid) = body.client_id {
        if cid.starts_with("https://") {
            // CIMD: fetch the client metadata document from the client_id URL.
            let cimd: serde_json::Value = state
                .http_client
                .get(cid)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
                .map_err(|e| AppError::Validation(format!("failed to fetch CIMD from {cid}: {e}")))?
                .json()
                .await
                .map_err(|e| AppError::Validation(format!("CIMD response not valid JSON: {e}")))?;

            let redirect_uris: Vec<String> = cimd["redirect_uris"]
                .as_array()
                .ok_or_else(|| AppError::Validation("CIMD missing redirect_uris".into()))?
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
            let client_name = cimd["client_name"]
                .as_str()
                .unwrap_or("Unknown")
                .to_owned();

            return Ok((cid.clone(), client_name, redirect_uris));
        }
    }

    // Classic DCR.
    let redirect_uris = body.redirect_uris.clone().ok_or_else(|| {
        AppError::Validation("redirect_uris required".into())
    })?;
    if redirect_uris.is_empty() {
        return Err(AppError::Validation("redirect_uris must not be empty".into()));
    }
    let client_id = format!("dcr-{}", secure_hex_token(12));
    let client_name = body.client_name.clone().unwrap_or_else(|| "Unnamed client".into());

    Ok((client_id, client_name, redirect_uris))
}

// ── Authorization endpoint ────────────────────────────────────────────────────

#[derive(Deserialize, Clone)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    /// RFC 8707 resource indicator.
    pub resource: String,
    /// OIDC `prompt` parameter. `"login"` forces re-authentication even when a
    /// session cookie is present, allowing the user to sign in as a different account.
    pub prompt: Option<String>,
}

/// `GET /oauth2/authorize` — Begin the authorization code flow.
#[get("/oauth2/authorize")]
pub async fn authorize_get(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: Query<AuthorizeParams>,
) -> Result<HttpResponse, AppError> {
    validate_authorize_params(&query)?;

    let client = db::oauth2::get_oauth2_client(&state.pool, &query.client_id)
        .await
        .map_err(|_| AppError::Validation("unknown client_id".into()))?;

    if !redirect_uri_allowed(&client.redirect_uris, &query.redirect_uri) {
        return Err(AppError::Validation("redirect_uri not registered for this client".into()));
    }

    if let Some(session_token) = session_token_from_req(&req) {
        let hash = sha256_hex(&session_token);
        if let Ok(session) = db::oauth2::get_user_session(&state.pool, &hash).await {
            // prompt=login forces re-authentication; skip session reuse entirely.
            if query.prompt.as_deref() != Some("login") {
                if client.first_party {
                    let user = db::get_user_by_id(&state.pool, session.user_id).await?;
                    return Ok(HttpResponse::Ok()
                        .content_type("text/html; charset=utf-8")
                        .body(account_chooser_html(&query, &user.email)));
                } else {
                    let user = db::get_user_by_id(&state.pool, session.user_id).await?;
                    return Ok(HttpResponse::Ok()
                        .content_type("text/html; charset=utf-8")
                        .body(consent_html(&query, &user.username, &client.client_name)));
                }
            }
        }
    }

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(login_html(&query, None)))
}

#[derive(Deserialize)]
pub struct AuthorizeForm {
    // Login fields
    email: Option<String>,
    password: Option<String>,
    // Consent decision ("approve" | "deny")
    action: Option<String>,
    // OAuth2 params forwarded as hidden fields
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    resource: Option<String>,
}

/// `POST /oauth2/authorize` — Process a login form or consent decision.
#[post("/oauth2/authorize")]
pub async fn authorize_post(
    state: web::Data<AppState>,
    req: HttpRequest,
    form: Form<AuthorizeForm>,
) -> Result<HttpResponse, AppError> {
    let params = AuthorizeParams {
        response_type: form.response_type.clone().unwrap_or_default(),
        client_id: form.client_id.clone().unwrap_or_default(),
        redirect_uri: form.redirect_uri.clone().unwrap_or_default(),
        scope: form.scope.clone(),
        state: form.state.clone(),
        code_challenge: form.code_challenge.clone().unwrap_or_default(),
        code_challenge_method: form.code_challenge_method.clone().unwrap_or_default(),
        resource: form.resource.clone().unwrap_or_default(),
        prompt: None,
    };

    let client = db::oauth2::get_oauth2_client(&state.pool, &params.client_id)
        .await
        .map_err(|_| AppError::Validation("unknown client_id".into()))?;

    if !redirect_uri_allowed(&client.redirect_uris, &params.redirect_uri) {
        return Err(AppError::Validation("redirect_uri not registered for this client".into()));
    }

    // Handle a consent decision (user was already logged in via session cookie).
    if let Some(ref action) = form.action {
        if let Some(session_token) = session_token_from_req(&req) {
            let hash = sha256_hex(&session_token);
            if let Ok(session) = db::oauth2::get_user_session(&state.pool, &hash).await {
                return match action.as_str() {
                    "approve" | "continue" => {
                        let result = build_code_redirect(&state, session.user_id, &params).await;
                        handle_code_redirect(result, &params.redirect_uri, params.state.as_deref())
                    }
                    _ => {
                        let url = error_redirect(&params.redirect_uri, "access_denied", params.state.as_deref());
                        Ok(HttpResponse::Found()
                            .append_header(("Location", url.as_str()))
                            .finish())
                    }
                };
            }
        }
        // Session expired during consent page — show login form again.
        return Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(login_html(&params, Some("Your session expired. Please sign in again."))));
    }

    // Process login form submission.
    let email = form.email.as_deref().unwrap_or("").trim().to_lowercase();
    let password = form.password.as_deref().unwrap_or("");

    let user = match db::get_user_by_email(&state.pool, &email).await {
        Ok(u) if u.is_active => u,
        _ => {
            return Ok(HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(login_html(&params, Some("Invalid email or password."))));
        }
    };

    match crate::utils::password::verify_password(password, &user.password_hash) {
        Ok(true) => {}
        _ => {
            return Ok(HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(login_html(&params, Some("Invalid email or password."))));
        }
    }

    // Credentials valid — create a browser session.
    let raw_token = secure_hex_token(32);
    let token_hash = sha256_hex(&raw_token);
    db::oauth2::create_user_session(&state.pool, &token_hash, user.id, SESSION_TTL_DAYS).await?;
    let cookie = make_session_cookie(&raw_token);

    if client.first_party {
        let result = build_code_redirect(&state, user.id, &params).await;
        match result {
            Ok(url) => Ok(HttpResponse::Found()
                .cookie(cookie)
                .append_header(("Location", url.as_str()))
                .finish()),
            Err(AppError::OAuth2(msg)) if msg.starts_with("access_denied") => {
                let url = error_redirect(&params.redirect_uri, "access_denied", params.state.as_deref());
                Ok(HttpResponse::Found()
                    .cookie(cookie)
                    .append_header(("Location", url.as_str()))
                    .finish())
            }
            Err(e) => Err(e),
        }
    } else {
        Ok(HttpResponse::Ok()
            .cookie(cookie)
            .content_type("text/html; charset=utf-8")
            .body(consent_html(&params, &user.username, &client.client_name)))
    }
}

// ── Token endpoint ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    // client_credentials grant (confidential/service clients only).
    client_secret: Option<String>,
    resource: Option<String>,
    scope: Option<String>,
}

/// `POST /oauth2/token` — Exchange auth code or refresh token for an access token.
#[post("/oauth2/token")]
pub async fn token(
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    form: Form<TokenForm>,
) -> Result<HttpResponse, AppError> {
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_owned();
    if !state.token_rate_limiter.check(&ip) {
        return Err(AppError::OAuth2("rate limit exceeded — try again later".into()));
    }
    match form.grant_type.as_str() {
        "authorization_code" => auth_code_grant(&state, &form, &ip).await,
        "refresh_token"      => refresh_token_grant(&state, &form, &ip).await,
        "client_credentials" => client_credentials_grant(&state, &form, &ip).await,
        gt => Err(AppError::Validation(format!("unsupported grant_type: {gt}"))),
    }
}

/// `client_credentials` grant (RFC 6749 §4.4) — machine-to-machine callers
/// with no human present. Only confidential clients provisioned via
/// `POST /admin/oauth2/service-clients` (see `handlers::admin`) are eligible;
/// public/DCR clients (`client_secret_hash IS NULL`) are rejected by
/// `get_service_client` returning `NotFound`.
///
/// Unlike `authorization_code`/`refresh_token`, there's no stored auth code or
/// refresh token to carry `resource`/`scope` forward from — both must be
/// supplied directly in the token request, same as `authorize`'s
/// `AuthorizeParams`. The minted token's `sub` is the client's bound
/// service-account user, so it flows through the exact same product
/// entitlement check (`resource_to_product_gate` + `user_has_product_access`)
/// as a human's token — the service account must be a member of a team with
/// the target product enabled, same as any other user.
///
/// No refresh token is issued — spec-correct for this grant. The caller just
/// re-authenticates with its (non-expiring) client secret whenever it wants a
/// new access token.
async fn client_credentials_grant(state: &AppState, form: &TokenForm, ip: &str) -> Result<HttpResponse, AppError> {
    let client_id = form.client_id.as_deref()
        .ok_or_else(|| AppError::Validation("client_id required".into()))?;
    let client_secret = form.client_secret.as_deref()
        .ok_or_else(|| AppError::Validation("client_secret required".into()))?;
    let resource = form.resource.as_deref()
        .ok_or_else(|| AppError::Validation("resource is required (RFC 8707)".into()))?;

    let client = db::oauth2::get_service_client(&state.pool, client_id)
        .await
        .map_err(|_| AppError::InvalidToken)?;

    if !crate::utils::password::verify_password(client_secret, &client.client_secret_hash)? {
        return Err(AppError::InvalidToken);
    }

    let requested_scope = form.scope.as_deref().unwrap_or("");
    let base_scope: Vec<&str> = requested_scope
        .split_whitespace()
        .filter(|s| client.allowed_scopes.iter().any(|a| a == s))
        .collect();
    let mut scope = base_scope.join(" ");

    // Same product gate `build_code_redirect` applies for human logins: the
    // service account must actually have the target product enabled on one
    // of its teams, checked fresh on every token request (not just at
    // provisioning time), so revoking the service account's team access cuts
    // off new tokens immediately.
    if let Some((product_slug, product_scope)) = resource_to_product_gate(resource) {
        let has_access = db::user_has_product_access(&state.pool, client.service_account_user_id, product_slug).await?;
        if !has_access {
            return Err(AppError::OAuth2(format!(
                "access_denied: service account for client {client_id:?} does not have access to the \"{product_slug}\" product"
            )));
        }
        if !scope.split_whitespace().any(|s| s == product_scope) {
            scope = if scope.is_empty() { product_scope.to_owned() } else { format!("{scope} {product_scope}") };
        }
    }

    let user = db::get_user_by_id(&state.pool, client.service_account_user_id).await?;
    let access_token = mint_access_token(
        state, user.id, &user.username, &scope, resource, client_id,
    ).await?;

    db::oauth2::audit_log(
        &state.pool, "token_issued", Some(user.id), Some(client_id),
        Some(&scope), Some(resource), Some(ip), None,
    ).await;

    Ok(token_json_response(&access_token, &scope, None))
}

async fn auth_code_grant(state: &AppState, form: &TokenForm, ip: &str) -> Result<HttpResponse, AppError> {
    let code = form.code.as_deref()
        .ok_or_else(|| AppError::Validation("code required".into()))?;
    let redirect_uri = form.redirect_uri.as_deref()
        .ok_or_else(|| AppError::Validation("redirect_uri required".into()))?;
    let client_id = form.client_id.as_deref()
        .ok_or_else(|| AppError::Validation("client_id required".into()))?;
    let verifier = form.code_verifier.as_deref()
        .ok_or_else(|| AppError::Validation("code_verifier required".into()))?;

    let auth_code = db::oauth2::consume_auth_code(&state.pool, code).await?;

    if auth_code.client_id != client_id {
        return Err(AppError::InvalidToken);
    }

    // RFC 6749 §4.1.3: redirect_uri in the token request must match the one used
    // in the authorization request (stored in the auth code), not just the registered set.
    // Use port-agnostic matching for loopback URIs per RFC 8252 §7.3.
    if !redirect_uri_allowed(&[auth_code.redirect_uri.clone()], redirect_uri) {
        return Err(AppError::Validation(
            "redirect_uri does not match the one used in the authorization request".into(),
        ));
    }

    // PKCE S256 verification (RFC 7636 §4.6).
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let computed = Base64UrlUnpadded::encode_string(&hasher.finalize());
    if computed != auth_code.code_challenge {
        return Err(AppError::InvalidToken);
    }

    let user = db::get_user_by_id(&state.pool, auth_code.user_id).await?;
    let access_token = mint_access_token(
        state, user.id, &user.username, &auth_code.scope, &auth_code.resource, client_id,
    ).await?;

    let refresh_raw = secure_hex_token(32);
    let refresh_hash = sha256_hex(&refresh_raw);
    db::oauth2::create_refresh_token(
        &state.pool, &refresh_hash, client_id, user.id,
        &auth_code.scope, &auth_code.resource, REFRESH_TOKEN_TTL_DAYS,
    ).await?;

    db::oauth2::audit_log(
        &state.pool, "token_issued", Some(user.id), Some(client_id),
        Some(&auth_code.scope), Some(&auth_code.resource), Some(ip), None,
    ).await;

    Ok(token_json_response(&access_token, &auth_code.scope, Some(&refresh_raw)))
}

async fn refresh_token_grant(state: &AppState, form: &TokenForm, ip: &str) -> Result<HttpResponse, AppError> {
    let raw = form.refresh_token.as_deref()
        .ok_or_else(|| AppError::Validation("refresh_token required".into()))?;
    let client_id = form.client_id.as_deref()
        .ok_or_else(|| AppError::Validation("client_id required".into()))?;

    let old = db::oauth2::rotate_refresh_token(&state.pool, &sha256_hex(raw)).await?;
    if old.client_id != client_id {
        return Err(AppError::InvalidToken);
    }

    // Re-enforce product gate: the user may have lost product access after the
    // original token was issued (team membership revoked, product disabled).
    // Fail the refresh so Claude re-triggers the authorization flow.
    if let Some((product_slug, _)) = resource_to_product_gate(&old.resource) {
        let has_access = db::user_has_product_access(&state.pool, old.user_id, product_slug).await?;
        if !has_access {
            return Err(AppError::OAuth2(format!(
                "access_denied: user no longer has access to the \"{product_slug}\" product"
            )));
        }
    }

    let user = db::get_user_by_id(&state.pool, old.user_id).await?;
    let access_token = mint_access_token(
        state, user.id, &user.username, &old.scope, &old.resource, client_id,
    ).await?;

    let new_refresh_raw = secure_hex_token(32);
    let new_refresh_hash = sha256_hex(&new_refresh_raw);
    db::oauth2::create_refresh_token(
        &state.pool, &new_refresh_hash, client_id, user.id,
        &old.scope, &old.resource, REFRESH_TOKEN_TTL_DAYS,
    ).await?;

    db::oauth2::audit_log(
        &state.pool, "token_refreshed", Some(user.id), Some(client_id),
        Some(&old.scope), Some(&old.resource), Some(ip), None,
    ).await;

    Ok(token_json_response(&access_token, &old.scope, Some(&new_refresh_raw)))
}

// ── Revocation (RFC 7009) ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RevokeForm {
    token: String,
    #[serde(rename = "token_type_hint")]
    _hint: Option<String>,
}

/// `POST /oauth2/revoke` — Revoke a refresh token.
///
/// Always returns 200 per RFC 7009, even if the token is unknown.
#[post("/oauth2/revoke")]
pub async fn revoke(
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    form: Form<RevokeForm>,
) -> HttpResponse {
    let revoked = db::oauth2::revoke_refresh_token(&state.pool, &sha256_hex(&form.token))
        .await
        .is_ok();
    if revoked {
        let ip = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_owned();
        db::oauth2::audit_log(
            &state.pool, "token_revoked", None, None, None, None, Some(&ip), None,
        ).await;
    }
    HttpResponse::Ok().finish()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn validate_authorize_params(p: &AuthorizeParams) -> Result<(), AppError> {
    if p.response_type != "code" {
        return Err(AppError::Validation("response_type must be 'code'".into()));
    }
    if p.code_challenge_method != "S256" {
        return Err(AppError::Validation("code_challenge_method must be 'S256'".into()));
    }
    if p.code_challenge.is_empty() {
        return Err(AppError::Validation("code_challenge is required".into()));
    }
    if p.resource.is_empty() {
        return Err(AppError::Validation("resource is required (RFC 8707)".into()));
    }
    Ok(())
}

async fn build_code_redirect(
    state: &web::Data<AppState>,
    user_id: Uuid,
    params: &AuthorizeParams,
) -> Result<Url, AppError> {
    let base_scope = params.scope.as_deref().unwrap_or("mcp:tools");

    // Check product gate and enrich the scope that will be stamped in the token.
    // Users who lack the required product are rejected here — before an auth code
    // is created — so no token is ever issued to them for this resource.
    let scope = if let Some((product_slug, product_scope)) = resource_to_product_gate(&params.resource) {
        let has_access = db::user_has_product_access(&state.pool, user_id, product_slug).await?;
        if !has_access {
            return Err(AppError::OAuth2(format!(
                "access_denied: your account does not have access to the \"{product_slug}\" product"
            )));
        }
        // Stamp the product scope so the resource server can verify it without a DB lookup.
        format!("{base_scope} {product_scope}")
    } else {
        base_scope.to_owned()
    };

    let code = secure_hex_token(32);
    db::oauth2::create_auth_code(
        &state.pool, &code, &params.client_id, user_id,
        &params.redirect_uri, &scope, &params.resource, &params.code_challenge,
        AUTH_CODE_TTL_MINUTES,
    ).await?;

    let mut url = Url::parse(&params.redirect_uri)
        .map_err(|_| AppError::Validation("invalid redirect_uri".into()))?;
    url.query_pairs_mut().append_pair("code", &code);
    if let Some(ref s) = params.state {
        url.query_pairs_mut().append_pair("state", s);
    }
    Ok(url)
}

/// Convert a `build_code_redirect` result into an HTTP response, redirecting
/// with `?error=access_denied` when the product gate rejects the user instead
/// of propagating a server-side error (which would produce a 400/500 page).
fn handle_code_redirect(
    result: Result<Url, AppError>,
    redirect_uri: &str,
    state_param: Option<&str>,
) -> Result<HttpResponse, AppError> {
    match result {
        Ok(url) => Ok(HttpResponse::Found()
            .append_header(("Location", url.as_str()))
            .finish()),
        Err(AppError::OAuth2(msg)) if msg.starts_with("access_denied") => {
            let url = error_redirect(redirect_uri, "access_denied", state_param);
            Ok(HttpResponse::Found()
                .append_header(("Location", url.as_str()))
                .finish())
        }
        Err(e) => Err(e),
    }
}

fn error_redirect(redirect_uri: &str, error: &str, state: Option<&str>) -> Url {
    let mut url = Url::parse(redirect_uri)
        .unwrap_or_else(|_| Url::parse("about:blank").unwrap());
    url.query_pairs_mut().append_pair("error", error);
    if let Some(s) = state {
        url.query_pairs_mut().append_pair("state", s);
    }
    url
}

// ── HTML views ────────────────────────────────────────────────────────────────

fn hidden_oauth2_fields(p: &AuthorizeParams) -> String {
    format!(
        r#"<input type="hidden" name="response_type" value="{response_type}">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="code_challenge" value="{challenge}">
<input type="hidden" name="code_challenge_method" value="{method}">
<input type="hidden" name="resource" value="{resource}">"#,
        response_type = html_escape(&p.response_type),
        client_id     = html_escape(&p.client_id),
        redirect_uri  = html_escape(&p.redirect_uri),
        scope         = html_escape(p.scope.as_deref().unwrap_or("")),
        state         = html_escape(p.state.as_deref().unwrap_or("")),
        challenge     = html_escape(&p.code_challenge),
        method        = html_escape(&p.code_challenge_method),
        resource      = html_escape(&p.resource),
    )
}

/// Builds the authorize URL with `prompt=login` so the user can re-authenticate.
fn switch_account_url(p: &AuthorizeParams) -> String {
    let mut pairs = url::form_urlencoded::Serializer::new(String::new());
    pairs.append_pair("response_type", &p.response_type);
    pairs.append_pair("client_id", &p.client_id);
    pairs.append_pair("redirect_uri", &p.redirect_uri);
    pairs.append_pair("scope", p.scope.as_deref().unwrap_or(""));
    pairs.append_pair("state", p.state.as_deref().unwrap_or(""));
    pairs.append_pair("code_challenge", &p.code_challenge);
    pairs.append_pair("code_challenge_method", &p.code_challenge_method);
    pairs.append_pair("resource", &p.resource);
    pairs.append_pair("prompt", "login");
    format!("/oauth2/authorize?{}", pairs.finish())
}

/// Shown to first-party clients when a session already exists.
/// Lets the user confirm they want to continue as the current account,
/// or switch to a different one.
fn account_chooser_html(params: &AuthorizeParams, email: &str) -> String {
    let hidden = hidden_oauth2_fields(params);
    let switch_url = switch_account_url(params);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Ullav — Continue as {email_esc}</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box}}
    body{{font-family:system-ui,sans-serif;background:#f8f8f6;
          display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}}
    .card{{background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.08);
           padding:2rem;width:100%;max-width:400px;text-align:center}}
    h1{{margin:0 0 .5rem;font-size:1.3rem;color:#1a1a1a}}
    .email{{font-size:1rem;color:#2563eb;font-weight:500;margin:0 0 1.75rem;
            word-break:break-all}}
    button{{width:100%;padding:.7rem;background:#2563eb;color:#fff;border:none;
            border-radius:4px;font-size:1rem;cursor:pointer;font-weight:500}}
    button:hover{{background:#1d4ed8}}
    .switch{{display:block;margin-top:1.1rem;font-size:.875rem;color:#6b7280;
             text-decoration:none}}
    .switch:hover{{color:#374151;text-decoration:underline}}
  </style>
</head>
<body>
  <div class="card">
    <h1>Continue as</h1>
    <p class="email">{email_esc}</p>
    <form method="post" action="/oauth2/authorize">
      {hidden}
      <button type="submit" name="action" value="continue" autofocus>Continue</button>
    </form>
    <a class="switch" href="{switch_url_esc}">Use a different account</a>
  </div>
</body>
</html>"#,
        email_esc     = html_escape(email),
        switch_url_esc = html_escape(&switch_url),
    )
}

fn login_html(params: &AuthorizeParams, error: Option<&str>) -> String {
    let error_html = error.map_or_else(String::new, |e| {
        format!(r#"<div class="err">{}</div>"#, html_escape(e))
    });
    let hidden = hidden_oauth2_fields(params);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Ullav — Sign in</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box}}
    body{{font-family:system-ui,sans-serif;background:#f8f8f6;
          display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}}
    .card{{background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.08);
           padding:2rem;width:100%;max-width:400px}}
    h1{{margin:0 0 1.5rem;font-size:1.4rem;color:#1a1a1a}}
    label{{display:block;font-size:.875rem;color:#444;margin-bottom:.25rem}}
    input[type=email],input[type=password]{{display:block;width:100%;padding:.6rem .75rem;
      border:1px solid #d0d0d0;border-radius:4px;font-size:1rem;margin-bottom:1rem}}
    button{{width:100%;padding:.7rem;background:#2563eb;color:#fff;border:none;
            border-radius:4px;font-size:1rem;cursor:pointer}}
    button:hover{{background:#1d4ed8}}
    .err{{background:#fef2f2;border:1px solid #fca5a5;color:#b91c1c;
          border-radius:4px;padding:.6rem .75rem;margin-bottom:1rem;font-size:.875rem}}
  </style>
</head>
<body>
  <div class="card">
    <h1>Sign in to Ullav</h1>
    {error_html}
    <form method="post" action="/oauth2/authorize">
      {hidden}
      <label for="email">Email</label>
      <input type="email" id="email" name="email" autocomplete="email" required autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required>
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>"#
    )
}

fn scope_description(scope: &str) -> &'static str {
    match scope {
        "cunav"         => "View and manage your Cunav support tickets",
        "cunav:tools"   => "Use AI tools to manage support tickets via Cunav MCP",
        "cunav:support" => "Manage support tickets as a support team member",
        "cunav:read"    => "View your Cunav support tickets (read-only)",
        "obair"         => "Access your AWE workflows and execution history",
        "obair:tools"   => "Use AI tools on your AWE projects and workflows",
        "clann"         => "View and edit your Clann family tree data",
        "dam"               => "Access your DAM digital assets",
        "dam:tools"         => "Use AI tools to search and browse your digital assets via DAM MCP",
        "collection"        => "Access your collection management data",
        "collection:tools"  => "Use AI tools to browse and annotate your collection via Collection MCP",
        "mcp:tools"         => "Use AI-assisted tools on your behalf",
        _               => "Additional access",
    }
}

fn consent_html(params: &AuthorizeParams, username: &str, client_name: &str) -> String {
    let scope_str = params.scope.as_deref().unwrap_or("mcp:tools");
    let hidden = hidden_oauth2_fields(params);
    let switch_url = switch_account_url(params);

    // Build a list of human-readable scope descriptions.
    let scope_items: String = scope_str
        .split_whitespace()
        .map(|s| {
            format!(
                r#"<li><span class="scope-label">{}</span><span class="scope-desc">{}</span></li>"#,
                html_escape(s),
                scope_description(s),
            )
        })
        .collect::<Vec<_>>()
        .join("\n      ");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Ullav — Authorise {client_name_esc}</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box}}
    body{{font-family:system-ui,sans-serif;background:#f8f8f6;
          display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}}
    .card{{background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.08);
           padding:2rem;width:100%;max-width:460px}}
    h1{{margin:0 0 .25rem;font-size:1.25rem;color:#111}}
    .sub{{color:#666;font-size:.9rem;margin:0 0 1.5rem}}
    .scope-list{{list-style:none;padding:0;margin:0 0 1.5rem;
                 border:1px solid #e5e7eb;border-radius:6px;overflow:hidden}}
    .scope-list li{{padding:.65rem .9rem;border-bottom:1px solid #e5e7eb;display:flex;
                    flex-direction:column;gap:.15rem}}
    .scope-list li:last-child{{border-bottom:none}}
    .scope-label{{font-size:.75rem;font-weight:600;color:#6b7280;text-transform:uppercase;
                  letter-spacing:.04em}}
    .scope-desc{{font-size:.9rem;color:#111}}
    .actions{{display:flex;gap:.75rem}}
    button{{flex:1;padding:.7rem;border:none;border-radius:4px;font-size:1rem;cursor:pointer;
            font-weight:500}}
    .approve{{background:#2563eb;color:#fff}}
    .approve:hover{{background:#1d4ed8}}
    .deny{{background:#e5e7eb;color:#374151}}
    .deny:hover{{background:#d1d5db}}
    .footer{{margin-top:1.25rem;font-size:.78rem;color:#9ca3af;text-align:center}}
    .switch{{display:block;margin-top:.6rem;font-size:.78rem;color:#6b7280;
             text-decoration:none;text-align:center}}
    .switch:hover{{color:#374151;text-decoration:underline}}
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorise {client_name_esc}</h1>
    <p class="sub">Signed in as <strong>{username_esc}</strong></p>
    <p style="color:#444;margin:0 0 .75rem;font-size:.9rem">
      <strong>{client_name_esc}</strong> is requesting access to:
    </p>
    <ul class="scope-list">
      {scope_items}
    </ul>
    <form method="post" action="/oauth2/authorize">
      {hidden}
      <div class="actions">
        <button class="deny"    type="submit" name="action" value="deny">Deny</button>
        <button class="approve" type="submit" name="action" value="approve">Allow</button>
      </div>
    </form>
    <a class="switch" href="{switch_url_esc}">Use a different account</a>
    <p class="footer">
      You can revoke access at any time from your Ullav account settings.
    </p>
  </div>
</body>
</html>"#,
        client_name_esc = html_escape(client_name),
        username_esc    = html_escape(username),
        scope_items     = scope_items,
        switch_url_esc  = html_escape(&switch_url),
    )
}

#[cfg(test)]
mod resource_gate_tests {
    use super::resource_to_product_gate;

    #[test]
    fn tack_host_takes_priority_over_the_ambiguous_port_8087_collection_fallback() {
        assert_eq!(
            resource_to_product_gate("http://tack-server.stage.ullav.setanta.dev/mcp"),
            Some(("tack", "tack:tools"))
        );
        // Local dev: no distinguishing hostname exists between tack-server and
        // ullav-collection-server (both can default to port 8087), so a
        // "tack"-containing host in the resource string is how a local
        // client_credentials request reaches the tack gate instead of collection's.
        assert_eq!(resource_to_product_gate("http://tack-local/mcp"), Some(("tack", "tack:tools")));
    }

    #[test]
    fn collection_still_resolves_by_port_when_host_has_no_marker() {
        assert_eq!(resource_to_product_gate("http://localhost:8087/mcp"), Some(("collection", "collection:tools")));
    }

    #[test]
    fn comad_resolves_by_host_or_port() {
        assert_eq!(resource_to_product_gate("http://comad.example.com/mcp"), Some(("comad", "dam:tools")));
        assert_eq!(resource_to_product_gate("http://localhost:8080/mcp"), Some(("comad", "dam:tools")));
    }

    #[test]
    fn cunav_resolves_by_unique_path_or_host() {
        assert_eq!(resource_to_product_gate("http://localhost:8085/cunav/mcp"), Some(("cunav", "cunav:tools")));
        assert_eq!(resource_to_product_gate("http://cunav.example.com/mcp"), Some(("cunav", "cunav:tools")));
    }

    #[test]
    fn unrecognized_resource_returns_none() {
        assert_eq!(resource_to_product_gate("not a url"), None);
        assert_eq!(resource_to_product_gate("http://example.com/unrelated"), None);
    }
}
