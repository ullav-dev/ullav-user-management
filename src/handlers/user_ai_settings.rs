use crate::{errors::AppError, middleware::auth::claims_from_req, AppState};
use actix_web::{delete, get, put, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

const DEFAULT_APP: &str = "togra";

#[derive(Debug, Deserialize)]
pub struct AppQuery {
    /// Which app's settings to read/write. Defaults to "togra" so existing
    /// callers that predate this param (Togra) keep working unchanged.
    pub app: Option<String>,
}

impl AppQuery {
    fn app(&self) -> &str {
        self.app.as_deref().unwrap_or(DEFAULT_APP)
    }
}

#[derive(Debug, Serialize)]
pub struct AiSettingsStoredResponse {
    pub provider: String,
    pub model: String,
    pub ollama_url: Option<String>,
    pub encrypted_key: Option<String>,
    pub iv: Option<String>,
    pub auth_tag: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpsertAiSettingsRequest {
    pub provider: String,
    pub model: String,
    pub ollama_url: Option<String>,
    pub encrypted_key: Option<String>,
    pub iv: Option<String>,
    pub auth_tag: Option<String>,
}

/// `GET /users/me/ai-settings?app=<app>` — return AI settings for the authenticated
/// user, scoped to `app` (default "togra"). Each app has its own isolated row.
///
/// Returns the full encrypted blob so the caller (Next.js API route, server-side)
/// can decrypt the key. The browser-facing `/api/ai/settings` route strips the
/// key material before forwarding to the client.
#[get("/users/me/ai-settings")]
pub async fn get_ai_settings(
    req: HttpRequest,
    query: web::Query<AppQuery>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;

    let client = state.pool.get().await?;
    let row = client
        .query_opt(
            "SELECT provider, model, ollama_url, encrypted_key, iv, auth_tag
             FROM user_ai_settings
             WHERE username = $1 AND app = $2",
            &[&claims.username, &query.app()],
        )
        .await?;

    match row {
        None => Ok(HttpResponse::NotFound().finish()),
        Some(r) => Ok(HttpResponse::Ok().json(AiSettingsStoredResponse {
            provider: r.get("provider"),
            model: r.get("model"),
            ollama_url: r.get("ollama_url"),
            encrypted_key: r.get("encrypted_key"),
            iv: r.get("iv"),
            auth_tag: r.get("auth_tag"),
        })),
    }
}

/// `PUT /users/me/ai-settings?app=<app>` — create or replace AI settings for the
/// user, scoped to `app` (default "togra").
#[put("/users/me/ai-settings")]
pub async fn upsert_ai_settings(
    req: HttpRequest,
    query: web::Query<AppQuery>,
    state: web::Data<AppState>,
    body: web::Json<UpsertAiSettingsRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;

    if body.provider.is_empty() || body.model.is_empty() {
        return Err(AppError::Validation("provider and model are required".into()));
    }

    let client = state.pool.get().await?;
    client
        .execute(
            "INSERT INTO user_ai_settings
                 (username, app, provider, model, ollama_url, encrypted_key, iv, auth_tag, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
             ON CONFLICT (username, app) DO UPDATE SET
                 provider      = EXCLUDED.provider,
                 model         = EXCLUDED.model,
                 ollama_url    = EXCLUDED.ollama_url,
                 encrypted_key = EXCLUDED.encrypted_key,
                 iv            = EXCLUDED.iv,
                 auth_tag      = EXCLUDED.auth_tag,
                 updated_at    = NOW()",
            &[
                &claims.username,
                &query.app(),
                &body.provider,
                &body.model,
                &body.ollama_url,
                &body.encrypted_key,
                &body.iv,
                &body.auth_tag,
            ],
        )
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "ok": true })))
}

/// `DELETE /users/me/ai-settings?app=<app>` — remove AI settings for the user,
/// scoped to `app` (default "togra").
#[delete("/users/me/ai-settings")]
pub async fn delete_ai_settings(
    req: HttpRequest,
    query: web::Query<AppQuery>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;

    let client = state.pool.get().await?;
    client
        .execute(
            "DELETE FROM user_ai_settings WHERE username = $1 AND app = $2",
            &[&claims.username, &query.app()],
        )
        .await?;

    Ok(HttpResponse::NoContent().finish())
}
