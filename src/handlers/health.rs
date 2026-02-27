use crate::AppState;
use actix_web::{get, web, HttpResponse};

/// `GET /health` — liveness and database connectivity check.
#[get("/health")]
pub async fn health(state: web::Data<AppState>) -> HttpResponse {
    match state.pool.get().await {
        Ok(client) => match client.query_one("SELECT 1", &[]).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                "status": "ok",
                "database": "ok"
            })),
            Err(_) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "status": "degraded",
                "database": "error"
            })),
        },
        Err(_) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "status": "degraded",
            "database": "unavailable"
        })),
    }
}
