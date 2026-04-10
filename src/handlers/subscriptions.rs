use crate::{
    db,
    errors::AppError,
    models::{CheckoutRequest, SubscriptionResponse},
    utils::jwt::Claims,
    AppState,
};
use actix_web::{get, post, web, HttpMessage, HttpRequest, HttpResponse};
use uuid::Uuid;

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct ProductQuery {
    product: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /subscriptions/current?product=<slug>`
///
/// Returns the caller's active subscription for the requested product.
/// If no subscription row exists the caller is treated as Individual (free).
#[get("/subscriptions/current")]
pub async fn get_current_subscription(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<ProductQuery>,
) -> Result<HttpResponse, AppError> {
    let claims = req
        .extensions()
        .get::<Claims>()
        .ok_or(AppError::InvalidToken)?
        .clone();

    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| AppError::InvalidToken)?;

    let product_slug = &query.product;

    let response = match db::get_subscription(&state.pool, user_id, product_slug).await? {
        Some(sub) => SubscriptionResponse::from(sub),
        // No row → synthesise a default Individual response so callers
        // never need to special-case a 404.
        None => {
            use chrono::Utc;
            use uuid::Uuid;
            SubscriptionResponse {
                id: Uuid::nil(),
                product: product_slug.clone(),
                plan: "individual".into(),
                status: "active".into(),
                seat_count: 1,
                trial_end: None,
                current_period_start: None,
                current_period_end: Some(
                    // Far-future date signals an open-ended free plan.
                    Utc::now() + chrono::Duration::days(36500),
                ),
                created_at: Utc::now(),
            }
        }
    };

    Ok(HttpResponse::Ok().json(response))
}

/// `POST /subscriptions/checkout`
///
/// Initiates a Stripe or PayPal checkout session for the requested plan.
/// Returns a redirect URL to the hosted checkout page.
///
/// **Not yet implemented — Phase 3.**
#[post("/subscriptions/checkout")]
pub async fn create_checkout_session(
    _state: web::Data<AppState>,
    _req: HttpRequest,
    _body: web::Json<CheckoutRequest>,
) -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "Payment integration not yet implemented — coming in Phase 3"
    })))
}

/// `POST /subscriptions/portal`
///
/// Creates a Stripe Customer Portal session so the user can manage their
/// billing details, change plan, or cancel.
///
/// **Not yet implemented — Phase 3.**
#[post("/subscriptions/portal")]
pub async fn create_portal_session(
    _state: web::Data<AppState>,
    _req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "Billing portal not yet implemented — coming in Phase 3"
    })))
}

// ── Webhook stubs ─────────────────────────────────────────────────────────────
// Webhook endpoints must return 2xx immediately; providers will retry on
// failure.  These stubs acknowledge receipt and log the raw payload so we can
// inspect events during development without losing them.

/// `POST /webhooks/stripe`
///
/// Receives and acknowledges Stripe lifecycle events.
/// Signature verification and event processing are implemented in Phase 3.
#[post("/webhooks/stripe")]
pub async fn stripe_webhook(body: web::Bytes) -> HttpResponse {
    log::info!(
        "Stripe webhook received ({} bytes) — processing not yet implemented",
        body.len()
    );
    HttpResponse::Ok().finish()
}

/// `POST /webhooks/paypal`
///
/// Receives and acknowledges PayPal lifecycle events.
/// Signature verification and event processing are implemented in Phase 3.
#[post("/webhooks/paypal")]
pub async fn paypal_webhook(body: web::Bytes) -> HttpResponse {
    log::info!(
        "PayPal webhook received ({} bytes) — processing not yet implemented",
        body.len()
    );
    HttpResponse::Ok().finish()
}
