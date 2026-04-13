use crate::{
    db,
    errors::AppError,
    models::{CheckoutRequest, CheckoutResponse, SubscriptionResponse},
    payments,
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
#[post("/subscriptions/checkout")]
pub async fn create_checkout_session(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CheckoutRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = req
        .extensions()
        .get::<Claims>()
        .ok_or(AppError::InvalidToken)?
        .clone();

    let user_id: Uuid = claims.sub.parse().map_err(|_| AppError::InvalidToken)?;
    let user = db::get_user_by_id(&state.pool, user_id).await?;
    let seat_count = body.seat_count.unwrap_or(1).max(1);

    let success_url = format!("{}/subscription/success", state.clann_app_url);
    let cancel_url = format!("{}/pricing", state.clann_app_url);

    let url = match body.provider.as_str() {
        "stripe" => {
            let config = state
                .stripe
                .as_ref()
                .ok_or_else(|| AppError::PaymentProvider("Stripe is not configured".into()))?;
            payments::stripe::create_checkout_session(
                config,
                &state.http_client,
                user_id,
                &user.email,
                &body.plan,
                seat_count,
                &success_url,
                &cancel_url,
            )
            .await?
        }
        "paypal" => {
            let config = state
                .paypal
                .as_ref()
                .ok_or_else(|| AppError::PaymentProvider("PayPal is not configured".into()))?;
            payments::paypal::create_subscription(
                config,
                &state.http_client,
                user_id,
                &user.email,
                &body.plan,
                seat_count,
                &success_url,
                &cancel_url,
            )
            .await?
        }
        other => {
            return Err(AppError::Validation(format!(
                "Unknown payment provider '{other}'. Use 'stripe' or 'paypal'."
            )));
        }
    };

    Ok(HttpResponse::Ok().json(CheckoutResponse { url }))
}

/// `POST /subscriptions/portal`
///
/// Creates a Stripe Customer Portal session so the user can manage their
/// billing details, change plan, or cancel.
#[post("/subscriptions/portal")]
pub async fn create_portal_session(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let claims = req
        .extensions()
        .get::<Claims>()
        .ok_or(AppError::InvalidToken)?
        .clone();

    let user_id: Uuid = claims.sub.parse().map_err(|_| AppError::InvalidToken)?;

    let config = state
        .stripe
        .as_ref()
        .ok_or_else(|| AppError::PaymentProvider("Stripe is not configured".into()))?;

    // Find the user's Stripe subscription to retrieve the customer_id.
    // We look across all products — the portal manages all of the user's billing.
    let subscriptions = db::get_all_user_subscriptions(&state.pool, user_id).await?;
    let stripe_sub = subscriptions
        .iter()
        .find(|s| s.payment_provider.as_deref() == Some("stripe"))
        .ok_or_else(|| AppError::NotFound)?;

    let customer_id = stripe_sub
        .provider_customer_id
        .as_deref()
        .ok_or_else(|| AppError::PaymentProvider("No Stripe customer ID on record".into()))?;

    let return_url = format!("{}/account", state.clann_app_url);

    let url = payments::stripe::create_portal_session(
        config,
        &state.http_client,
        customer_id,
        &return_url,
    )
    .await?;

    Ok(HttpResponse::Ok().json(CheckoutResponse { url }))
}

// ── Webhook handlers ──────────────────────────────────────────────────────────

/// `POST /webhooks/stripe`
///
/// Receives Stripe lifecycle events, verifies the signature, and dispatches
/// to the appropriate handler.
#[post("/webhooks/stripe")]
pub async fn stripe_webhook(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    let config = match &state.stripe {
        Some(c) => c,
        None => {
            log::warn!("Stripe webhook received but Stripe is not configured — ignoring");
            return HttpResponse::Ok().finish();
        }
    };

    let signature = req
        .headers()
        .get("Stripe-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if let Err(e) = payments::stripe::verify_signature(&body, signature, &config.webhook_secret) {
        log::warn!("Stripe webhook signature verification failed: {e}");
        return HttpResponse::Unauthorized().finish();
    }

    match payments::stripe::handle_event(&state, &body).await {
        Ok(()) => HttpResponse::Ok().finish(),
        Err(e) => {
            log::error!("Stripe webhook handler error: {e}");
            // Return 500 so Stripe will retry the event.
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// `POST /webhooks/paypal`
///
/// Receives PayPal lifecycle events, verifies the signature via PayPal's
/// verification API, and dispatches to the appropriate handler.
#[post("/webhooks/paypal")]
pub async fn paypal_webhook(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    let config = match &state.paypal {
        Some(c) => c,
        None => {
            log::warn!("PayPal webhook received but PayPal is not configured — ignoring");
            return HttpResponse::Ok().finish();
        }
    };

    // PayPal sends verification metadata in headers.
    let get_header = |name: &str| -> String {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };

    let transmission_id = get_header("PAYPAL-TRANSMISSION-ID");
    let transmission_time = get_header("PAYPAL-TRANSMISSION-TIME");
    let cert_url = get_header("PAYPAL-CERT-URL");
    let auth_algo = get_header("PAYPAL-AUTH-ALGO");
    let transmission_sig = get_header("PAYPAL-TRANSMISSION-SIG");

    let event: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("PayPal webhook: invalid JSON body: {e}");
            return HttpResponse::BadRequest().finish();
        }
    };

    if let Err(e) = payments::paypal::verify_signature(
        config,
        &state.http_client,
        &transmission_id,
        &transmission_time,
        &cert_url,
        &auth_algo,
        &transmission_sig,
        &event,
    )
    .await
    {
        log::warn!("PayPal webhook signature verification failed: {e}");
        return HttpResponse::Unauthorized().finish();
    }

    match payments::paypal::handle_event(&state, &event).await {
        Ok(()) => HttpResponse::Ok().finish(),
        Err(e) => {
            log::error!("PayPal webhook handler error: {e}");
            HttpResponse::InternalServerError().finish()
        }
    }
}
