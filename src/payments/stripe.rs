//! Stripe Checkout and webhook integration.
//!
//! All API calls use the Stripe REST API directly via reqwest (form-encoded
//! requests, JSON responses) — no third-party Stripe SDK required.
//!
//! Sandbox vs live is determined entirely by the key prefix (`sk_test_` vs
//! `sk_live_`); no code changes are needed to switch environments.

use crate::{config::StripeConfig, db, errors::AppError, AppState};
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const STRIPE_API: &str = "https://api.stripe.com/v1";

// ── Checkout session ──────────────────────────────────────────────────────────

/// Create a Stripe Checkout Session and return its hosted URL.
///
/// For the Family/Team plan the session includes two line items:
/// - base price (qty 1, covers 2 seats)
/// - per-seat overage price (qty = extra seats beyond 2)
///
/// A 7-day trial is applied to Family/Team and Professional plans.
pub async fn create_checkout_session(
    config: &StripeConfig,
    http: &reqwest::Client,
    user_id: Uuid,
    user_email: &str,
    plan: &str,
    seat_count: i16,
    success_url: &str,
    cancel_url: &str,
) -> Result<String, AppError> {
    let seat_count = seat_count.max(2); // minimum 2 for family plan
    let extra_seats = if plan == "family" {
        (seat_count - 2).max(0)
    } else {
        0
    };

    let mut params: Vec<(&str, String)> = vec![
        ("mode", "subscription".into()),
        ("customer_email", user_email.into()),
        ("success_url", format!("{success_url}?session_id={{CHECKOUT_SESSION_ID}}")),
        ("cancel_url", cancel_url.into()),
        ("metadata[user_id]", user_id.to_string()),
        ("metadata[product]", "clann".into()),
        ("metadata[plan]", plan.into()),
        ("metadata[seat_count]", seat_count.to_string()),
    ];

    match plan {
        "family" => {
            params.push(("line_items[0][price]", config.price_id_clann_family_base.clone()));
            params.push(("line_items[0][quantity]", "1".into()));
            if extra_seats > 0 {
                params.push(("line_items[1][price]", config.price_id_clann_family_seat.clone()));
                params.push(("line_items[1][quantity]", extra_seats.to_string()));
            }
            params.push(("subscription_data[trial_period_days]", "7".into()));
        }
        "professional" => {
            params.push(("line_items[0][price]", config.price_id_clann_professional.clone()));
            params.push(("line_items[0][quantity]", "1".into()));
            params.push(("subscription_data[trial_period_days]", "7".into()));
        }
        other => {
            return Err(AppError::Validation(format!(
                "Plan '{other}' does not support Stripe checkout"
            )));
        }
    }

    let resp: serde_json::Value = http
        .post(format!("{STRIPE_API}/checkout/sessions"))
        .bearer_auth(&config.secret_key)
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::PaymentProvider(e.to_string()))?
        .json()
        .await
        .map_err(|e| AppError::PaymentProvider(e.to_string()))?;

    if let Some(err) = resp.get("error") {
        return Err(AppError::PaymentProvider(
            err["message"].as_str().unwrap_or("Unknown Stripe error").to_string(),
        ));
    }

    resp["url"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| AppError::PaymentProvider("Stripe response missing checkout URL".into()))
}

// ── Customer Portal ───────────────────────────────────────────────────────────

/// Create a Stripe Customer Portal session and return its URL.
///
/// The portal lets the user update their payment method, change plan, or cancel.
pub async fn create_portal_session(
    config: &StripeConfig,
    http: &reqwest::Client,
    customer_id: &str,
    return_url: &str,
) -> Result<String, AppError> {
    let params = [
        ("customer", customer_id.to_string()),
        ("return_url", return_url.to_string()),
    ];

    let resp: serde_json::Value = http
        .post(format!("{STRIPE_API}/billing_portal/sessions"))
        .bearer_auth(&config.secret_key)
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::PaymentProvider(e.to_string()))?
        .json()
        .await
        .map_err(|e| AppError::PaymentProvider(e.to_string()))?;

    if let Some(err) = resp.get("error") {
        return Err(AppError::PaymentProvider(
            err["message"].as_str().unwrap_or("Unknown Stripe error").to_string(),
        ));
    }

    resp["url"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| AppError::PaymentProvider("Stripe portal response missing URL".into()))
}

// ── Webhook signature verification ───────────────────────────────────────────

/// Verify the `Stripe-Signature` header against the raw request body.
///
/// Stripe sends: `t=<timestamp>,v1=<sig>[,v1=<sig>...]`
/// We compute `HMAC-SHA256(webhook_secret, "<timestamp>.<body>")` and compare.
pub fn verify_signature(payload: &[u8], signature_header: &str, secret: &str) -> Result<(), AppError> {
    let mut timestamp: Option<&str> = None;
    let mut signatures: Vec<&str> = Vec::new();

    for part in signature_header.split(',') {
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = Some(t);
        } else if let Some(sig) = part.strip_prefix("v1=") {
            signatures.push(sig);
        }
    }

    let timestamp = timestamp
        .ok_or_else(|| AppError::Validation("Missing timestamp in Stripe-Signature header".into()))?;

    if signatures.is_empty() {
        return Err(AppError::Validation("No v1 signatures in Stripe-Signature header".into()));
    }

    let mut signed_payload = timestamp.as_bytes().to_vec();
    signed_payload.push(b'.');
    signed_payload.extend_from_slice(payload);

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| AppError::Validation(e.to_string()))?;
    mac.update(&signed_payload);
    let expected = hex::encode(mac.finalize().into_bytes());

    if signatures.iter().any(|s| *s == expected.as_str()) {
        Ok(())
    } else {
        Err(AppError::InvalidToken)
    }
}

// ── Webhook event dispatch ────────────────────────────────────────────────────

/// Dispatch a verified Stripe webhook event to the appropriate handler.
pub async fn handle_event(state: &AppState, body: &[u8]) -> Result<(), AppError> {
    let event: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| AppError::Validation(e.to_string()))?;

    let event_type = event["type"].as_str().unwrap_or("");
    let obj = &event["data"]["object"];

    log::info!("Stripe webhook event: {event_type}");

    match event_type {
        "checkout.session.completed" => on_checkout_completed(state, obj).await,
        "customer.subscription.updated" => on_subscription_updated(state, obj).await,
        "customer.subscription.deleted" => on_subscription_deleted(state, obj).await,
        "invoice.payment_failed" => on_invoice_payment_failed(state, obj).await,
        "invoice.payment_succeeded" => on_invoice_payment_succeeded(state, obj).await,
        other => {
            log::debug!("Unhandled Stripe event type: {other}");
            Ok(())
        }
    }
}

// ── Individual event handlers ─────────────────────────────────────────────────

async fn on_checkout_completed(state: &AppState, obj: &serde_json::Value) -> Result<(), AppError> {
    let subscription_id = obj["subscription"].as_str().unwrap_or_default();
    let customer_id = obj["customer"].as_str().unwrap_or_default();
    let metadata = &obj["metadata"];

    let user_id_str = metadata["user_id"].as_str().unwrap_or_default();
    let product = metadata["product"].as_str().unwrap_or("clann");
    let plan = metadata["plan"].as_str().unwrap_or("individual");
    let seat_count: i16 = metadata["seat_count"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    if subscription_id.is_empty() || customer_id.is_empty() || user_id_str.is_empty() {
        log::warn!("checkout.session.completed missing required fields — skipping");
        return Ok(());
    }

    let user_id: Uuid = match user_id_str.parse() {
        Ok(id) => id,
        Err(_) => {
            log::warn!("checkout.session.completed: invalid user_id '{user_id_str}'");
            return Ok(());
        }
    };

    // Fetch the subscription object from Stripe to get period dates and status.
    let stripe_config = match &state.stripe {
        Some(c) => c,
        None => return Ok(()),
    };
    let stripe_sub = fetch_subscription(stripe_config, &state.http_client, subscription_id).await?;

    let status = stripe_sub["status"].as_str().unwrap_or("active");
    let trial_end = epoch_to_datetime(stripe_sub["trial_end"].as_i64());
    let period_start = epoch_to_datetime(stripe_sub["current_period_start"].as_i64());
    let period_end = epoch_to_datetime(stripe_sub["current_period_end"].as_i64());

    db::activate_subscription(
        &state.pool,
        user_id,
        product,
        plan,
        "stripe",
        subscription_id,
        customer_id,
        seat_count,
        trial_end,
        period_start,
        period_end,
    )
    .await
    .map(|_| ())
    .or_else(|e| {
        if matches!(e, AppError::Conflict) {
            log::warn!(
                "checkout.session.completed: active subscription already exists for user {user_id} / {product}"
            );
            Ok(())
        } else {
            Err(e)
        }
    })?;

    log::info!(
        "Stripe subscription activated: user={user_id} product={product} plan={plan} status={status}"
    );

    if product == "clann" {
        db::ensure_comad_individual(&state.pool, user_id).await?;
        log::info!("Bundled Comad Individual subscription ensured for user={user_id}");
    }

    Ok(())
}

async fn on_subscription_updated(state: &AppState, obj: &serde_json::Value) -> Result<(), AppError> {
    let subscription_id = obj["id"].as_str().unwrap_or_default();
    let status = stripe_status_to_internal(obj["status"].as_str().unwrap_or("active"));
    let trial_end = epoch_to_datetime(obj["trial_end"].as_i64());
    let period_start = epoch_to_datetime(obj["current_period_start"].as_i64());
    let period_end = epoch_to_datetime(obj["current_period_end"].as_i64());

    if subscription_id.is_empty() {
        return Ok(());
    }

    db::update_subscription_period(&state.pool, subscription_id, status, trial_end, period_start, period_end).await?;
    log::info!("Stripe subscription updated: sub={subscription_id} status={status}");
    Ok(())
}

async fn on_subscription_deleted(state: &AppState, obj: &serde_json::Value) -> Result<(), AppError> {
    let subscription_id = obj["id"].as_str().unwrap_or_default();
    if subscription_id.is_empty() {
        return Ok(());
    }
    db::cancel_subscription(&state.pool, subscription_id).await?;
    log::info!("Stripe subscription cancelled: sub={subscription_id}");
    Ok(())
}

async fn on_invoice_payment_failed(state: &AppState, obj: &serde_json::Value) -> Result<(), AppError> {
    let subscription_id = obj["subscription"].as_str().unwrap_or_default();
    if subscription_id.is_empty() {
        return Ok(());
    }
    db::set_subscription_status(&state.pool, subscription_id, "past_due").await?;
    log::warn!("Stripe invoice payment failed: sub={subscription_id}");
    Ok(())
}

async fn on_invoice_payment_succeeded(
    state: &AppState,
    obj: &serde_json::Value,
) -> Result<(), AppError> {
    let subscription_id = obj["subscription"].as_str().unwrap_or_default();
    if subscription_id.is_empty() {
        return Ok(());
    }

    // Read the billing period from the first line item.
    let period = &obj["lines"]["data"][0]["period"];
    let period_start = epoch_to_datetime(period["start"].as_i64());
    let period_end = epoch_to_datetime(period["end"].as_i64());

    db::update_subscription_period(
        &state.pool,
        subscription_id,
        "active",
        None, // trial_end — not changed on a normal payment
        period_start,
        period_end,
    )
    .await?;

    log::info!("Stripe invoice payment succeeded: sub={subscription_id}");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn fetch_subscription(
    config: &StripeConfig,
    http: &reqwest::Client,
    subscription_id: &str,
) -> Result<serde_json::Value, AppError> {
    http.get(format!("{STRIPE_API}/subscriptions/{subscription_id}"))
        .bearer_auth(&config.secret_key)
        .send()
        .await
        .map_err(|e| AppError::PaymentProvider(e.to_string()))?
        .json()
        .await
        .map_err(|e| AppError::PaymentProvider(e.to_string()))
}

fn epoch_to_datetime(ts: Option<i64>) -> Option<DateTime<Utc>> {
    ts.and_then(|t| Utc.timestamp_opt(t, 0).single())
}

/// Map Stripe's subscription status strings to our internal values.
fn stripe_status_to_internal(s: &str) -> &str {
    match s {
        "active" => "active",
        "trialing" => "trialing",
        "past_due" | "unpaid" => "past_due",
        "canceled" | "cancelled" | "incomplete_expired" => "cancelled",
        _ => "pending",
    }
}
