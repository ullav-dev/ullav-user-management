//! PayPal Subscriptions API and webhook integration.
//!
//! Uses the PayPal REST API directly via reqwest.  Switch between sandbox
//! and production by setting `PAYPAL_SANDBOX=false` (default true).

use crate::{config::PayPalConfig, db, errors::AppError, AppState};
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ── Access token ──────────────────────────────────────────────────────────────

/// Obtain a short-lived OAuth2 access token from PayPal.
///
/// Tokens are valid for ~9 hours.  For simplicity we fetch a fresh token per
/// request; caching can be added later if rate limits become a concern.
pub async fn get_access_token(
    config: &PayPalConfig,
    http: &reqwest::Client,
) -> Result<String, AppError> {
    let resp: serde_json::Value = http
        .post(format!("{}/v1/oauth2/token", config.api_base))
        .basic_auth(&config.client_id, Some(&config.client_secret))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .map_err(|e| AppError::PaymentProvider(e.to_string()))?
        .json()
        .await
        .map_err(|e| AppError::PaymentProvider(e.to_string()))?;

    resp["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| AppError::PaymentProvider("PayPal token response missing access_token".into()))
}

// ── Subscription creation ─────────────────────────────────────────────────────

/// Create a PayPal Billing Subscription and return the user approval URL.
///
/// The `custom_id` field encodes `{user_id}:{product}:{plan}:{seat_count}` so
/// the webhook handler can identify the subscriber without a DB lookup.
pub async fn create_subscription(
    config: &PayPalConfig,
    http: &reqwest::Client,
    user_id: Uuid,
    user_email: &str,
    plan: &str,
    seat_count: i16,
    return_url: &str,
    cancel_url: &str,
) -> Result<String, AppError> {
    let plan_id = match plan {
        "family" => &config.plan_id_clann_family,
        "professional" => &config.plan_id_clann_professional,
        other => {
            return Err(AppError::Validation(format!(
                "Plan '{other}' does not support PayPal checkout"
            )));
        }
    };

    let token = get_access_token(config, http).await?;

    // custom_id carries subscriber context through to the webhook.
    let custom_id = format!("{user_id}:clann:{plan}:{seat_count}");

    let body = serde_json::json!({
        "plan_id": plan_id,
        // quantity maps to seat count for plans that support it
        "quantity": seat_count.to_string(),
        "custom_id": custom_id,
        "subscriber": {
            "email_address": user_email
        },
        "application_context": {
            "return_url": return_url,
            "cancel_url": cancel_url,
            "user_action": "SUBSCRIBE_NOW",
            "shipping_preference": "NO_SHIPPING"
        }
    });

    let resp: serde_json::Value = http
        .post(format!("{}/v1/billing/subscriptions", config.api_base))
        .bearer_auth(&token)
        .header("Prefer", "return=representation")
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::PaymentProvider(e.to_string()))?
        .json()
        .await
        .map_err(|e| AppError::PaymentProvider(e.to_string()))?;

    if let Some(name) = resp["name"].as_str() {
        let msg = resp["message"].as_str().unwrap_or("Unknown PayPal error");
        return Err(AppError::PaymentProvider(format!("{name}: {msg}")));
    }

    // Find the approve link in the HATEOAS links array.
    resp["links"]
        .as_array()
        .and_then(|links| {
            links
                .iter()
                .find(|l| l["rel"].as_str() == Some("approve"))
                .and_then(|l| l["href"].as_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| {
            AppError::PaymentProvider("PayPal response missing approve link".into())
        })
}

// ── Webhook signature verification ───────────────────────────────────────────

/// Verify a PayPal webhook event using their verification API.
///
/// PayPal requires an API call (not a local HMAC) to verify signatures.
/// Returns `Ok(())` if verification succeeds, `Err(InvalidToken)` otherwise.
pub async fn verify_signature(
    config: &PayPalConfig,
    http: &reqwest::Client,
    transmission_id: &str,
    transmission_time: &str,
    cert_url: &str,
    auth_algo: &str,
    transmission_sig: &str,
    raw_body: &serde_json::Value,
) -> Result<(), AppError> {
    let token = get_access_token(config, http).await?;

    let verify_body = serde_json::json!({
        "auth_algo": auth_algo,
        "cert_url": cert_url,
        "transmission_id": transmission_id,
        "transmission_sig": transmission_sig,
        "transmission_time": transmission_time,
        "webhook_id": config.webhook_id,
        "webhook_event": raw_body
    });

    let resp: serde_json::Value = http
        .post(format!(
            "{}/v1/notifications/verify-webhook-signature",
            config.api_base
        ))
        .bearer_auth(&token)
        .json(&verify_body)
        .send()
        .await
        .map_err(|e| AppError::PaymentProvider(e.to_string()))?
        .json()
        .await
        .map_err(|e| AppError::PaymentProvider(e.to_string()))?;

    match resp["verification_status"].as_str() {
        Some("SUCCESS") => Ok(()),
        other => {
            log::warn!(
                "PayPal webhook verification status: {}",
                other.unwrap_or("unknown")
            );
            Err(AppError::InvalidToken)
        }
    }
}

// ── Webhook event dispatch ────────────────────────────────────────────────────

/// Dispatch a verified PayPal webhook event to the appropriate handler.
pub async fn handle_event(state: &AppState, event: &serde_json::Value) -> Result<(), AppError> {
    let event_type = event["event_type"].as_str().unwrap_or("");
    let resource = &event["resource"];

    log::info!("PayPal webhook event: {event_type}");

    match event_type {
        "BILLING.SUBSCRIPTION.ACTIVATED" => on_subscription_activated(state, resource).await,
        "BILLING.SUBSCRIPTION.CANCELLED" => on_subscription_cancelled(state, resource).await,
        "BILLING.SUBSCRIPTION.SUSPENDED" => on_subscription_suspended(state, resource).await,
        "BILLING.SUBSCRIPTION.PAYMENT.FAILED" => on_payment_failed(state, resource).await,
        "PAYMENT.SALE.COMPLETED" => on_payment_completed(state, resource).await,
        other => {
            log::debug!("Unhandled PayPal event type: {other}");
            Ok(())
        }
    }
}

// ── Individual event handlers ─────────────────────────────────────────────────

async fn on_subscription_activated(
    state: &AppState,
    resource: &serde_json::Value,
) -> Result<(), AppError> {
    let subscription_id = resource["id"].as_str().unwrap_or_default();
    let custom_id = resource["custom_id"].as_str().unwrap_or_default();

    if subscription_id.is_empty() || custom_id.is_empty() {
        log::warn!("BILLING.SUBSCRIPTION.ACTIVATED: missing id or custom_id");
        return Ok(());
    }

    // custom_id = "{user_id}:{product}:{plan}:{seat_count}"
    let parts: Vec<&str> = custom_id.splitn(4, ':').collect();
    if parts.len() < 4 {
        log::warn!("BILLING.SUBSCRIPTION.ACTIVATED: malformed custom_id '{custom_id}'");
        return Ok(());
    }

    let user_id: Uuid = match parts[0].parse() {
        Ok(id) => id,
        Err(_) => {
            log::warn!("BILLING.SUBSCRIPTION.ACTIVATED: invalid user_id in custom_id");
            return Ok(());
        }
    };
    let product = parts[1];
    let plan = parts[2];
    let seat_count: i16 = parts[3].parse().unwrap_or(1);

    let subscriber_email = resource["subscriber"]["email_address"]
        .as_str()
        .unwrap_or_default();

    // Billing period from the subscription resource.
    let period_start = parse_paypal_time(resource["start_time"].as_str());
    let period_end = parse_paypal_time(
        resource["billing_info"]["next_billing_time"].as_str(),
    );

    db::activate_subscription(
        &state.pool,
        user_id,
        product,
        plan,
        "paypal",
        subscription_id,
        subscriber_email, // use email as customer identifier for PayPal
        seat_count,
        None,         // PayPal free-trial period handled via plan definition
        period_start,
        period_end,
    )
    .await
    .map(|_| ())
    .or_else(|e| {
        if matches!(e, AppError::Conflict) {
            log::warn!("BILLING.SUBSCRIPTION.ACTIVATED: subscription already exists for user {user_id}");
            Ok(())
        } else {
            Err(e)
        }
    })?;

    log::info!(
        "PayPal subscription activated: sub={subscription_id} user={user_id} plan={plan}"
    );
    Ok(())
}

async fn on_subscription_cancelled(
    state: &AppState,
    resource: &serde_json::Value,
) -> Result<(), AppError> {
    let subscription_id = resource["id"].as_str().unwrap_or_default();
    if subscription_id.is_empty() {
        return Ok(());
    }
    db::cancel_subscription(&state.pool, subscription_id).await?;
    log::info!("PayPal subscription cancelled: sub={subscription_id}");
    Ok(())
}

async fn on_subscription_suspended(
    state: &AppState,
    resource: &serde_json::Value,
) -> Result<(), AppError> {
    let subscription_id = resource["id"].as_str().unwrap_or_default();
    if subscription_id.is_empty() {
        return Ok(());
    }
    db::set_subscription_status(&state.pool, subscription_id, "past_due").await?;
    log::warn!("PayPal subscription suspended: sub={subscription_id}");
    Ok(())
}

async fn on_payment_failed(
    state: &AppState,
    resource: &serde_json::Value,
) -> Result<(), AppError> {
    // For payment failure events the subscription ID is nested differently
    // depending on the event version. Try both locations.
    let subscription_id = resource["id"]
        .as_str()
        .or_else(|| resource["billing_agreement_id"].as_str())
        .unwrap_or_default();

    if subscription_id.is_empty() {
        return Ok(());
    }
    db::set_subscription_status(&state.pool, subscription_id, "past_due").await?;
    log::warn!("PayPal payment failed: sub={subscription_id}");
    Ok(())
}

async fn on_payment_completed(
    state: &AppState,
    resource: &serde_json::Value,
) -> Result<(), AppError> {
    let subscription_id = resource["billing_agreement_id"].as_str().unwrap_or_default();
    if subscription_id.is_empty() {
        return Ok(());
    }

    let period_end: Option<DateTime<Utc>> = parse_paypal_time(
        resource["transaction_fee"]["payee"]["merchant_id"] // fallback: no period info in this event
            .as_str(),
    );

    // PayPal's PAYMENT.SALE.COMPLETED doesn't include the new billing period.
    // We set status to active and leave period_end unchanged (it updates on the
    // next BILLING.SUBSCRIPTION.ACTIVATED or subscription GET).
    db::update_subscription_period(
        &state.pool,
        subscription_id,
        "active",
        None,
        None,
        period_end,
    )
    .await?;

    log::info!("PayPal payment completed: sub={subscription_id}");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_paypal_time(s: Option<&str>) -> Option<DateTime<Utc>> {
    s.and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|dt| dt.with_timezone(&Utc))
}
