/// Stripe payment configuration.
///
/// Present in `AppState` only when all required Stripe env vars are set.
/// Missing configuration causes checkout/portal endpoints to return 501.
#[derive(Clone)]
pub struct StripeConfig {
    pub secret_key: String,
    pub webhook_secret: String,
    /// Stripe Price ID for the Family/Team base subscription (€5/mo, 2 seats).
    pub price_id_clann_family_base: String,
    /// Stripe Price ID for each additional Family/Team seat beyond 2 (€2/mo).
    pub price_id_clann_family_seat: String,
    /// Stripe Price ID for the Professional subscription (€15/mo).
    pub price_id_clann_professional: String,
}

/// PayPal payment configuration.
///
/// Present in `AppState` only when all required PayPal env vars are set.
#[derive(Clone)]
pub struct PayPalConfig {
    pub client_id: String,
    pub client_secret: String,
    /// PayPal Billing Plan ID for the Clann Family/Team subscription.
    pub plan_id_clann_family: String,
    /// PayPal Billing Plan ID for the Clann Professional subscription.
    pub plan_id_clann_professional: String,
    /// PayPal Webhook ID used for signature verification.
    pub webhook_id: String,
    /// API base URL — sandbox or live.
    /// Sandbox:    <https://api-m.sandbox.paypal.com>
    /// Production: <https://api-m.paypal.com>
    pub api_base: String,
}
