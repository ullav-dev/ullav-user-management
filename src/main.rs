use actix_cors::Cors;
use actix_web::{http, middleware::Logger, web, App, HttpServer};
use deadpool_postgres::{Config as PoolConfig, Runtime};
use dotenv::dotenv;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use std::{collections::HashSet, env, net::IpAddr, sync::Arc};
use tokio::sync::RwLock;
use tokio_postgres::NoTls;
use utils::key_store::KeyStore;
use utils::rate_limit::RateLimiter;

pub(crate) fn resolve_secret(name: &str) -> Option<String> {
    utils::resolve_secret(name)
}

mod config;
mod db;
mod errors;
mod handlers;
mod middleware;
mod models;
mod payments;
mod seed;
mod utils;
#[cfg(test)]
mod tests;

/// Shared application state injected into every handler via `web::Data`.
#[derive(Clone)]
pub struct AppState {
    pub pool: deadpool_postgres::Pool,
    pub jwt_secret: String,
    /// Lifetime of a JWT in hours.
    pub jwt_ttl_hours: i64,
    /// Lifetime of a password-reset token in minutes.
    pub reset_token_ttl_minutes: i64,
    /// Lifetime of an email-confirmation token in minutes.
    pub confirmation_token_ttl_minutes: i64,
    /// SMTP mailer — `None` when `SMTP_HOST` is not configured.
    pub mailer: Option<AsyncSmtpTransport<Tokio1Executor>>,
    pub smtp_from: String,
    pub app_base_url: String,
    /// Allowlist of caller-supplied `app_url` values accepted in request bodies.
    /// Empty when `ALLOWED_APP_URLS` is not configured (single-tenant mode).
    pub allowed_app_urls: Vec<String>,
    /// Shared HTTP client for payment provider API calls.
    pub http_client: reqwest::Client,
    /// Stripe configuration — `None` when Stripe env vars are not set.
    pub stripe: Option<config::StripeConfig>,
    /// PayPal configuration — `None` when PayPal env vars are not set.
    pub paypal: Option<config::PayPalConfig>,
    /// Base URL of the Clann app — used to build checkout return/cancel URLs.
    pub clann_app_url: String,
    /// RS256 signing keys. Wrapped in Arc<RwLock> so admin key-rotation handlers can
    /// update the in-memory store immediately without a restart.
    pub oauth2_keys: Arc<RwLock<KeyStore>>,
    /// Key Encryption Key (AES-256-GCM) for encrypting RSA private key PEMs in DB.
    /// `None` in single-key mode; required for the generate-key admin endpoint.
    pub kek: Option<Arc<utils::key_encrypt::KeyEncryptionKey>>,
    /// Issuer URL for OAuth2 tokens and AS metadata (`OAUTH2_ISSUER` env var).
    pub oauth2_issuer: String,
    /// Rate limiter for /oauth2/token: max 20 requests per IP per minute.
    pub token_rate_limiter: RateLimiter,
    /// Rate limiter for /oauth2/register: max 10 registrations per IP per hour.
    pub register_rate_limiter: RateLimiter,
    /// Shared secret required (via `X-Git-Service-Secret`) on `/pat/exchange`
    /// and `/ssh-keys/resolve` — both accept a raw credential instead of a
    /// Bearer JWT, so without this gate they'd be an open "is this token
    /// valid" oracle on a publicly reachable listener. `None` (unset) leaves
    /// the gate open — fine for local dev, not for production.
    pub git_service_shared_secret: Option<String>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let jwt_secret = resolve_secret("JWT_SECRET")
        .expect("JWT_SECRET (or JWT_SECRET_FILE) must be set");
    let jwt_ttl_hours: i64 = env::var("JWT_TTL_HOURS")
        .unwrap_or_else(|_| "24".into())
        .parse()
        .expect("JWT_TTL_HOURS must be an integer");
    let reset_token_ttl_minutes: i64 = env::var("RESET_TOKEN_TTL_MINUTES")
        .unwrap_or_else(|_| "30".into())
        .parse()
        .expect("RESET_TOKEN_TTL_MINUTES must be an integer");
    let confirmation_token_ttl_minutes: i64 = env::var("CONFIRMATION_TOKEN_TTL_MINUTES")
        .unwrap_or_else(|_| "1440".into())
        .parse()
        .expect("CONFIRMATION_TOKEN_TTL_MINUTES must be an integer");
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "8081".into())
        .parse()
        .expect("PORT must be a number");
    let enable_docs: bool = env::var("ENABLE_DOCS")
        .unwrap_or_else(|_| "true".into())
        .parse()
        .unwrap_or(true);
    let require_https: bool = env::var("REQUIRE_HTTPS")
        .unwrap_or_else(|_| "true".into())
        .parse()
        .unwrap_or(true);
    let https_whitelist: Vec<IpAddr> = env::var("WHITELIST")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect();
    if require_https {
        log::info!(
            "HTTPS enforcement enabled — {} additional whitelisted IP(s)",
            https_whitelist.len()
        );
    } else {
        log::info!("HTTPS enforcement disabled (REQUIRE_HTTPS=false)");
    }

    // Geo-blocking — optional; requires GEOBLOCK (country codes) + GEOIP_DB (path to .mmdb).
    let geoblock_countries: Arc<HashSet<String>> = Arc::new(
        env::var("GEOBLOCK")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_uppercase())
            .filter(|s| !s.is_empty())
            .collect(),
    );
    let geoip_reader: Option<Arc<maxminddb::Reader<Vec<u8>>>> = if geoblock_countries.is_empty() {
        None
    } else {
        match env::var("GEOIP_DB") {
            Ok(path) => {
                match std::fs::read(&path)
                    .map_err(|e| e.to_string())
                    .and_then(|b| maxminddb::Reader::from_source(b).map_err(|e| e.to_string()))
                {
                    Ok(reader) => {
                        log::info!(
                            "GeoIP database loaded from {} — blocking {} country code(s): {:?}",
                            path,
                            geoblock_countries.len(),
                            geoblock_countries,
                        );
                        Some(Arc::new(reader))
                    }
                    Err(e) => {
                        log::error!("Failed to load GeoIP database from {}: {}", path, e);
                        None
                    }
                }
            }
            Err(_) => {
                log::warn!("GEOBLOCK is set but GEOIP_DB is not configured — geo-blocking disabled");
                None
            }
        }
    };

    // SMTP configuration — all optional; email is disabled if SMTP_HOST is absent.
    let smtp_host = env::var("SMTP_HOST").ok();
    let smtp_port: u16 = env::var("SMTP_PORT")
        .unwrap_or_else(|_| "587".into())
        .parse()
        .expect("SMTP_PORT must be a number");
    let smtp_username = env::var("SMTP_USERNAME").ok();
    let smtp_password = resolve_secret("SMTP_PASSWORD");
    let smtp_from = env::var("SMTP_FROM").unwrap_or_default();
    let app_base_url = env::var("APP_BASE_URL").unwrap_or_default();
    let allowed_app_urls: Vec<String> = env::var("ALLOWED_APP_URLS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    if allowed_app_urls.is_empty() {
        log::info!("ALLOWED_APP_URLS not set — app_url in requests ignored, using APP_BASE_URL");
    } else {
        log::info!(
            "ALLOWED_APP_URLS configured — {} allowed URL(s)",
            allowed_app_urls.len()
        );
    }
    let smtp_no_tls: bool = env::var("SMTP_NO_TLS")
        .unwrap_or_else(|_| "false".into())
        .parse()
        .unwrap_or(false);

    let mailer = if let Some(ref h) = smtp_host {
        match utils::email::build_mailer(h, smtp_port, smtp_username, smtp_password, smtp_no_tls) {
            Ok(m) => {
                log::info!("SMTP mailer configured for {}:{}", h, smtp_port);
                Some(m)
            }
            Err(e) => {
                log::error!("Failed to build SMTP mailer: {}", e);
                None
            }
        }
    } else {
        log::info!("SMTP_HOST not set — email sending disabled");
        None
    };

    // CORS — optional; set CORS_ORIGINS to "*" or a comma-separated list of allowed origins.
    let cors_origins: Vec<String> = env::var("CORS_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    if cors_origins.is_empty() {
        log::info!("CORS_ORIGINS not set — CORS disabled");
    } else if cors_origins == ["*"] {
        log::info!("CORS enabled — any origin allowed");
    } else {
        log::info!("CORS enabled — {} allowed origin(s)", cors_origins.len());
    }

    // Admin seed — credentials configurable via env vars.
    let admin_username = env::var("ADMIN_USERNAME").unwrap_or_else(|_| "theboss".into());
    let admin_password = resolve_secret("ADMIN_PASSWORD").unwrap_or_else(|| "changeme".into());
    let admin_email    = env::var("ADMIN_EMAIL").unwrap_or_else(|_| "admin@localhost".into());

    // Build the connection pool.
    // Supports DATABASE_URL_FILE (Docker secrets) as well as a plain DATABASE_URL.
    let database_url = resolve_secret("DATABASE_URL")
        .expect("DATABASE_URL (or DATABASE_URL_FILE) must be set");
    let mut cfg = PoolConfig::new();
    cfg.url = Some(database_url);
    let pool = cfg
        .create_pool(Some(Runtime::Tokio1), NoTls)
        .expect("failed to create database pool");

    // Seed admin user (idempotent — no-op if already exists).
    if let Err(e) = seed::seed_admin(&pool, &admin_username, &admin_email, &admin_password).await {
        log::error!("Failed to seed admin user: {}", e);
    }

    // Payment configuration — optional; endpoints return 501 when not set.
    let stripe_config = build_stripe_config();
    let paypal_config = build_paypal_config();
    if stripe_config.is_some() {
        log::info!("Stripe payment integration enabled");
    } else {
        log::info!("STRIPE_SECRET_KEY not set — Stripe disabled");
    }
    if paypal_config.is_some() {
        log::info!("PayPal payment integration enabled");
    } else {
        log::info!("PAYPAL_CLIENT_ID not set — PayPal disabled");
    }

    let clann_app_url = env::var("CLANN_APP_URL")
        .unwrap_or_else(|_| "http://localhost:3000".into());

    // OAuth2 — load RS256 signing key(s).
    // If OAUTH2_KEY_ENCRYPTION_KEY is set, keys are loaded from the DB (DB-backed mode).
    // Otherwise, the single OAUTH2_SIGNING_KEY env var is used (single-key mode).
    let oauth2_keys = utils::key_store::init_key_store(&pool)
        .await
        .expect("Failed to initialise OAuth2 signing key store");
    let oauth2_keys = Arc::new(RwLock::new(oauth2_keys));
    // Keep a separate clone for the AuthMiddleware in the HttpServer closure —
    // the original Arc is moved into AppState below.
    let oauth2_keys_middleware = oauth2_keys.clone();

    let kek = env::var("OAUTH2_KEY_ENCRYPTION_KEY")
        .ok()
        .and_then(|b64| {
            utils::key_encrypt::KeyEncryptionKey::from_base64(&b64)
                .map(Arc::new)
                .map_err(|e| { log::error!("Failed to load OAUTH2_KEY_ENCRYPTION_KEY: {e}"); e })
                .ok()
        });

    let oauth2_issuer = env::var("OAUTH2_ISSUER")
        .unwrap_or_else(|_| "http://localhost:8081".into());
    log::info!("OAuth2 issuer: {}", oauth2_issuer);

    let http_client = reqwest::Client::new();

    let git_service_shared_secret = resolve_secret("GIT_SERVICE_SHARED_SECRET");
    if git_service_shared_secret.is_none() {
        log::warn!(
            "GIT_SERVICE_SHARED_SECRET not set — /pat/exchange and /ssh-keys/resolve are \
             callable by anyone on the network, not just lagan-server; set this in any \
             deployment where these endpoints are reachable outside a trusted service mesh"
        );
    }

    let state = web::Data::new(AppState {
        pool,
        jwt_secret: jwt_secret.clone(),
        jwt_ttl_hours,
        reset_token_ttl_minutes,
        confirmation_token_ttl_minutes,
        mailer,
        smtp_from,
        app_base_url,
        allowed_app_urls,
        http_client,
        stripe: stripe_config,
        paypal: paypal_config,
        clann_app_url,
        oauth2_keys,
        kek,
        oauth2_issuer,
        token_rate_limiter: RateLimiter::new(20, std::time::Duration::from_secs(60)),
        register_rate_limiter: RateLimiter::new(10, std::time::Duration::from_secs(3600)),
        git_service_shared_secret,
    });

    log::info!("Starting server on {}:{}", host, port);

    HttpServer::new(move || {
        // Build CORS middleware.
        let cors = if cors_origins == ["*"] {
            Cors::default()
                .allow_any_origin()
                .allowed_methods(["GET", "POST", "PUT", "DELETE", "OPTIONS"])
                .allowed_headers([http::header::AUTHORIZATION, http::header::CONTENT_TYPE, http::header::ACCEPT])
                .max_age(3600)
        } else if cors_origins.is_empty() {
            Cors::default()
        } else {
            let mut c = Cors::default()
                .allowed_methods(["GET", "POST", "PUT", "DELETE", "OPTIONS"])
                .allowed_headers([http::header::AUTHORIZATION, http::header::CONTENT_TYPE, http::header::ACCEPT])
                .supports_credentials()
                .max_age(3600);
            for origin in &cors_origins {
                c = c.allowed_origin(origin);
            }
            c
        };

        let mut app = App::new()
            .app_data(state.clone())
            .wrap(Logger::default())
            .wrap(middleware::https::HttpsOnly::new(&https_whitelist, require_https))
            .wrap(middleware::geo::GeoBlock::new(
                geoip_reader.clone(),
                geoblock_countries.clone(),
            ))
            .wrap(cors)
            // Open routes — no authentication required
            .service(handlers::users::create_user)
            .service(handlers::auth::login)
            .service(handlers::auth::confirm_email)
            .service(handlers::auth::confirm_email_get)
            .service(handlers::auth::request_password_reset)
            .service(handlers::auth::confirm_password_reset)
            // OAuth2 Authorization Server — all unauthenticated (bootstraps auth)
            .service(handlers::oauth2::as_metadata)
            .service(handlers::oauth2::jwks)
            .service(handlers::oauth2::register)
            .service(handlers::oauth2::authorize_get)
            .service(handlers::oauth2::authorize_post)
            .service(handlers::oauth2::token)
            .service(handlers::oauth2::revoke)
            // Git credential exchange — the credential itself (PAT / SSH key
            // fingerprint) is the auth, not a Bearer JWT, so these are
            // unauthenticated at the actix-web level and instead gated by
            // `check_service_secret` inside each handler.
            .service(handlers::pat::exchange)
            .service(handlers::ssh_keys::resolve);

        if enable_docs {
            app = app
                .service(handlers::docs::openapi_spec)
                .service(handlers::docs::openapi_spec_json)
                .service(handlers::docs::swagger_ui);
        }

        app
            // JWT required — all protected routes in one scope to avoid prefix-matching conflicts.
            // Per-route permission enforcement is handled by nested scopes with path prefixes.
            .service(
                web::scope("")
                    .wrap(middleware::auth::AuthMiddleware::new(jwt_secret.clone(), oauth2_keys_middleware.clone()))
                    // Any authenticated user
                    .service(handlers::auth::refresh)
                    .service(handlers::auth::change_password)
                    .service(handlers::profile::get_me)
                    .service(handlers::profile::update_me)
                    .service(handlers::users::resolve_users)
                    .service(handlers::user_ai_settings::get_ai_settings)
                    .service(handlers::user_ai_settings::upsert_ai_settings)
                    .service(handlers::user_ai_settings::delete_ai_settings)
                    .service(handlers::subscriptions::get_current_subscription)
                    .service(handlers::subscriptions::create_checkout_session)
                    .service(handlers::subscriptions::create_portal_session)
                    // Personal access tokens & SSH keys — self-service, no
                    // permission beyond being authenticated (ownership checks
                    // happen inside each handler).
                    .service(handlers::pat::create_pat)
                    .service(handlers::pat::list_pats)
                    .service(handlers::pat::revoke_pat)
                    .service(handlers::ssh_keys::create_ssh_key)
                    .service(handlers::ssh_keys::list_ssh_keys)
                    .service(handlers::ssh_keys::delete_ssh_key)
                    // Teams — permission-checked inside handlers; invite accept/decline registered
                    // before /{id} routes so static "invitations" segment wins over UUID param.
                    .service(handlers::teams::list_my_teams)
                    .service(handlers::teams::accept_invitation)
                    .service(handlers::teams::decline_invitation)
                    .service(handlers::teams::get_team_by_slug)
                    .service(handlers::teams::create_team)
                    .service(handlers::teams::get_team)
                    .service(handlers::teams::update_team)
                    .service(handlers::teams::delete_team)
                    .service(handlers::teams::invite_member)
                    .service(handlers::teams::resend_invitation)
                    .service(handlers::teams::remove_member)
                    // Team roles — ownership/membership checks inside handlers.
                    // Role routes registered before member-role routes so the
                    // static /roles segment wins over /{role_id} where ambiguous.
                    .service(handlers::teams::list_team_roles)
                    .service(handlers::teams::create_team_role)
                    .service(handlers::teams::update_team_role)
                    .service(handlers::teams::delete_team_role)
                    .service(handlers::teams::assign_member_role)
                    .service(handlers::teams::unassign_member_role)
                    // Product roles — owner assigns product-specific roles to members
                    .service(handlers::teams::assign_member_product_role)
                    .service(handlers::teams::revoke_member_product_role)
                    // Health — requires `health:read`; use /health prefix to isolate
                    .service(
                        web::scope("/health")
                            .wrap(middleware::auth::AuthMiddleware::require(
                                jwt_secret.clone(),
                                oauth2_keys_middleware.clone(),
                                "health:read",
                            ))
                            .service(handlers::health::health_scoped),
                    )
                    // OAuth2 key management — requires `oauth2:manage` (separate from users:read).
                    //
                    // Registered BEFORE the broader `/admin` scope below: actix-web's Scope
                    // routing commits to the first scope whose prefix matches and does not
                    // backtrack to try sibling scopes if the specific sub-route isn't found
                    // within it. Since `/admin` is itself a prefix of `/admin/oauth2/...`, this
                    // scope was completely unreachable when registered after `/admin` — every
                    // request landed inside `/admin`'s middleware (gated by `users:read`, not
                    // `oauth2:manage`), found no matching internal route, and 404'd from within
                    // it. Confirmed via a temporary debug trace on the auth middleware: the
                    // `required_permission` it logged for a request to `/admin/oauth2/keys` was
                    // `Some("users:read")`, not `Some("oauth2:manage")`. Pre-existing bug, not
                    // introduced by the `client_credentials` work — this fix also makes
                    // `list_oauth2_keys`/`generate_oauth2_key`/`promote_oauth2_key`/
                    // `retire_oauth2_key` reachable for the first time.
                    .service(
                        web::scope("/admin/oauth2")
                            .wrap(middleware::auth::AuthMiddleware::require(
                                jwt_secret.clone(),
                                oauth2_keys_middleware.clone(),
                                "oauth2:manage",
                            ))
                            .service(handlers::admin::list_oauth2_keys)
                            .service(handlers::admin::generate_oauth2_key)
                            .service(handlers::admin::promote_oauth2_key)
                            .service(handlers::admin::retire_oauth2_key)
                            .service(handlers::admin::create_service_client)
                            .service(handlers::admin::list_service_clients)
                            .service(handlers::admin::delete_service_client),
                    )
                    // Git credential audit (all users' PATs/SSH keys) — requires
                    // `git_credentials:manage`, distinct from `users:read`. Registered
                    // BEFORE the broader `/admin` scope below for the same reason as
                    // `/admin/oauth2` above: actix-web commits to the first matching
                    // scope prefix and won't fall through to a sibling scope.
                    .service(
                        web::scope("/admin/git-credentials")
                            .wrap(middleware::auth::AuthMiddleware::require(
                                jwt_secret.clone(),
                                oauth2_keys_middleware.clone(),
                                "git_credentials:manage",
                            ))
                            .service(handlers::pat::admin_list_pats)
                            .service(handlers::ssh_keys::admin_list_ssh_keys),
                    )
                    // Admin user/role/subscription/team management — requires `users:read`
                    .service(
                        web::scope("/admin")
                            .wrap(middleware::auth::AuthMiddleware::require(
                                jwt_secret.clone(),
                                oauth2_keys_middleware.clone(),
                                "users:read",
                            ))
                            // Users
                            .service(handlers::admin::list_users)
                            .service(handlers::admin::create_user)
                            .service(handlers::admin::get_user)
                            .service(handlers::admin::update_user)
                            .service(handlers::admin::delete_user)
                            .service(handlers::admin::add_user_role)
                            .service(handlers::admin::remove_user_role)
                            .service(handlers::admin::list_user_subscriptions)
                            .service(handlers::admin::list_user_teams)
                            .service(handlers::admin::create_user_subscription)
                            // Roles & permissions
                            .service(handlers::admin::list_roles)
                            .service(handlers::admin::create_role)
                            .service(handlers::admin::delete_role)
                            .service(handlers::admin::list_permissions)
                            .service(handlers::admin::create_permission)
                            .service(handlers::admin::add_role_permission)
                            .service(handlers::admin::remove_role_permission)
                            // Subscriptions
                            .service(handlers::admin::list_subscriptions)
                            .service(handlers::admin::update_subscription)
                            .service(handlers::admin::delete_subscription)
                            // Products
                            .service(handlers::admin::list_products)
                            // Plans
                            .service(handlers::admin::list_plans)
                            .service(handlers::admin::create_plan)
                            .service(handlers::admin::delete_plan)
                            // Teams
                            .service(handlers::admin::list_teams)
                            .service(handlers::admin::create_team)
                            .service(handlers::admin::get_team)
                            .service(handlers::admin::update_team)
                            .service(handlers::admin::delete_team)
                            .service(handlers::admin::add_team_member)
                            .service(handlers::admin::remove_team_member)
                            // Team product access
                            .service(handlers::admin::list_team_products)
                            .service(handlers::admin::enable_team_product)
                            .service(handlers::admin::disable_team_product)
                            .service(handlers::admin::assign_member_product_role)
                            .service(handlers::admin::revoke_member_product_role),
                    ),
            )
            // Webhook endpoints — no auth, provider-signed payloads
            .service(handlers::subscriptions::stripe_webhook)
            .service(handlers::subscriptions::paypal_webhook)
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}

// ── Payment config helpers ────────────────────────────────────────────────────

fn build_stripe_config() -> Option<config::StripeConfig> {
    let secret_key = resolve_secret("STRIPE_SECRET_KEY")?;
    let webhook_secret = resolve_secret("STRIPE_WEBHOOK_SECRET").unwrap_or_default();
    let price_id_clann_family_base = env::var("STRIPE_PRICE_CLANN_FAMILY_BASE").ok()?;
    let price_id_clann_family_seat = env::var("STRIPE_PRICE_CLANN_FAMILY_SEAT").ok()?;
    let price_id_clann_professional = env::var("STRIPE_PRICE_CLANN_PROFESSIONAL").ok()?;
    Some(config::StripeConfig {
        secret_key,
        webhook_secret,
        price_id_clann_family_base,
        price_id_clann_family_seat,
        price_id_clann_professional,
    })
}

fn build_paypal_config() -> Option<config::PayPalConfig> {
    let client_id = resolve_secret("PAYPAL_CLIENT_ID")?;
    let client_secret = resolve_secret("PAYPAL_CLIENT_SECRET")?;
    let plan_id_clann_family = env::var("PAYPAL_PLAN_CLANN_FAMILY").ok()?;
    let plan_id_clann_professional = env::var("PAYPAL_PLAN_CLANN_PROFESSIONAL").ok()?;
    let webhook_id = env::var("PAYPAL_WEBHOOK_ID").unwrap_or_default();
    let sandbox: bool = env::var("PAYPAL_SANDBOX")
        .unwrap_or_else(|_| "true".into())
        .parse()
        .unwrap_or(true);
    let api_base = if sandbox {
        "https://api-m.sandbox.paypal.com".into()
    } else {
        "https://api-m.paypal.com".into()
    };
    Some(config::PayPalConfig {
        client_id,
        client_secret,
        plan_id_clann_family,
        plan_id_clann_professional,
        webhook_id,
        api_base,
    })
}
