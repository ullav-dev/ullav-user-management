use actix_cors::Cors;
use actix_web::{http, middleware::Logger, web, App, HttpServer};
use deadpool_postgres::{Config as PoolConfig, Runtime};
use dotenv::dotenv;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use std::{collections::HashSet, env, net::IpAddr, sync::Arc};
use tokio_postgres::NoTls;

/// Resolve a secret value, preferring the Docker-secrets `_FILE` convention.
///
/// If `{name}_FILE` is set, the file at that path is read and its contents
/// trimmed (Docker writes a trailing newline). Falls back to the plain `{name}`
/// env var. Returns `None` when neither is present.
fn resolve_secret(name: &str) -> Option<String> {
    let file_key = format!("{}_FILE", name);
    if let Ok(path) = env::var(&file_key) {
        match std::fs::read_to_string(&path) {
            Ok(contents) => return Some(contents.trim().to_string()),
            Err(e) => log::warn!(
                "{} points to {:?} but the file could not be read: {} — falling back to {}",
                file_key, path, e, name
            ),
        }
    }
    env::var(name).ok()
}

mod db;
mod errors;
mod handlers;
mod middleware;
mod models;
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
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
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
    let https_whitelist: Vec<IpAddr> = env::var("WHITELIST")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect();
    log::info!(
        "HTTPS enforcement enabled — {} additional whitelisted IP(s)",
        https_whitelist.len()
    );

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
    let mut cfg = PoolConfig::new();
    cfg.url = Some(database_url);
    let pool = cfg
        .create_pool(Some(Runtime::Tokio1), NoTls)
        .expect("failed to create database pool");

    // Seed admin user (idempotent — no-op if already exists).
    if let Err(e) = seed::seed_admin(&pool, &admin_username, &admin_email, &admin_password).await {
        log::error!("Failed to seed admin user: {}", e);
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
            .wrap(middleware::https::HttpsOnly::new(&https_whitelist))
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
            .service(handlers::auth::confirm_password_reset);

        if enable_docs {
            app = app
                .service(handlers::docs::openapi_spec)
                .service(handlers::docs::openapi_spec_json)
                .service(handlers::docs::swagger_ui);
        }

        app
            // JWT required — ownership/permission checked in handler
            .service(
                web::scope("")
                    .wrap(middleware::auth::AuthMiddleware::new(jwt_secret.clone()))
                    .service(handlers::auth::change_password),
            )
            // Admin only — requires `health:read` permission
            .service(
                web::scope("")
                    .wrap(middleware::auth::AuthMiddleware::require(
                        jwt_secret.clone(),
                        "health:read",
                    ))
                    .service(handlers::health::health),
            )
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
