use actix_web::{middleware::Logger, web, App, HttpServer};
use deadpool_postgres::{Config as PoolConfig, Runtime};
use dotenv::dotenv;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use std::env;
use tokio_postgres::NoTls;

mod db;
mod errors;
mod handlers;
mod middleware;
mod models;
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
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    let jwt_secret = env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set");
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

    // SMTP configuration — all optional; email is disabled if SMTP_HOST is absent.
    let smtp_host = env::var("SMTP_HOST").ok();
    let smtp_port: u16 = env::var("SMTP_PORT")
        .unwrap_or_else(|_| "587".into())
        .parse()
        .expect("SMTP_PORT must be a number");
    let smtp_username = env::var("SMTP_USERNAME").ok();
    let smtp_password = env::var("SMTP_PASSWORD").ok();
    let smtp_from = env::var("SMTP_FROM").unwrap_or_default();
    let app_base_url = env::var("APP_BASE_URL").unwrap_or_default();
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

    // Build the connection pool.
    let mut cfg = PoolConfig::new();
    cfg.url = Some(database_url);
    let pool = cfg
        .create_pool(Some(Runtime::Tokio1), NoTls)
        .expect("failed to create database pool");

    let state = web::Data::new(AppState {
        pool,
        jwt_secret: jwt_secret.clone(),
        jwt_ttl_hours,
        reset_token_ttl_minutes,
        confirmation_token_ttl_minutes,
        mailer,
        smtp_from,
        app_base_url,
    });

    log::info!("Starting server on {}:{}", host, port);

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(Logger::default())
            // Open routes — no authentication required
            .service(handlers::users::create_user)
            .service(handlers::auth::login)
            .service(handlers::auth::confirm_email)
            .service(handlers::auth::confirm_email_get)
            .service(handlers::auth::request_password_reset)
            .service(handlers::auth::confirm_password_reset)
            .service(handlers::docs::openapi_spec)
            .service(handlers::docs::openapi_spec_json)
            .service(handlers::docs::swagger_ui)
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
