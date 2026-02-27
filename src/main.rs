use actix_web::{middleware::Logger, web, App, HttpServer};
use deadpool_postgres::{Config as PoolConfig, Runtime};
use dotenv::dotenv;
use std::env;
use tokio_postgres::NoTls;

mod db;
mod errors;
mod handlers;
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
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "8081".into())
        .parse()
        .expect("PORT must be a number");

    // Build the connection pool.
    let mut cfg = PoolConfig::new();
    cfg.url = Some(database_url);
    let pool = cfg
        .create_pool(Some(Runtime::Tokio1), NoTls)
        .expect("failed to create database pool");

    let state = web::Data::new(AppState {
        pool,
        jwt_secret,
        jwt_ttl_hours,
        reset_token_ttl_minutes,
    });

    log::info!("Starting server on {}:{}", host, port);

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(Logger::default())
            .service(handlers::users::create_user)
            .service(handlers::auth::login)
            .service(handlers::auth::change_password)
            .service(handlers::auth::request_password_reset)
            .service(handlers::auth::confirm_password_reset)
            .service(handlers::docs::openapi_spec)
            .service(handlers::docs::swagger_ui)
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
