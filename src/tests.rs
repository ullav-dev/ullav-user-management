/// Unit tests for password utilities and JWT helpers.
///
/// These tests run without a database connection and validate the
/// pure-function behaviour of hashing, verification and token generation.
#[cfg(test)]
mod password_tests {
    use crate::utils::password::{
        generate_secure_token, hash_password, validate_password, verify_password,
    };

    #[test]
    fn test_hash_and_verify_password() {
        let plaintext = "SuperSecret1!";
        let hash = hash_password(plaintext).expect("hashing should succeed");
        assert!(
            verify_password(plaintext, &hash).expect("verify should succeed"),
            "correct password must verify to true"
        );
    }

    #[test]
    fn test_wrong_password_does_not_verify() {
        let hash = hash_password("correct_password").expect("hashing should succeed");
        let ok = verify_password("wrong_password", &hash).expect("verify should succeed");
        assert!(!ok, "wrong password must not verify");
    }

    #[test]
    fn test_validate_password_too_short() {
        let err = validate_password("short").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("8 characters"), "expected length error, got: {}", msg);
    }

    #[test]
    fn test_validate_password_ok() {
        assert!(validate_password("longenough").is_ok());
    }

    #[test]
    fn test_generate_secure_token_length() {
        let token = generate_secure_token();
        // 32 random bytes → 64 hex characters
        assert_eq!(token.len(), 64, "token should be 64 hex characters");
    }

    #[test]
    fn test_generate_secure_tokens_are_unique() {
        let t1 = generate_secure_token();
        let t2 = generate_secure_token();
        assert_ne!(t1, t2, "two generated tokens must differ");
    }
}

#[cfg(test)]
mod jwt_tests {
    use crate::utils::jwt::{create_jwt, decode_jwt};
    use uuid::Uuid;

    #[test]
    fn test_create_and_decode_jwt() {
        let id = Uuid::new_v4();
        let secret = "test_secret_key_12345";
        let token = create_jwt(id, secret, 1).expect("create_jwt should succeed");
        let claims = decode_jwt(&token, secret).expect("decode_jwt should succeed");
        assert_eq!(claims.sub, id.to_string());
    }

    #[test]
    fn test_jwt_wrong_secret_fails() {
        let id = Uuid::new_v4();
        let token = create_jwt(id, "secret_a", 1).expect("create_jwt should succeed");
        let result = decode_jwt(&token, "secret_b");
        assert!(result.is_err(), "decoding with wrong secret should fail");
    }
}

#[cfg(test)]
mod handler_tests {
    use actix_web::{test, web, App};
    use deadpool_postgres::{Config as PoolConfig, Runtime};
    use serde_json::json;
    use tokio_postgres::NoTls;

    use crate::{handlers::users::create_user, AppState};

    /// Build a minimal `AppState` whose pool will never be reached during
    /// input-validation tests (the pool URL is fake; a connection would only
    /// be attempted inside the handler body, which is never reached when the
    /// request is structurally invalid).
    fn test_state() -> web::Data<AppState> {
        let mut cfg = PoolConfig::new();
        cfg.url = Some("postgresql://user:pass@localhost/testdb".into());
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .expect("pool construction must not fail for a bad url");
        web::Data::new(AppState {
            pool,
            jwt_secret: "test_secret".into(),
            jwt_ttl_hours: 1,
            reset_token_ttl_minutes: 30,
            confirmation_token_ttl_minutes: 1440,
        })
    }

    /// Verify that the `POST /users` handler returns 400 when the request body
    /// is structurally invalid JSON.
    #[actix_web::test]
    async fn test_create_user_bad_json() {
        let state = test_state();
        let app = test::init_service(
            App::new().app_data(state).service(create_user),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/users")
            .insert_header(("content-type", "application/json"))
            .set_payload(b"{bad json".to_vec())
            .to_request();

        let resp = test::call_service(&app, req).await;
        // actix-web returns 400 for malformed JSON
        assert_eq!(resp.status().as_u16(), 400);
    }

    /// Verify that the `POST /users` handler returns 400 when mandatory fields are missing.
    #[actix_web::test]
    async fn test_create_user_missing_fields() {
        let state = test_state();
        let app = test::init_service(
            App::new().app_data(state).service(create_user),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/users")
            .insert_header(("content-type", "application/json"))
            .set_json(json!({ "email": "test@example.com" }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 400);
    }
}

#[cfg(test)]
mod health_tests {
    use actix_web::{test, web, App};
    use deadpool_postgres::{Config as PoolConfig, Runtime};
    use tokio_postgres::NoTls;

    use crate::{handlers::health::health, AppState};

    fn make_state(database_url: &str) -> web::Data<AppState> {
        let mut cfg = PoolConfig::new();
        cfg.url = Some(database_url.into());
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .expect("pool construction should not fail");
        web::Data::new(AppState {
            pool,
            jwt_secret: "test_secret".into(),
            jwt_ttl_hours: 1,
            reset_token_ttl_minutes: 30,
            confirmation_token_ttl_minutes: 1440,
        })
    }

    /// With an unreachable database the handler must return 503 with
    /// `status: degraded`.
    #[actix_web::test]
    async fn test_health_degraded_when_db_unreachable() {
        let state = make_state("postgresql://user:pass@localhost:9/no_such_db");
        let app = test::init_service(App::new().app_data(state).service(health)).await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 503);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "degraded");
    }

    /// With a reachable database the handler must return 200 with `status: ok`.
    ///
    /// Requires `TEST_DATABASE_URL` to be set; the test is silently skipped
    /// when the variable is absent so that `cargo test` works without a live
    /// Postgres instance.
    #[actix_web::test]
    async fn test_health_ok_when_db_reachable() {
        let url = match std::env::var("TEST_DATABASE_URL") {
            Ok(u) => u,
            Err(_) => return, // skip — no live database configured
        };

        let state = make_state(&url);
        let app = test::init_service(App::new().app_data(state).service(health)).await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["database"], "ok");
    }
}
