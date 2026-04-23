/// Tests for the `resolve_secret` helper in `main.rs`.
#[cfg(test)]
mod resolve_secret_tests {
    use std::{env, fs, io::Write};
    use crate::resolve_secret;

    /// Helper: write `contents` to a named temp file and return the path.
    fn tmp_file(name: &str, contents: &str) -> std::path::PathBuf {
        let path = env::temp_dir().join(name);
        let mut f = fs::File::create(&path).expect("tmp file creation failed");
        f.write_all(contents.as_bytes()).expect("tmp file write failed");
        path
    }

    #[test]
    fn test_plain_env_var_returned() {
        let key = "RS_TEST_PLAIN";
        env::set_var(key, "plain_value");
        assert_eq!(resolve_secret(key), Some("plain_value".into()));
        env::remove_var(key);
    }

    #[test]
    fn test_returns_none_when_absent() {
        // Use a name that is certainly not set in the environment.
        assert_eq!(resolve_secret("RS_TEST_DEFINITELY_NOT_SET_XQ9Z"), None);
    }

    #[test]
    fn test_file_variant_preferred_over_plain() {
        let key = "RS_TEST_FILE_PREF";
        let file_key = format!("{}_FILE", key);
        let path = tmp_file("rs_test_file_pref.txt", "from_file");

        env::set_var(&file_key, path.to_str().unwrap());
        env::set_var(key, "from_plain");

        assert_eq!(resolve_secret(key), Some("from_file".into()));

        env::remove_var(&file_key);
        env::remove_var(key);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_file_contents_are_trimmed() {
        let key = "RS_TEST_TRIM";
        let file_key = format!("{}_FILE", key);
        // Docker secret files typically end with a newline.
        let path = tmp_file("rs_test_trim.txt", "secret_value\n");

        env::set_var(&file_key, path.to_str().unwrap());

        assert_eq!(resolve_secret(key), Some("secret_value".into()));

        env::remove_var(&file_key);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_falls_back_to_plain_when_file_unreadable() {
        let key = "RS_TEST_FALLBACK";
        let file_key = format!("{}_FILE", key);

        env::set_var(&file_key, "/tmp/rs_test_this_file_does_not_exist_xq9z.txt");
        env::set_var(key, "fallback_value");

        assert_eq!(resolve_secret(key), Some("fallback_value".into()));

        env::remove_var(&file_key);
        env::remove_var(key);
    }

    #[test]
    fn test_file_only_no_plain_fallback() {
        let key = "RS_TEST_FILE_ONLY";
        let file_key = format!("{}_FILE", key);
        let path = tmp_file("rs_test_file_only.txt", "only_from_file");

        env::set_var(&file_key, path.to_str().unwrap());
        env::remove_var(key); // ensure plain var is absent

        assert_eq!(resolve_secret(key), Some("only_from_file".into()));

        env::remove_var(&file_key);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_unreadable_file_and_no_plain_returns_none() {
        let key = "RS_TEST_NONE_FALLBACK";
        let file_key = format!("{}_FILE", key);

        env::set_var(&file_key, "/tmp/rs_test_no_such_file_xq9z.txt");
        env::remove_var(key);

        assert_eq!(resolve_secret(key), None);

        env::remove_var(&file_key);
    }
}

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
    use crate::utils::jwt::{create_jwt, decode_jwt, SubscriptionClaim};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn test_create_and_decode_jwt() {
        let id = Uuid::new_v4();
        let secret = "test_secret_key_12345";
        let token = create_jwt(id, secret, 1, vec![], vec![], HashMap::new())
            .expect("create_jwt should succeed");
        let claims = decode_jwt(&token, secret).expect("decode_jwt should succeed");
        assert_eq!(claims.sub, id.to_string());
    }

    #[test]
    fn test_jwt_wrong_secret_fails() {
        let id = Uuid::new_v4();
        let token = create_jwt(id, "secret_a", 1, vec![], vec![], HashMap::new())
            .expect("create_jwt should succeed");
        let result = decode_jwt(&token, "secret_b");
        assert!(result.is_err(), "decoding with wrong secret should fail");
    }

    #[test]
    fn test_jwt_subscription_claims_round_trip() {
        let id = Uuid::new_v4();
        let secret = "test_secret";
        let mut subs = HashMap::new();
        subs.insert(
            "clann".into(),
            SubscriptionClaim {
                tier: "family".into(),
                status: "active".into(),
                seat_count: Some(5),
            },
        );
        let token = create_jwt(id, secret, 1, vec![], vec![], subs)
            .expect("create_jwt should succeed");
        let claims = decode_jwt(&token, secret).expect("decode_jwt should succeed");

        let clann = claims.subscriptions.get("clann").expect("clann claim must be present");
        assert_eq!(clann.tier, "family");
        assert_eq!(clann.status, "active");
        assert_eq!(clann.seat_count, Some(5));
    }

    #[test]
    fn test_jwt_no_subscriptions_returns_empty_map() {
        let id = Uuid::new_v4();
        let secret = "test_secret";
        let token = create_jwt(id, secret, 1, vec![], vec![], HashMap::new())
            .expect("create_jwt should succeed");
        let claims = decode_jwt(&token, secret).expect("decode_jwt should succeed");
        assert!(claims.subscriptions.is_empty(), "subscriptions map must be empty");
    }

    #[test]
    fn test_jwt_individual_subscription_no_seat_count() {
        let id = Uuid::new_v4();
        let secret = "test_secret";
        let mut subs = HashMap::new();
        subs.insert(
            "clann".into(),
            SubscriptionClaim {
                tier: "individual".into(),
                status: "active".into(),
                seat_count: None,
            },
        );
        let token = create_jwt(id, secret, 1, vec![], vec![], subs)
            .expect("create_jwt should succeed");
        let claims = decode_jwt(&token, secret).expect("decode_jwt should succeed");

        let clann = claims.subscriptions.get("clann").expect("clann claim must be present");
        assert_eq!(clann.tier, "individual");
        assert!(clann.seat_count.is_none(), "individual plan must have no seat_count");
    }

    #[test]
    fn test_jwt_multiple_product_subscriptions() {
        let id = Uuid::new_v4();
        let secret = "test_secret";
        let mut subs = HashMap::new();
        subs.insert(
            "clann".into(),
            SubscriptionClaim { tier: "family".into(), status: "active".into(), seat_count: Some(3) },
        );
        subs.insert(
            "dam".into(),
            SubscriptionClaim { tier: "professional".into(), status: "trialing".into(), seat_count: None },
        );
        let token = create_jwt(id, secret, 1, vec![], vec![], subs)
            .expect("create_jwt should succeed");
        let claims = decode_jwt(&token, secret).expect("decode_jwt should succeed");

        assert_eq!(claims.subscriptions.len(), 2);
        assert_eq!(claims.subscriptions["clann"].tier, "family");
        assert_eq!(claims.subscriptions["dam"].status, "trialing");
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
            mailer: None,
            smtp_from: String::new(),
            app_base_url: String::new(),
            allowed_app_urls: vec![],
            http_client: reqwest::Client::new(),
            stripe: None,
            paypal: None,
            clann_app_url: String::new(),
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
            mailer: None,
            smtp_from: String::new(),
            app_base_url: String::new(),
            allowed_app_urls: vec![],
            http_client: reqwest::Client::new(),
            stripe: None,
            paypal: None,
            clann_app_url: String::new(),
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

/// Handler-level tests for the `app_url` allowlist feature.
///
/// These tests exercise `POST /users` and `POST /auth/password-reset/request`
/// without a real database connection.  The fake pool URL is never reached
/// because:
///  - In `create_user` the `app_url` check now runs before any DB call, so a
///    rejected URL returns 400 immediately.
///  - In `request_password_reset` the DB call is inside `if let Ok(...)`, so
///    an unreachable pool is silently swallowed and the handler still returns 200.
#[cfg(test)]
mod app_url_handler_tests {
    use actix_web::{test, web, App};
    use deadpool_postgres::{Config as PoolConfig, Runtime};
    use serde_json::json;
    use tokio_postgres::NoTls;

    use crate::{
        handlers::{auth::request_password_reset, users::create_user},
        AppState,
    };

    fn make_state(allowed_app_urls: Vec<String>) -> web::Data<AppState> {
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
            mailer: None,
            smtp_from: String::new(),
            app_base_url: "https://default.example.com".into(),
            allowed_app_urls,
            http_client: reqwest::Client::new(),
            stripe: None,
            paypal: None,
            clann_app_url: String::new(),
        })
    }

    // ── POST /users ──────────────────────────────────────────────────────────

    /// Unlisted app_url with a configured allowlist must be rejected before any
    /// DB work is attempted.
    #[actix_web::test]
    async fn test_create_user_unlisted_app_url_rejected() {
        let state = make_state(vec!["https://allowed.example.com".into()]);
        let app = test::init_service(App::new().app_data(state).service(create_user)).await;

        let req = test::TestRequest::post()
            .uri("/users")
            .insert_header(("content-type", "application/json"))
            .set_json(json!({
                "email": "user@example.com",
                "username": "testuser",
                "password": "longenough",
                "app_url": "https://evil.example.com"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 400);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(
            body["error"].as_str().unwrap_or("").contains("not in the list of allowed URLs"),
            "expected allowlist error, got: {}",
            body["error"]
        );
    }

    /// When no allowlist is configured, any app_url in the request is silently
    /// ignored — the handler proceeds (and fails at the unreachable DB, not at
    /// app_url validation), so the response must not be a 400.
    #[actix_web::test]
    async fn test_create_user_app_url_ignored_without_allowlist() {
        let state = make_state(vec![]); // no allowlist
        let app = test::init_service(App::new().app_data(state).service(create_user)).await;

        let req = test::TestRequest::post()
            .uri("/users")
            .insert_header(("content-type", "application/json"))
            .set_json(json!({
                "email": "user@example.com",
                "username": "testuser",
                "password": "longenough",
                "app_url": "https://arbitrary.example.com"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        // Must not be 400 (app_url validation); a 500 from the unreachable DB is fine here.
        assert_ne!(resp.status().as_u16(), 400);
    }

    /// A listed app_url must pass validation and allow the handler to proceed to
    /// the DB layer (which fails on the fake pool — that's expected; the point is
    /// the response is not a 400 from app_url validation).
    #[actix_web::test]
    async fn test_create_user_listed_app_url_passes_validation() {
        let state = make_state(vec!["https://allowed.example.com".into()]);
        let app = test::init_service(App::new().app_data(state).service(create_user)).await;

        let req = test::TestRequest::post()
            .uri("/users")
            .insert_header(("content-type", "application/json"))
            .set_json(json!({
                "email": "user@example.com",
                "username": "testuser",
                "password": "longenough",
                "app_url": "https://allowed.example.com"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_ne!(resp.status().as_u16(), 400);
    }

    // ── POST /auth/password-reset/request ────────────────────────────────────

    /// Unlisted app_url is rejected before the DB call.
    #[actix_web::test]
    async fn test_password_reset_unlisted_app_url_rejected() {
        let state = make_state(vec!["https://allowed.example.com".into()]);
        let app =
            test::init_service(App::new().app_data(state).service(request_password_reset)).await;

        let req = test::TestRequest::post()
            .uri("/auth/password-reset/request")
            .insert_header(("content-type", "application/json"))
            .set_json(json!({
                "email": "user@example.com",
                "app_url": "https://evil.example.com"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 400);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(
            body["error"].as_str().unwrap_or("").contains("not in the list of allowed URLs"),
            "expected allowlist error, got: {}",
            body["error"]
        );
    }

    /// Listed app_url passes validation; the DB lookup is silently swallowed
    /// (email not found → no-op), so the handler returns 200.
    #[actix_web::test]
    async fn test_password_reset_listed_app_url_returns_200() {
        let state = make_state(vec!["https://allowed.example.com".into()]);
        let app =
            test::init_service(App::new().app_data(state).service(request_password_reset)).await;

        let req = test::TestRequest::post()
            .uri("/auth/password-reset/request")
            .insert_header(("content-type", "application/json"))
            .set_json(json!({
                "email": "nobody@example.com",
                "app_url": "https://allowed.example.com"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);
    }

    /// No app_url with no allowlist falls back to APP_BASE_URL; handler returns 200.
    #[actix_web::test]
    async fn test_password_reset_no_app_url_no_allowlist_returns_200() {
        let state = make_state(vec![]);
        let app =
            test::init_service(App::new().app_data(state).service(request_password_reset)).await;

        let req = test::TestRequest::post()
            .uri("/auth/password-reset/request")
            .insert_header(("content-type", "application/json"))
            .set_json(json!({ "email": "nobody@example.com" }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);
    }

    /// No app_url with an allowlist configured also falls back to APP_BASE_URL.
    #[actix_web::test]
    async fn test_password_reset_no_app_url_with_allowlist_returns_200() {
        let state = make_state(vec!["https://allowed.example.com".into()]);
        let app =
            test::init_service(App::new().app_data(state).service(request_password_reset)).await;

        let req = test::TestRequest::post()
            .uri("/auth/password-reset/request")
            .insert_header(("content-type", "application/json"))
            .set_json(json!({ "email": "nobody@example.com" }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);
    }
}

/// Unit tests for the `SubscriptionClaim` struct and `SubscriptionResponse` conversion.
#[cfg(test)]
mod subscription_tests {
    use crate::models::{Subscription, SubscriptionResponse};
    use crate::utils::jwt::SubscriptionClaim;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_subscription(plan: &str, status: &str, seat_count: i16) -> Subscription {
        Subscription {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            product_id: Uuid::new_v4(),
            product_slug: "clann".into(),
            plan: plan.into(),
            status: status.into(),
            payment_provider: Some("stripe".into()),
            provider_subscription_id: Some("sub_test".into()),
            provider_customer_id: Some("cus_test".into()),
            seat_count,
            trial_end: None,
            current_period_start: None,
            current_period_end: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// `SubscriptionResponse::from` must copy all public fields correctly.
    #[test]
    fn test_subscription_response_from_subscription() {
        let sub = make_subscription("family", "active", 5);
        let sub_id = sub.id;
        let resp = SubscriptionResponse::from(sub);

        assert_eq!(resp.id, sub_id);
        assert_eq!(resp.product, "clann");
        assert_eq!(resp.plan, "family");
        assert_eq!(resp.status, "active");
        assert_eq!(resp.seat_count, 5);
        assert!(resp.trial_end.is_none());
        assert!(resp.current_period_start.is_none());
        assert!(resp.current_period_end.is_none());
    }

    /// `SubscriptionResponse::from` must preserve optional period dates when present.
    #[test]
    fn test_subscription_response_period_dates_preserved() {
        let now = Utc::now();
        let mut sub = make_subscription("individual", "active", 1);
        sub.current_period_start = Some(now);
        sub.current_period_end = Some(now);
        let resp = SubscriptionResponse::from(sub);

        assert!(resp.current_period_start.is_some());
        assert!(resp.current_period_end.is_some());
    }

    /// A `SubscriptionClaim` with `seat_count = 1` must map to `None` per login handler logic.
    #[test]
    fn test_subscription_claim_seat_count_omitted_for_single_seat() {
        // The login handler sets seat_count to None when seat_count <= 1.
        let sub = make_subscription("individual", "active", 1);
        let seat_count = if sub.seat_count > 1 { Some(sub.seat_count) } else { None };
        let claim = SubscriptionClaim {
            tier: sub.plan.clone(),
            status: sub.status.clone(),
            seat_count,
        };
        assert!(claim.seat_count.is_none(), "seat_count must be None for individual plan");
    }

    /// A multi-seat subscription must carry seat_count in the claim.
    #[test]
    fn test_subscription_claim_seat_count_present_for_multi_seat() {
        let sub = make_subscription("family", "active", 6);
        let seat_count = if sub.seat_count > 1 { Some(sub.seat_count) } else { None };
        let claim = SubscriptionClaim {
            tier: sub.plan.clone(),
            status: sub.status.clone(),
            seat_count,
        };
        assert_eq!(claim.seat_count, Some(6));
    }

    /// `SubscriptionClaim` fields must survive JSON serialisation and deserialisation.
    #[test]
    fn test_subscription_claim_serde_round_trip() {
        let claim = SubscriptionClaim {
            tier: "professional".into(),
            status: "trialing".into(),
            seat_count: None,
        };
        let json = serde_json::to_string(&claim).expect("serialisation must succeed");
        let back: SubscriptionClaim = serde_json::from_str(&json).expect("deserialisation must succeed");
        assert_eq!(back.tier, "professional");
        assert_eq!(back.status, "trialing");
        assert!(back.seat_count.is_none());
        // seat_count must be omitted from JSON when None (skip_serializing_if).
        assert!(!json.contains("seat_count"), "seat_count must be absent from JSON when None");
    }

    /// seat_count must appear in JSON when present.
    #[test]
    fn test_subscription_claim_serde_seat_count_included_when_some() {
        let claim = SubscriptionClaim {
            tier: "family".into(),
            status: "active".into(),
            seat_count: Some(4),
        };
        let json = serde_json::to_string(&claim).expect("serialisation must succeed");
        assert!(json.contains("seat_count"), "seat_count must appear in JSON when Some");
        assert!(json.contains('4'));
    }
}
