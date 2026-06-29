use crate::{
    errors::AppError,
    utils::{
        jwt::{Claims, decode_jwt, decode_jwt_rs256},
        key_store::KeyStore,
    },
};
use actix_web::HttpRequest;
use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header,
    Error, HttpMessage, HttpResponse,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Extract the JWT [`Claims`] injected by [`AuthMiddleware`] from a handler's request.
pub fn claims_from_req(req: &HttpRequest) -> Result<Claims, AppError> {
    req.extensions()
        .get::<Claims>()
        .cloned()
        .ok_or(AppError::InvalidToken)
}
use std::{
    future::{ready, Future, Ready},
    pin::Pin,
    rc::Rc,
};

/// Actix-web middleware that validates a Bearer JWT and optionally checks
/// for a specific permission claim.
///
/// Tries RS256 validation first (using all active OAuth2 signing keys to support
/// key rotation), then falls back to HS256 with `jwt_secret` for backward compat
/// with any sessions issued before the RS256 migration.
///
/// On success, the decoded [`Claims`](crate::utils::jwt::Claims) are inserted
/// into the request extensions so downstream handlers can access them via
/// `req.extensions().get::<Claims>()`.
pub struct AuthMiddleware {
    jwt_secret: String,
    oauth2_keys: Arc<RwLock<KeyStore>>,
    required_permission: Option<String>,
}

impl AuthMiddleware {
    /// Require a valid JWT; no specific permission enforced.
    pub fn new(jwt_secret: String, oauth2_keys: Arc<RwLock<KeyStore>>) -> Self {
        Self {
            jwt_secret,
            oauth2_keys,
            required_permission: None,
        }
    }

    /// Require a valid JWT **and** the specified permission in the claims.
    pub fn require(jwt_secret: String, oauth2_keys: Arc<RwLock<KeyStore>>, permission: &str) -> Self {
        Self {
            jwt_secret,
            oauth2_keys,
            required_permission: Some(permission.to_string()),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareInner<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareInner {
            service: Rc::new(service),
            jwt_secret: self.jwt_secret.clone(),
            oauth2_keys: self.oauth2_keys.clone(),
            required_permission: self.required_permission.clone(),
        }))
    }
}

pub struct AuthMiddlewareInner<S> {
    service: Rc<S>,
    jwt_secret: String,
    oauth2_keys: Arc<RwLock<KeyStore>>,
    required_permission: Option<String>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareInner<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let jwt_secret = self.jwt_secret.clone();
        let oauth2_keys = self.oauth2_keys.clone();
        let required_permission = self.required_permission.clone();

        // Extract the token before consuming `req`.
        let token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_owned());

        Box::pin(async move {
            let token = match token {
                Some(t) => t,
                None => {
                    let (req, _) = req.into_parts();
                    let resp = HttpResponse::Unauthorized()
                        .json(serde_json::json!({
                            "error": "missing or invalid authorization header"
                        }))
                        .map_into_right_body();
                    return Ok(ServiceResponse::new(req, resp));
                }
            };

            // Try RS256 first (tokens issued by the new OAuth2 login), then fall
            // back to HS256 for any sessions issued before the RS256 migration.
            let claims_result = {
                let keys_snapshot = oauth2_keys.read().await.keys.clone();

                decode_jwt_rs256(&token, &keys_snapshot)
                    .or_else(|_| decode_jwt(&token, &jwt_secret))
            };

            match claims_result {
                Ok(claims) => {
                    if let Some(perm) = &required_permission {
                        if !claims.permissions.contains(perm) {
                            let (req, _) = req.into_parts();
                            let resp = HttpResponse::Forbidden()
                                .json(serde_json::json!({
                                    "error": "insufficient permissions"
                                }))
                                .map_into_right_body();
                            return Ok(ServiceResponse::new(req, resp));
                        }
                    }
                    req.extensions_mut().insert(claims);
                    let res = service.call(req).await?;
                    Ok(res.map_into_left_body())
                }
                Err(_) => {
                    let (req, _) = req.into_parts();
                    let resp = HttpResponse::Unauthorized()
                        .json(serde_json::json!({
                            "error": "invalid or expired token"
                        }))
                        .map_into_right_body();
                    Ok(ServiceResponse::new(req, resp))
                }
            }
        })
    }
}
