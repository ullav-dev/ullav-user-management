use crate::utils::jwt::decode_jwt;
use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header,
    Error, HttpMessage, HttpResponse,
};
use std::{
    future::{ready, Future, Ready},
    pin::Pin,
    rc::Rc,
};

/// Actix-web middleware that validates a Bearer JWT and optionally checks
/// for a specific permission claim.
///
/// On success, the decoded [`Claims`](crate::utils::jwt::Claims) are inserted
/// into the request extensions so downstream handlers can access them via
/// `req.extensions().get::<Claims>()`.
pub struct AuthMiddleware {
    jwt_secret: String,
    required_permission: Option<String>,
}

impl AuthMiddleware {
    /// Require a valid JWT; no specific permission enforced.
    pub fn new(jwt_secret: String) -> Self {
        Self {
            jwt_secret,
            required_permission: None,
        }
    }

    /// Require a valid JWT **and** the specified permission in the claims.
    pub fn require(jwt_secret: String, permission: &str) -> Self {
        Self {
            jwt_secret,
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
            required_permission: self.required_permission.clone(),
        }))
    }
}

pub struct AuthMiddlewareInner<S> {
    service: Rc<S>,
    jwt_secret: String,
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

            match decode_jwt(&token, &jwt_secret) {
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
