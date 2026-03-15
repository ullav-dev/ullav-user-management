use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use std::{
    future::{ready, Future, Ready},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    rc::Rc,
};

/// Parse an IP address string that may include a port suffix
/// (`"192.0.2.1:1234"` or `"[::1]:1234"`).
fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse::<SocketAddr>()
        .map(|a| a.ip())
        .ok()
        .or_else(|| s.parse::<IpAddr>().ok())
}

/// Middleware that rejects non-HTTPS requests unless the client IP is
/// localhost (`127.0.0.1` / `::1`) or listed in the configured whitelist.
///
/// HTTPS is detected via the `X-Forwarded-Proto` / `Forwarded` headers (set by
/// a reverse proxy) or from the actual connection scheme when TLS is terminated
/// by the application itself.
pub struct HttpsOnly {
    allowed_ips: Rc<Vec<IpAddr>>,
}

impl HttpsOnly {
    /// `whitelist` is the set of additional IPs that may use plain HTTP.
    /// Localhost addresses are always included automatically.
    pub fn new(whitelist: &[IpAddr]) -> Self {
        let mut allowed: Vec<IpAddr> = vec![
            "127.0.0.1".parse().unwrap(),
            "::1".parse().unwrap(),
        ];
        allowed.extend_from_slice(whitelist);
        Self {
            allowed_ips: Rc::new(allowed),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for HttpsOnly
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = HttpsOnlyInner<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(HttpsOnlyInner {
            service: Rc::new(service),
            allowed_ips: self.allowed_ips.clone(),
        }))
    }
}

pub struct HttpsOnlyInner<S> {
    service: Rc<S>,
    allowed_ips: Rc<Vec<IpAddr>>,
}

impl<S, B> Service<ServiceRequest> for HttpsOnlyInner<S>
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
        // Resolve scheme and real client IP before consuming `req`.
        // connection_info checks X-Forwarded-Proto / X-Real-IP / X-Forwarded-For
        // headers set by a reverse proxy before falling back to the socket address.
        let conn = req.connection_info().clone();
        let scheme = conn.scheme().to_owned();
        let ip_str = conn
            .realip_remote_addr()
            .or_else(|| conn.peer_addr())
            .map(str::to_owned);
        let allowed_ips = self.allowed_ips.clone();
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            if scheme == "https" {
                return service.call(req).await.map(ServiceResponse::map_into_left_body);
            }

            let is_allowed = ip_str
                .as_deref()
                .and_then(parse_ip)
                .map_or(false, |ip| allowed_ips.contains(&ip));

            if is_allowed {
                return service.call(req).await.map(ServiceResponse::map_into_left_body);
            }

            let (req, _) = req.into_parts();
            let resp = HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "HTTPS is required"}))
                .map_into_right_body();
            Ok(ServiceResponse::new(req, resp))
        })
    }
}
