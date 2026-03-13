use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use maxminddb::path;
use std::{
    collections::HashSet,
    future::{ready, Future, Ready},
    net::IpAddr,
    pin::Pin,
    rc::Rc,
    sync::Arc,
};

/// Middleware that denies requests from IP addresses resolving to a blocked
/// country using a MaxMind GeoLite2 (or GeoIP2) Country database.
///
/// When `db` is `None` or `blocked_countries` is empty the middleware is a
/// transparent no-op, so it is safe to register unconditionally.
///
/// The real client IP is resolved from the `X-Real-IP` / `X-Forwarded-For`
/// headers (set by a reverse proxy) before falling back to the direct peer
/// address. Private / reserved addresses that have no GeoIP entry are always
/// allowed through.
pub struct GeoBlock {
    db: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    blocked_countries: Arc<HashSet<String>>,
}

impl GeoBlock {
    pub fn new(
        db: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
        blocked_countries: Arc<HashSet<String>>,
    ) -> Self {
        Self { db, blocked_countries }
    }
}

impl<S, B> Transform<S, ServiceRequest> for GeoBlock
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = GeoBlockInner<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(GeoBlockInner {
            service: Rc::new(service),
            db: self.db.clone(),
            blocked_countries: self.blocked_countries.clone(),
        }))
    }
}

pub struct GeoBlockInner<S> {
    service: Rc<S>,
    db: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    blocked_countries: Arc<HashSet<String>>,
}

impl<S, B> Service<ServiceRequest> for GeoBlockInner<S>
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

        // Fast path: no-op when geo-blocking is not configured.
        let db = match self.db.clone() {
            Some(db) if !self.blocked_countries.is_empty() => db,
            _ => {
                return Box::pin(async move {
                    service.call(req).await.map(ServiceResponse::map_into_left_body)
                });
            }
        };

        let blocked_countries = self.blocked_countries.clone();

        // Resolve the real client IP. `realip_remote_addr` checks X-Real-IP
        // then the first entry of X-Forwarded-For before the socket address.
        let conn = req.connection_info().clone();
        let ip_str = conn
            .realip_remote_addr()
            .or_else(|| conn.peer_addr())
            .map(str::to_owned);

        Box::pin(async move {
            if let Some(ip) = ip_str.as_deref().and_then(parse_ip) {
                if let Ok(result) = db.lookup(ip) {
                    if let Ok(Some(iso)) = result.decode_path::<String>(&path!["country", "iso_code"]) {
                        if blocked_countries.contains(iso.as_str()) {
                            let (req, _) = req.into_parts();
                            let resp = HttpResponse::Forbidden()
                                .json(serde_json::json!({"error": "access denied"}))
                                .map_into_right_body();
                            return Ok(ServiceResponse::new(req, resp));
                        }
                    }
                }
            }

            service.call(req).await.map(ServiceResponse::map_into_left_body)
        })
    }
}

/// Parse an IP address string that may include a port suffix
/// (`"192.0.2.1:1234"` or `"[::1]:1234"`).
fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse::<std::net::SocketAddr>()
        .map(|a| a.ip())
        .ok()
        .or_else(|| s.parse::<IpAddr>().ok())
}
