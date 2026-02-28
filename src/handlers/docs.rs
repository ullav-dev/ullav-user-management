use actix_web::{get, HttpResponse};
use std::sync::OnceLock;

static OPENAPI_YAML: &str = include_str!("../../openapi.yaml");

/// Parse the embedded YAML spec to JSON once and cache it.
fn openapi_json() -> &'static str {
    static JSON: OnceLock<String> = OnceLock::new();
    JSON.get_or_init(|| {
        let value: serde_json::Value =
            serde_yaml::from_str(OPENAPI_YAML).expect("openapi.yaml is valid YAML");
        serde_json::to_string(&value).expect("spec serialises to JSON")
    })
}

/// `GET /openapi.yaml` — serve the raw OpenAPI specification.
#[get("/openapi.yaml")]
pub async fn openapi_spec() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/yaml")
        .body(OPENAPI_YAML)
}

/// `GET /openapi.json` — serve the OpenAPI specification as JSON.
#[get("/openapi.json")]
pub async fn openapi_spec_json() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(openapi_json())
}

/// `GET /docs` — serve Swagger UI backed by the local spec.
#[get("/docs")]
pub async fn swagger_ui() -> HttpResponse {
    let html = r##"<!DOCTYPE html>
<html>
<head>
  <title>User Management API</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({
    url: "/openapi.json",
    dom_id: "#swagger-ui",
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
    layout: "BaseLayout",
    deepLinking: true,
  });
</script>
</body>
</html>"##;

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}
