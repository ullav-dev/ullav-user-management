use actix_web::{get, HttpResponse};

static OPENAPI_SPEC: &str = include_str!("../../openapi.yaml");

/// `GET /openapi.yaml` — serve the raw OpenAPI specification.
#[get("/openapi.yaml")]
pub async fn openapi_spec() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/yaml")
        .body(OPENAPI_SPEC)
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
    url: "/openapi.yaml",
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
