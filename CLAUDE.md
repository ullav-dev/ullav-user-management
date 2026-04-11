# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
cargo build
cargo build --release

# Run (requires .env or environment variables)
cargo run

# Unit and handler tests (no database required)
cargo test

# Include the health endpoint integration test (requires Docker DB on port 5433)
TEST_DATABASE_URL=postgresql://app_user:app_password@localhost:5433/user_management cargo test

# Run a single test by name
cargo test test_hash_and_verify_password

# Lint
cargo clippy

# Format
cargo fmt
```

### Running with Docker

```bash
# Full stack (PostgreSQL + app)
docker compose up --build

# Database only (for local development)
docker compose up db
```

### Production deployment

Uses `docker-compose-prod.yaml` + `.env.prod`. Three services (`db`, `migrate`, `app`) run on the external `ullav-net` network with no host port bindings. All secrets are injected via Docker secrets mounted at `/run/secrets/*`.

`migrate` service runs `scripts/migrate.sh` before the app starts. The script creates a `schema_migrations` tracking table (if absent), then applies any `.sql` files in `migrations/` not yet recorded. The `app` service has `depends_on: migrate: condition: service_completed_successfully`.

`docker-entrypoint.sh` is a thin wrapper that simply exec's the binary. `DATABASE_URL` is now passed as its own secret (`DATABASE_URL_FILE=/run/secrets/database_url`), so no URL assembly is needed in the entrypoint.

```bash
# Pre-requisite: create the shared network (once)
docker network create ullav-net

# Populate secret files (never commit these)
mkdir -p secrets
echo -n "postgresql://user:pass@db:5432/user_management" > secrets/database_url.txt
echo -n "strong-db-password"  > secrets/db_password.txt
echo -n "long-random-jwt-key" > secrets/jwt_secret.txt
echo -n "smtp-password"       > secrets/smtp_password.txt
echo -n "admin-password"      > secrets/admin_password.txt
chmod 600 secrets/*.txt

# Edit .env.prod with real SMTP host, domain, etc., then deploy
docker compose -f docker-compose-prod.yaml --env-file .env.prod up -d
```

`.env.prod` and `secrets/` are `.gitignore`d.

### Local setup without Docker

```bash
cp .env.example .env
# Edit DATABASE_URL and JWT_SECRET in .env
psql "$DATABASE_URL" -f migrations/001_initial.sql
psql "$DATABASE_URL" -f migrations/002_email_confirmation.sql
psql "$DATABASE_URL" -f migrations/003_rbac.sql
psql "$DATABASE_URL" -f migrations/004_collection_permissions.sql
psql "$DATABASE_URL" -f migrations/005_products.sql
psql "$DATABASE_URL" -f migrations/006_subscriptions.sql
psql "$DATABASE_URL" -f migrations/007_grandfather_subscriptions.sql
psql "$DATABASE_URL" -f migrations/008_admin_user_permissions.sql
psql "$DATABASE_URL" -f migrations/009_comad_product.sql
cargo run
```

## Architecture

This is a single-binary Actix-web microservice. `src/main.rs` wires together the connection pool, `AppState`, and route registration. `AppState` (defined in `main.rs`) is the shared state injected into every handler via `web::Data<AppState>`.

**Module layout:**

- `src/main.rs` — server bootstrap, route registration, `AppState` struct
- `src/models/mod.rs` — all request/response structs and DB model types
- `src/errors.rs` — `AppError` enum; implements `actix_web::ResponseError` to map errors to HTTP status codes
- `src/db/mod.rs` — all raw SQL queries (no ORM); returns `AppError` on failure
- `src/handlers/users.rs` — `POST /users` (open; assigns `user` role on creation; accepts optional `app_url` for multi-tenant confirmation links)
- `src/handlers/auth.rs` — `POST /auth/login`, `PUT /users/{id}/password` (JWT-protected), `POST /auth/password-reset/request` (accepts optional `app_url`), `POST /auth/password-reset/confirm` (also activates the user if not yet confirmed — password reset proves email ownership), `POST /auth/confirm-email`, `GET /auth/confirm-email` (link-click activation)
- `src/handlers/health.rs` — `GET /health` (requires `health:read` permission); also exposes `health_scoped` (`GET ""`) mounted at `/health` inside the auth scope
- `src/handlers/admin.rs` — full CRUD for user/role/permission/subscription/product management; all routes require `users:read` permission and are mounted under the `/admin` scope prefix:
  - `GET /admin/users`, `GET /admin/users/{id}`, `PATCH /admin/users/{id}`, `DELETE /admin/users/{id}`
  - `POST /admin/users/{id}/roles/{role}`, `DELETE /admin/users/{id}/roles/{role}`
  - `POST /admin/users/{id}/subscriptions`
  - `GET /admin/roles`, `POST /admin/roles`, `DELETE /admin/roles/{name}`
  - `GET /admin/permissions`, `POST /admin/permissions`
  - `POST /admin/roles/{name}/permissions/{perm}`, `DELETE /admin/roles/{name}/permissions/{perm}`
  - `GET /admin/subscriptions`, `PATCH /admin/subscriptions/{id}`, `DELETE /admin/subscriptions/{id}`
  - `GET /admin/products`
- `src/handlers/subscriptions.rs` — `GET /subscriptions/current?product=<slug>` (JWT-protected; returns Individual free tier when no row exists), `POST /subscriptions/checkout` (JWT-protected; initiates Stripe or PayPal checkout), `POST /subscriptions/portal` (JWT-protected; Stripe Customer Portal), `POST /webhooks/stripe`, `POST /webhooks/paypal` (signature-verified webhook receivers)
- `src/handlers/docs.rs` — `GET /openapi.yaml`, `GET /openapi.json` (YAML spec embedded via `include_str!`, converted to JSON with `serde_yaml`), `GET /docs` (Swagger UI via CDN); all three disabled when `ENABLE_DOCS=false`
- `src/middleware/auth.rs` — `AuthMiddleware`: validates Bearer JWT, optionally checks a permission claim, injects `Claims` into request extensions
- `src/middleware/https.rs` — `HttpsOnly`: rejects non-HTTPS requests; localhost and `WHITELIST` IPs are exempt; uses `X-Forwarded-Proto` for proxy-terminated TLS
- `src/middleware/geo.rs` — `GeoBlock`: denies requests from IPs in blocked countries using a MaxMind GeoLite2 `.mmdb` database (`GEOBLOCK` + `GEOIP_DB` env vars); no-op when not configured

Middleware is registered in this order (innermost → outermost, i.e. outermost is processed first): `Logger` → `HttpsOnly` → `GeoBlock` → `Cors` (from `actix-cors`). `Cors` is outermost so OPTIONS preflight requests are answered before any auth or geo checks. Configured via `CORS_ORIGINS` env var.
- `src/utils/jwt.rs` — `create_jwt` / `decode_jwt` using HS256; `Claims` carries `sub`, `iat`, `exp`, `roles`, `permissions`, `subscriptions` (map of product slug → `SubscriptionClaim{tier, status, seat_count?}`)
- `src/utils/app_url.rs` — `resolve_app_url(requested, allowed, fallback)`: validates caller-supplied `app_url` against the `ALLOWED_APP_URLS` allowlist; returns `APP_BASE_URL` fallback when no allowlist is configured or no URL is supplied
- `src/seed.rs` — `seed_admin`: runs at startup, idempotently inserts the admin user (active, admin role) using `ADMIN_USERNAME/EMAIL/PASSWORD` env vars
- `src/utils/email.rs` — `build_mailer` (STARTTLS or no-TLS), `send_confirmation_email`, `send_password_reset_email` (HTML emails via lettre)
- `src/utils/password.rs` — Argon2id hashing, verification, validation, and secure token generation
- `src/tests.rs` — unit tests for password utils, JWT helpers, `resolve_secret`, `resolve_app_url`, and handler smoke tests using `actix_web::test` (no real DB needed)

**Route structure:** All JWT-protected routes live inside a single `web::scope("")` with `AuthMiddleware::new`. Routes with stricter permission requirements use **nested scopes with concrete path prefixes** (e.g. `web::scope("/admin")` wrapping `AuthMiddleware::require("users:read")`). Do NOT use multiple top-level `web::scope("")` blocks for different permission levels — actix-web commits to the first matching scope and will return 404 rather than falling through, so all overlapping-prefix scopes must be nested.

**Data flow:** handlers call `db::*` functions directly (no service layer). All DB functions take `&Pool` and return `Result<T, AppError>`. The `AppError` enum converts into JSON `{ "error": "..." }` responses automatically.

**Database:** PostgreSQL only, native SQL via `tokio-postgres`. Schema is in `migrations/001_initial.sql`; email-confirmation columns are added by `migrations/002_email_confirmation.sql`; RBAC tables (`roles`, `permissions`, `role_permissions`, `user_roles`) and seed data are in `migrations/003_rbac.sql`; collection-server roles/permissions (`collection_admin`, `curator`, `registrar`) are in `migrations/004_collection_permissions.sql`; subscription tables (`products`, `subscriptions`, `subscription_seats`) are in `migrations/005_products.sql` and `migrations/006_subscriptions.sql`; existing users are grandfathered into the Individual (free) plan by `migrations/007_grandfather_subscriptions.sql`. In production, all migrations are applied automatically by the `migrate` service. In dev Docker Compose, `001_initial.sql` runs automatically; the rest must be applied manually.

**JWT:** Tokens carry `{ sub, iat, exp, roles, permissions }` claims where `sub` is the user UUID as a string. `AuthMiddleware` validates Bearer tokens and injects `Claims` into request extensions. `PUT /users/{id}/password` requires a valid JWT (ownership or `users:change_any_password` permission). `GET /health` requires the `health:read` permission (admin only).

**RBAC:** Seeded roles: `admin` (has `health:read`, `users:change_any_password`, `users:read`, `users:write`, and all collection permissions), `user` (no permissions), `collection_admin`, `curator`, `registrar` (see `migrations/004_collection_permissions.sql` for permission sets). New users are automatically assigned the `user` role on registration. Promote a user by inserting a row into `user_roles`. Migration `008_admin_user_permissions.sql` adds `users:read` and `users:write` permissions and grants them to the `admin` role. Migration `009_comad_product.sql` seeds the `comad` product.

## Configuration

All config is read from environment variables at startup (`.env` loaded via `dotenv`). Required: `DATABASE_URL`, `JWT_SECRET`. Optional: `JWT_TTL_HOURS` (default 24), `RESET_TOKEN_TTL_MINUTES` (default 30), `CONFIRMATION_TOKEN_TTL_MINUTES` (default 1440), `ENABLE_DOCS` (default `true` — set `false` in production to disable `/openapi.yaml`, `/openapi.json`, `/docs`), `WHITELIST` (comma-separated IPs allowed to use plain HTTP in addition to localhost), `GEOBLOCK` (comma-separated ISO 3166-1 alpha-2 country codes to deny — requires `GEOIP_DB`), `GEOIP_DB` (path to a MaxMind GeoLite2-Country or GeoIP2-Country `.mmdb` file), `CORS_ORIGINS` (`*` to allow any origin, or comma-separated list of allowed origins e.g. `https://app.example.com`). SMTP (all optional — email disabled when `SMTP_HOST` absent): `SMTP_HOST`, `SMTP_PORT` (default 587), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `APP_BASE_URL`, `SMTP_NO_TLS` (set `true` for MailHog/no-TLS testing). Multi-tenant email links: `ALLOWED_APP_URLS` (comma-separated list of permitted `app_url` values that clients may supply in `POST /users` and `POST /auth/password-reset/request`; omit for single-tenant deployments). Subscriptions: `CLANN_APP_URL` (base URL of the Clann app; used to build checkout success/cancel/portal return URLs). Stripe (all optional — disabled when `STRIPE_SECRET_KEY` absent): `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_CLANN_FAMILY_BASE`, `STRIPE_PRICE_CLANN_FAMILY_SEAT`, `STRIPE_PRICE_CLANN_PROFESSIONAL`. PayPal (all optional — disabled when `PAYPAL_CLIENT_ID` absent): `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_PLAN_CLANN_FAMILY`, `PAYPAL_PLAN_CLANN_PROFESSIONAL`, `PAYPAL_WEBHOOK_ID`, `PAYPAL_SANDBOX` (set `true` for sandbox). See `.env.example` for all variables and defaults.

**Docker secrets (`_FILE` convention):** `DATABASE_URL`, `JWT_SECRET`, `SMTP_PASSWORD`, `ADMIN_PASSWORD`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `PAYPAL_CLIENT_ID`, and `PAYPAL_CLIENT_SECRET` each support a companion `_FILE` variable (e.g. `JWT_SECRET_FILE=/run/secrets/jwt_secret`). When set, the value is read from that file (contents trimmed) instead of the plain env var. If the file is unreadable, the service falls back to the plain env var with a warning.

**Payments:** Stripe and PayPal are optional; both are disabled when their respective env vars are absent. Stripe is enabled by setting `STRIPE_SECRET_KEY`; PayPal by setting `PAYPAL_CLIENT_ID` + `PAYPAL_CLIENT_SECRET`. Subscription state (plan, status, seat count) is embedded in the JWT at login under the `subscriptions` claim keyed by product slug. Webhooks update the DB; the user must re-login for the JWT to reflect the change.

## Admin seed (`src/seed.rs`)

On every startup, `seed::seed_admin` runs before the HTTP server binds. It reads:

| Variable | Default |
|---|---|
| `ADMIN_USERNAME` | `theboss` |
| `ADMIN_PASSWORD` | `changeme` |
| `ADMIN_EMAIL` | `admin@localhost` |

If no user with that username/email exists, it inserts one with `is_active = TRUE` (bypassing email confirmation) and assigns the `admin` role. The operation is idempotent — if the user already exists the seed logs a message and returns `Ok`. Changing the env vars after first run has no effect until the existing account is deleted from the database.
