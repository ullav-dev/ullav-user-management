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

### Local setup without Docker

```bash
cp .env.example .env
# Edit DATABASE_URL and JWT_SECRET in .env
psql "$DATABASE_URL" -f migrations/001_initial.sql
psql "$DATABASE_URL" -f migrations/002_email_confirmation.sql
psql "$DATABASE_URL" -f migrations/003_rbac.sql
cargo run
```

## Architecture

This is a single-binary Actix-web microservice. `src/main.rs` wires together the connection pool, `AppState`, and route registration. `AppState` (defined in `main.rs`) is the shared state injected into every handler via `web::Data<AppState>`.

**Module layout:**

- `src/main.rs` — server bootstrap, route registration, `AppState` struct
- `src/models/mod.rs` — all request/response structs and DB model types
- `src/errors.rs` — `AppError` enum; implements `actix_web::ResponseError` to map errors to HTTP status codes
- `src/db/mod.rs` — all raw SQL queries (no ORM); returns `AppError` on failure
- `src/handlers/users.rs` — `POST /users` (open; assigns `user` role on creation)
- `src/handlers/auth.rs` — `POST /auth/login`, `PUT /users/{id}/password` (JWT-protected), `POST /auth/password-reset/request`, `POST /auth/password-reset/confirm`, `POST /auth/confirm-email`, `GET /auth/confirm-email` (link-click activation)
- `src/handlers/health.rs` — `GET /health` (admin-only; requires `health:read` permission)
- `src/handlers/docs.rs` — `GET /openapi.yaml`, `GET /openapi.json` (YAML spec embedded via `include_str!`, converted to JSON with `serde_yaml`), `GET /docs` (Swagger UI via CDN); all three disabled when `ENABLE_DOCS=false`
- `src/middleware/auth.rs` — `AuthMiddleware`: validates Bearer JWT, optionally checks a permission claim, injects `Claims` into request extensions
- `src/utils/jwt.rs` — `create_jwt` / `decode_jwt` using HS256; `Claims` carries `sub`, `iat`, `exp`, `roles`, `permissions`
- `src/seed.rs` — `seed_admin`: runs at startup, idempotently inserts the admin user (active, admin role) using `ADMIN_USERNAME/EMAIL/PASSWORD` env vars
- `src/utils/email.rs` — `build_mailer` (STARTTLS or no-TLS), `send_confirmation_email`, `send_password_reset_email` (HTML emails via lettre)
- `src/utils/password.rs` — Argon2id hashing, verification, validation, and secure token generation
- `src/tests.rs` — unit tests for password utils and JWT helpers; handler smoke tests using `actix_web::test` (no real DB needed)

**Data flow:** handlers call `db::*` functions directly (no service layer). All DB functions take `&Pool` and return `Result<T, AppError>`. The `AppError` enum converts into JSON `{ "error": "..." }` responses automatically.

**Database:** PostgreSQL only, native SQL via `tokio-postgres`. Schema is in `migrations/001_initial.sql`; email-confirmation columns are added by `migrations/002_email_confirmation.sql`; RBAC tables (`roles`, `permissions`, `role_permissions`, `user_roles`) and seed data are in `migrations/003_rbac.sql`. The `docker-compose.yml` mounts `001_initial.sql` into the Postgres `docker-entrypoint-initdb.d/` directory so it runs automatically on first start; `002_email_confirmation.sql` and `003_rbac.sql` must be applied manually.

**JWT:** Tokens carry `{ sub, iat, exp, roles, permissions }` claims where `sub` is the user UUID as a string. `AuthMiddleware` validates Bearer tokens and injects `Claims` into request extensions. `PUT /users/{id}/password` requires a valid JWT (ownership or `users:change_any_password` permission). `GET /health` requires the `health:read` permission (admin only).

**RBAC:** Two seeded roles: `admin` (has `health:read` and `users:change_any_password`) and `user` (no permissions). New users are automatically assigned the `user` role on registration. Promote a user to admin by inserting a row into `user_roles`.

## Configuration

All config is read from environment variables at startup (`.env` loaded via `dotenv`). Required: `DATABASE_URL`, `JWT_SECRET`. Optional: `JWT_TTL_HOURS` (default 24), `RESET_TOKEN_TTL_MINUTES` (default 30), `CONFIRMATION_TOKEN_TTL_MINUTES` (default 1440), `ENABLE_DOCS` (default `true` — set `false` in production to disable `/openapi.yaml`, `/openapi.json`, `/docs`). SMTP (all optional — email disabled when `SMTP_HOST` absent): `SMTP_HOST`, `SMTP_PORT` (default 587), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `APP_BASE_URL`, `SMTP_NO_TLS` (set `true` for MailHog/no-TLS testing). See `.env.example` for all variables and defaults.

## Admin seed (`src/seed.rs`)

On every startup, `seed::seed_admin` runs before the HTTP server binds. It reads:

| Variable | Default |
|---|---|
| `ADMIN_USERNAME` | `theboss` |
| `ADMIN_PASSWORD` | `changeme` |
| `ADMIN_EMAIL` | `admin@localhost` |

If no user with that username/email exists, it inserts one with `is_active = TRUE` (bypassing email confirmation) and assigns the `admin` role. The operation is idempotent — if the user already exists the seed logs a message and returns `Ok`. Changing the env vars after first run has no effect until the existing account is deleted from the database.
