# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
cargo build
cargo build --release

# Run (requires .env or environment variables)
cargo run

# Test (unit tests only — no database required)
cargo test

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
cargo run
```

## Architecture

This is a single-binary Actix-web microservice. `src/main.rs` wires together the connection pool, `AppState`, and route registration. `AppState` (defined in `main.rs`) is the shared state injected into every handler via `web::Data<AppState>`.

**Module layout:**

- `src/main.rs` — server bootstrap, route registration, `AppState` struct
- `src/models/mod.rs` — all request/response structs and DB model types
- `src/errors.rs` — `AppError` enum; implements `actix_web::ResponseError` to map errors to HTTP status codes
- `src/db/mod.rs` — all raw SQL queries (no ORM); returns `AppError` on failure
- `src/handlers/users.rs` — `POST /users`
- `src/handlers/auth.rs` — `POST /auth/login`, `PUT /users/{id}/password`, `POST /auth/password-reset/request`, `POST /auth/password-reset/confirm`
- `src/utils/jwt.rs` — `create_jwt` / `decode_jwt` using HS256
- `src/utils/password.rs` — Argon2id hashing, verification, validation, and secure token generation
- `src/tests.rs` — unit tests for password utils and JWT helpers; handler smoke tests using `actix_web::test` (no real DB needed)

**Data flow:** handlers call `db::*` functions directly (no service layer). All DB functions take `&Pool` and return `Result<T, AppError>`. The `AppError` enum converts into JSON `{ "error": "..." }` responses automatically.

**Database:** PostgreSQL only, native SQL via `tokio-postgres`. Schema is in `migrations/001_initial.sql`. The `docker-compose.yml` mounts this file into the Postgres `docker-entrypoint-initdb.d/` directory so it runs automatically on first start.

**JWT:** Tokens carry `{ sub, iat, exp }` claims where `sub` is the user UUID as a string. There is no middleware that validates JWTs on incoming requests — the `change_password` handler trusts the `{id}` path parameter directly (no bearer-token verification is wired in yet).

## Configuration

All config is read from environment variables at startup (`.env` loaded via `dotenv`). Required: `DATABASE_URL`, `JWT_SECRET`. See `.env.example` for all variables and defaults.
