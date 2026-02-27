# ullav-user-management

A user management microservice built in Rust that provides:

- **User account creation** — register users with email, username and password.
- **Authentication** — log in and receive a signed JWT.
- **Password management** — change your own password (authenticated).
- **Password reset** — request and confirm a secure password-reset token.

Data is persisted in **PostgreSQL** using native SQL (no ORM).

---

## Technology stack

| Component      | Crate / tool          |
|----------------|-----------------------|
| HTTP framework | `actix-web 4`         |
| Async runtime  | `tokio`               |
| Database       | `tokio-postgres`      |
| Conn. pooling  | `deadpool-postgres`   |
| Password hash  | `rust-argon2` (Argon2id) |
| JWT            | `jsonwebtoken 10`     |
| Serialisation  | `serde` / `serde_json`|

---

## API reference

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/users` | Create a new user account |
| `POST` | `/auth/login` | Authenticate and receive a JWT |
| `PUT`  | `/users/{id}/password` | Change a user's password |
| `POST` | `/auth/password-reset/request` | Request a password-reset token |
| `POST` | `/auth/password-reset/confirm` | Confirm a password reset |

### POST /users

```json
{
  "email": "alice@example.com",
  "username": "alice",
  "password": "s3cretP@ss"
}
```

Returns `201 Created` with the new user object (password hash omitted).

---

### POST /auth/login

```json
{
  "email": "alice@example.com",
  "password": "s3cretP@ss"
}
```

Returns `200 OK` with `{ "token": "<jwt>", "user": { … } }`.

---

### PUT /users/{id}/password

```json
{
  "current_password": "s3cretP@ss",
  "new_password": "newP@ssw0rd"
}
```

Returns `204 No Content`.

---

### POST /auth/password-reset/request

```json
{ "email": "alice@example.com" }
```

Returns `200 OK`. The reset token is included in the response body (in production it would be sent by email).

---

### POST /auth/password-reset/confirm

```json
{
  "token": "<reset-token>",
  "new_password": "fresh_P@ssw0rd"
}
```

Returns `204 No Content`.

---

## Getting started

### Prerequisites

- [Rust](https://rustup.rs/) ≥ 1.80
- [Docker](https://www.docker.com/) & Docker Compose (for the full stack)

### Quick start with Docker Compose

```bash
# 1. Clone the repo
git clone https://github.com/colinmanning/ullav-user-management.git
cd ullav-user-management

# 2. Start PostgreSQL and the service
docker compose up --build
```

The API will be available at `http://localhost:8081`.

### Running locally (without Docker)

```bash
# 1. Copy and edit the environment file
cp .env.example .env
# Edit DATABASE_URL and JWT_SECRET

# 2. Apply the schema to your Postgres instance
psql "$DATABASE_URL" -f migrations/001_initial.sql

# 3. Run
cargo run
```

### Running tests

```bash
# Unit and handler tests (no database required)
cargo test

# Include the health endpoint integration test
TEST_DATABASE_URL=postgresql://app_user:app_password@localhost:5433/user_management cargo test
```

> The Docker database is exposed on host port **5433** to avoid conflicts with a local PostgreSQL instance on 5432.

---

## Configuration

All configuration is via environment variables (or a `.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | PostgreSQL connection URL (required) |
| `JWT_SECRET` | — | HMAC secret for signing JWTs (required) |
| `JWT_TTL_HOURS` | `24` | JWT validity in hours |
| `RESET_TOKEN_TTL_MINUTES` | `30` | Password-reset token lifetime in minutes |
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8081` | Listen port |
| `RUST_LOG` | `info` | Log level |

---

## Database schema

The schema lives in [`migrations/001_initial.sql`](migrations/001_initial.sql) and creates two tables:

- **`users`** — core account data (email, username, Argon2id password hash).
- **`password_reset_tokens`** — short-lived tokens issued during a reset flow.
