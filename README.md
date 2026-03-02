# ullav-user-management

A user management microservice built in Rust that provides:

- **User account creation** — register with email, username, and password; assigned the `user` role automatically.
- **Email confirmation** — account is inactive until the confirmation token is verified.
- **Authentication** — log in and receive a signed JWT carrying roles and permissions.
- **Role-based access control** — middleware enforces JWT validity and permission checks on protected routes.
- **Password management** — users change their own password; admins can change any user's password.
- **Password reset** — request and confirm a secure password-reset token.

Data is persisted in **PostgreSQL** using native SQL (no ORM).

---

## Technology stack

| Component      | Crate / tool             |
|----------------|--------------------------|
| HTTP framework | `actix-web 4`            |
| Async runtime  | `tokio`                  |
| Database       | `tokio-postgres`         |
| Conn. pooling  | `deadpool-postgres`      |
| Password hash  | `rust-argon2` (Argon2id) |
| JWT            | `jsonwebtoken 10`        |
| Serialisation  | `serde` / `serde_json`   |

---

## API reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/users` | — | Create a new user account |
| `POST` | `/auth/login` | — | Authenticate and receive a JWT |
| `POST` | `/auth/confirm-email` | — | Activate account with confirmation token |
| `POST` | `/auth/password-reset/request` | — | Request a password-reset token |
| `POST` | `/auth/password-reset/confirm` | — | Complete a password reset |
| `PUT`  | `/users/{id}/password` | Bearer JWT | Change a user's password |
| `GET`  | `/health` | Bearer JWT (`health:read`) | Service and database health check |
| `GET`  | `/openapi.yaml` | — | OpenAPI spec |
| `GET`  | `/docs` | — | Swagger UI |

### POST /users

Creates an inactive account and returns a confirmation token.

```json
{
  "email": "alice@example.com",
  "username": "alice",
  "password": "s3cretP@ss"
}
```

Returns `200 OK`:

```json
{
  "message": "Account created. Use the confirmation token to activate your account.",
  "confirmation_token": "<64-char hex token>"
}
```

---

### POST /auth/confirm-email

Activates the account. The token comes from `POST /users`.

```json
{ "token": "<confirmation-token>" }
```

Returns `204 No Content`.

---

### POST /auth/login

```json
{
  "email": "alice@example.com",
  "password": "s3cretP@ss"
}
```

Returns `200 OK`. The JWT carries `roles` and `permissions` claims:

```json
{
  "token": "<jwt>",
  "user": { "id": "...", "email": "...", "username": "...", "is_active": true, "..." },
  "roles": ["user"],
  "permissions": []
}
```

---

### PUT /users/{id}/password

Requires `Authorization: Bearer <token>`.

- **Own account** — must supply `current_password`.
- **Admin** (holds `users:change_any_password`) — may omit `current_password`.

```json
{
  "current_password": "s3cretP@ss",
  "new_password": "newP@ssw0rd"
}
```

Returns `204 No Content`. Returns `401` if the token is missing/invalid, `403` if the caller is neither the owner nor an admin.

---

### POST /auth/password-reset/request

```json
{ "email": "alice@example.com" }
```

Returns `200 OK`. Always succeeds to prevent user enumeration. The reset token is included in the response body (in production it would be sent by email).

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

### GET /health

Requires `Authorization: Bearer <token>` with the `health:read` permission (admin only).

Returns `200 OK` when healthy, `503` when the database is unreachable:

```json
{ "status": "ok", "database": "ok" }
```

---

## Roles and permissions

Two roles are seeded at migration time:

| Role | Permissions |
|------|-------------|
| `admin` | `health:read`, `users:change_any_password` |
| `user` | _(none)_ |

Every new user is automatically assigned the `user` role. To promote a user to admin, insert a row into `user_roles`:

```sql
INSERT INTO user_roles (user_id, role_id)
SELECT '<user-uuid>', id FROM roles WHERE name = 'admin';
```

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

> **Note:** `docker-compose.yml` applies `migrations/001_initial.sql` automatically on first start. Apply the remaining migrations manually against the running container's database:
>
> ```bash
> psql "postgresql://app_user:app_password@localhost:5433/user_management" \
>   -f migrations/002_email_confirmation.sql \
>   -f migrations/003_rbac.sql
> ```

### Running locally (without Docker)

```bash
# 1. Copy and edit the environment file
cp .env.example .env
# Edit DATABASE_URL and JWT_SECRET

# 2. Apply all migrations
psql "$DATABASE_URL" -f migrations/001_initial.sql
psql "$DATABASE_URL" -f migrations/002_email_confirmation.sql
psql "$DATABASE_URL" -f migrations/003_rbac.sql

# 3. Run
cargo run
```

### Running tests

```bash
# Unit and handler tests (no database required)
cargo test

# Include the health endpoint integration test (requires Docker DB on port 5433)
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
| `CONFIRMATION_TOKEN_TTL_MINUTES` | `1440` | Email confirmation token lifetime in minutes |
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8081` | Listen port |
| `RUST_LOG` | `info` | Log level |

---

## Database schema

Migrations are applied in order:

| Migration | Tables |
|-----------|--------|
| `001_initial.sql` | `users`, `password_reset_tokens` |
| `002_email_confirmation.sql` | Adds `confirmation_token` columns to `users` |
| `003_rbac.sql` | `roles`, `permissions`, `role_permissions`, `user_roles` |
