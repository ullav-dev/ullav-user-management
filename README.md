# ullav-user-management

A user management microservice built in Rust that provides:

- **User account creation** — register with email, username, and password; assigned the `user` role automatically.
- **Email confirmation** — account is inactive until the confirmation token is verified; a confirmation email is sent automatically when SMTP is configured.
- **Authentication** — log in and receive a signed JWT carrying roles and permissions.
- **Role-based access control** — middleware enforces JWT validity and permission checks on protected routes.
- **Password management** — users change their own password; admins can change any user's password.
- **Password reset** — request and confirm a secure password-reset token; a reset link is emailed automatically when SMTP is configured.
- **Multi-tenant email links** — `POST /users` and `POST /auth/password-reset/request` accept an optional `app_url` field; the service validates it against an allowlist (`ALLOWED_APP_URLS`) and uses it as the base for confirmation and reset links, enabling one auth service to serve multiple front-end applications.
- **Docker secrets** — `JWT_SECRET`, `SMTP_PASSWORD`, and `ADMIN_PASSWORD` each support a `_FILE` variant (e.g. `JWT_SECRET_FILE=/run/secrets/jwt_secret`) for use with Docker / Compose secrets.
- **HTTPS enforcement** — non-HTTPS requests are rejected with `403` unless the client IP is localhost or listed in `WHITELIST`; proxy-terminated TLS is detected via `X-Forwarded-Proto`.
- **Geo-blocking** — requests from IPs in blocked countries are denied with `403`; configured via `GEOBLOCK` (ISO country codes) and `GEOIP_DB` (MaxMind `.mmdb` file).
- **CORS** — cross-origin resource sharing headers; configured via `CORS_ORIGINS` (`*` for any origin, or a comma-separated list of allowed origins).
- **Subscriptions** — per-product subscription management (Individual free, Family, Professional plans). Stripe and PayPal checkout, Stripe Customer Portal, and webhook receivers for lifecycle events. Subscription state (plan, status, seat count) is embedded in the JWT at login under the `subscriptions` claim.
- **Grandfather free plan** — all users who existed before the subscription system was introduced are automatically seeded with an Individual (free) subscription for Clann.

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
| Email          | `lettre 0.11` (SMTP)     |
| CORS           | `actix-cors 0.7`         |
| Geo-blocking   | `maxminddb 0.27`         |

---

## API reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/users` | — | Create a new user account |
| `POST` | `/auth/login` | — | Authenticate and receive a JWT |
| `POST` | `/auth/confirm-email` | — | Activate account with confirmation token (JSON body) |
| `GET`  | `/auth/confirm-email?token=…` | — | Activate account via link click |
| `POST` | `/auth/password-reset/request` | — | Request a password-reset token |
| `POST` | `/auth/password-reset/confirm` | — | Complete a password reset |
| `PUT`  | `/users/{id}/password` | Bearer JWT | Change a user's password |
| `GET`  | `/health` | Bearer JWT (`health:read`) | Service and database health check |
| `GET`  | `/subscriptions/current?product=<slug>` | Bearer JWT | Active subscription for a product (returns Individual free if none) |
| `POST` | `/subscriptions/checkout` | Bearer JWT | Initiate Stripe or PayPal checkout session |
| `POST` | `/subscriptions/portal` | Bearer JWT | Create Stripe Customer Portal session |
| `POST` | `/webhooks/stripe` | — (signature verified) | Stripe lifecycle event receiver |
| `POST` | `/webhooks/paypal` | — (signature verified) | PayPal lifecycle event receiver |
| `GET`  | `/openapi.yaml` | — | OpenAPI spec (YAML) |
| `GET`  | `/openapi.json` | — | OpenAPI spec (JSON) |
| `GET`  | `/docs` | — | Swagger UI |

### POST /users

Creates an inactive account. If SMTP is configured, a confirmation email is sent to the provided address containing a clickable activation link. The confirmation token is also returned in the response body (useful when SMTP is not configured).

The optional `app_url` field sets the base URL used to build the confirmation link in the email. It must be present in `ALLOWED_APP_URLS` when that variable is configured; omit it to use the server's default `APP_BASE_URL`.

```json
{
  "email": "alice@example.com",
  "username": "alice",
  "password": "s3cretP@ss",
  "app_url": "https://app.example.com"
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

Activates the account. The token comes from the confirmation email (or the `POST /users` response body when SMTP is not configured).

```json
{ "token": "<confirmation-token>" }
```

Returns `204 No Content`.

---

### GET /auth/confirm-email?token=…

Same as `POST /auth/confirm-email` but accepts the token as a query parameter. This is the endpoint linked to in the confirmation email — email clients fire a GET request when the user clicks the link.

Returns `204 No Content`.

---

### POST /auth/login

```json
{
  "email": "alice@example.com",
  "password": "s3cretP@ss"
}
```

Returns `200 OK`. The JWT carries `roles`, `permissions`, and `subscriptions` claims:

```json
{
  "token": "<jwt>",
  "user": { "id": "...", "email": "...", "username": "...", "is_active": true, "..." },
  "roles": ["user"],
  "permissions": [],
  "subscriptions": {
    "clann": { "tier": "family", "status": "active", "seat_count": 4 }
  }
}
```

The `subscriptions` map is keyed by product slug. Users with no paid subscription receive an empty map (treated as Individual free by downstream services). Downstream services can read plan limits from the JWT without an extra DB call; the user must re-login after a plan change for the JWT to reflect the new state.

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

Returns `200 OK`. Always succeeds to prevent user enumeration. If SMTP is configured, a password-reset email is sent to the address containing a clickable link. When SMTP is not configured, the reset token is logged to stdout instead.

The optional `app_url` field sets the base URL used to build the reset link in the email. It must be present in `ALLOWED_APP_URLS` when that variable is configured; omit it to use the server's default `APP_BASE_URL`.

```json
{
  "email": "alice@example.com",
  "app_url": "https://app.example.com"
}
```

---

### POST /auth/password-reset/confirm

```json
{
  "token": "<reset-token>",
  "new_password": "fresh_P@ssw0rd"
}
```

Returns `204 No Content`. If the account is not yet active (email confirmation never completed), it is activated automatically — a successful password reset is treated as sufficient proof of email ownership.

---

### GET /subscriptions/current?product=\<slug\>

Requires `Authorization: Bearer <token>`. Returns the caller's active or trialing subscription for the given product slug (e.g. `clann`). When no subscription row exists, a synthetic Individual (free) response is returned so clients never need to special-case a 404.

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "product": "clann",
  "plan": "individual",
  "status": "active",
  "seat_count": 1
}
```

---

### POST /subscriptions/checkout

Requires `Authorization: Bearer <token>`. Initiates a hosted checkout session with Stripe or PayPal. Returns a redirect URL.

```json
{
  "product": "clann",
  "plan": "family",
  "provider": "stripe",
  "seat_count": 4
}
```

Returns `200 OK`:

```json
{ "url": "https://checkout.stripe.com/..." }
```

---

### POST /subscriptions/portal

Requires `Authorization: Bearer <token>`. Creates a Stripe Customer Portal session so the user can manage billing, change plan, or cancel. The caller must have an existing Stripe subscription.

Returns `200 OK`:

```json
{ "url": "https://billing.stripe.com/..." }
```

---

### POST /webhooks/stripe / POST /webhooks/paypal

Webhook endpoints for Stripe and PayPal lifecycle events (subscription activated, renewed, cancelled, etc.). Stripe events are verified using the `Stripe-Signature` header and `STRIPE_WEBHOOK_SECRET`; PayPal events are verified via PayPal's verification API.

Both return `200 OK` on success, `401` on signature failure, `500` on handler error (so the provider retries).

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
| `admin` | `health:read`, `users:change_any_password`, `users:read`, `users:write`, and all collection permissions |
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
>   -f migrations/003_rbac.sql \
>   -f migrations/004_collection_permissions.sql \
>   -f migrations/005_products.sql \
>   -f migrations/006_subscriptions.sql \
>   -f migrations/007_grandfather_subscriptions.sql \
>   -f migrations/008_admin_user_permissions.sql \
>   -f migrations/009_comad_product.sql
> ```

### Production deployment

`docker-compose-prod.yaml` is the production Compose file. Three services (`db`, `migrate`, `app`) run on an external `ullav-net` Docker network with **no host port bindings**. All secrets are injected via Docker secrets.

The `migrate` service runs `scripts/migrate.sh` once on deploy — it applies any unapplied migrations from `migrations/` in order, tracking state in a `schema_migrations` table. The `app` service only starts after `migrate` completes successfully.

**One-time network setup:**

```bash
docker network create ullav-net
```

**Populate secret files** (keep these out of version control):

```bash
mkdir -p secrets
echo -n "postgresql://myuser:mypass@db:5432/user_management" > secrets/database_url.txt
echo -n "strong-db-password"  > secrets/db_password.txt
echo -n "long-random-jwt-key" > secrets/jwt_secret.txt
echo -n "smtp-password"       > secrets/smtp_password.txt
echo -n "admin-password"      > secrets/admin_password.txt
chmod 600 secrets/*.txt
```

**Configure non-secret variables:**

```bash
# Edit .env.prod — set SMTP_HOST, APP_BASE_URL, ADMIN_EMAIL, DATABASE_USER, DATABASE_NAME, etc.
```

**Deploy:**

```bash
docker compose -f docker-compose-prod.yaml --env-file .env.prod up -d
```

> `.env.prod` and `secrets/` are `.gitignore`d so they are never committed.

---

### Running locally (without Docker)

```bash
# 1. Copy and edit the environment file
cp .env.example .env
# Edit DATABASE_URL and JWT_SECRET

# 2. Apply all migrations
psql "$DATABASE_URL" -f migrations/001_initial.sql
psql "$DATABASE_URL" -f migrations/002_email_confirmation.sql
psql "$DATABASE_URL" -f migrations/003_rbac.sql
psql "$DATABASE_URL" -f migrations/004_collection_permissions.sql
psql "$DATABASE_URL" -f migrations/005_products.sql
psql "$DATABASE_URL" -f migrations/006_subscriptions.sql
psql "$DATABASE_URL" -f migrations/007_grandfather_subscriptions.sql
psql "$DATABASE_URL" -f migrations/008_admin_user_permissions.sql
psql "$DATABASE_URL" -f migrations/009_comad_product.sql

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

## Admin user seed

On every startup, before the HTTP server binds, the service idempotently ensures an admin user exists. If no user with the configured username or email is found, one is inserted with `is_active = true` (bypassing email confirmation) and assigned the `admin` role.

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_USERNAME` | `theboss` | Admin account username |
| `ADMIN_EMAIL` | `admin@localhost` | Admin account email |
| `ADMIN_PASSWORD` | `changeme` | Admin account password — **change in production** (supports `ADMIN_PASSWORD_FILE`) |

Changing these env vars after first run has no effect until the existing account is deleted from the database.

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
| `ADMIN_USERNAME` | `theboss` | Seeded admin username |
| `ADMIN_EMAIL` | `admin@localhost` | Seeded admin email |
| `ADMIN_PASSWORD` | `changeme` | Seeded admin password |
| `ENABLE_DOCS` | `true` | Set `false` in production to disable `/openapi.yaml`, `/openapi.json`, and `/docs` |
| `WHITELIST` | — | Comma-separated IPs allowed to use plain HTTP (e.g. `10.0.0.1,10.0.0.2`); `127.0.0.1` and `::1` are always allowed |
| `GEOBLOCK` | — | Comma-separated ISO 3166-1 alpha-2 country codes to deny (e.g. `CN,RU,KP`); requires `GEOIP_DB` |
| `GEOIP_DB` | — | Path to a MaxMind GeoLite2-Country or GeoIP2-Country `.mmdb` file |
| `CORS_ORIGINS` | — | `*` to allow any origin, or comma-separated list of allowed origins (e.g. `https://app.example.com`); omit to disable CORS headers |
| `SMTP_HOST` | — | SMTP server hostname; omit to disable email sending |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USERNAME` | — | SMTP authentication username (optional) |
| `SMTP_PASSWORD` | — | SMTP authentication password (optional; see Docker secrets below) |
| `SMTP_FROM` | — | From address for outgoing emails |
| `APP_BASE_URL` | — | Default base URL used to build confirmation and reset links |
| `SMTP_NO_TLS` | `false` | Set `true` to use an unencrypted connection (e.g. for MailHog) |
| `ALLOWED_APP_URLS` | — | Comma-separated allowlist of `app_url` values accepted in `POST /users` and `POST /auth/password-reset/request` (see Multi-tenant below) |
| `CLANN_APP_URL` | — | Base URL of the Clann front-end; used to build checkout success/cancel and portal return URLs |
| `STRIPE_SECRET_KEY` | — | Stripe secret key; omit to disable Stripe (supports `_FILE`) |
| `STRIPE_WEBHOOK_SECRET` | — | Stripe webhook signing secret for `POST /webhooks/stripe` |
| `STRIPE_PRICE_CLANN_FAMILY_BASE` | — | Stripe Price ID for the Clann Family plan base charge |
| `STRIPE_PRICE_CLANN_FAMILY_SEAT` | — | Stripe Price ID for each additional Family seat |
| `STRIPE_PRICE_CLANN_PROFESSIONAL` | — | Stripe Price ID for the Clann Professional plan |
| `PAYPAL_CLIENT_ID` | — | PayPal app client ID; omit to disable PayPal (supports `_FILE`) |
| `PAYPAL_CLIENT_SECRET` | — | PayPal app client secret (supports `_FILE`) |
| `PAYPAL_PLAN_CLANN_FAMILY` | — | PayPal billing plan ID for Clann Family |
| `PAYPAL_PLAN_CLANN_PROFESSIONAL` | — | PayPal billing plan ID for Clann Professional |
| `PAYPAL_WEBHOOK_ID` | — | PayPal webhook ID used for signature verification |
| `PAYPAL_SANDBOX` | `false` | Set `true` to use PayPal sandbox endpoints |

#### Docker secrets

`DATABASE_URL`, `JWT_SECRET`, `SMTP_PASSWORD`, and `ADMIN_PASSWORD` each support a `_FILE` companion variable. When set, the value is read from that file (trailing whitespace trimmed) instead of the plain env var. If the file is unreadable, the service falls back to the plain env var with a warning log.

```yaml
# docker-compose-prod.yaml (excerpt)
services:
  db:
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets: [db_password]

  app:
    secrets: [database_url, jwt_secret, smtp_password, admin_password]
    environment:
      DATABASE_URL_FILE: /run/secrets/database_url
      JWT_SECRET_FILE: /run/secrets/jwt_secret
      SMTP_PASSWORD_FILE: /run/secrets/smtp_password
      ADMIN_PASSWORD_FILE: /run/secrets/admin_password

secrets:
  db_password:
    file: ./secrets/db_password.txt
  database_url:
    file: ./secrets/database_url.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt
  smtp_password:
    file: ./secrets/smtp_password.txt
  admin_password:
    file: ./secrets/admin_password.txt
```

---

#### Multi-tenant email links

When this auth service is shared across multiple front-end applications, each application can pass its own base URL in the request body:

```json
POST /users
{ "email": "...", "username": "...", "password": "...", "app_url": "https://app2.example.com/fr" }

POST /auth/password-reset/request
{ "email": "...", "app_url": "https://app2.example.com/fr" }
```

Configure the allowlist to restrict which URLs are accepted:

```
ALLOWED_APP_URLS=https://app1.example.com,https://app2.example.com/fr
```

- When `ALLOWED_APP_URLS` is **not set**, any `app_url` in the request body is silently ignored and `APP_BASE_URL` is always used (single-tenant mode — secure by default).
- When `ALLOWED_APP_URLS` **is set**, a supplied `app_url` must be in the list or the request is rejected with `400`.
- Omitting `app_url` always falls back to `APP_BASE_URL` regardless of whether an allowlist is configured.

---

#### Geo-blocking setup

Download the free [GeoLite2-Country database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (requires a free MaxMind account), then set:

```
GEOIP_DB=/etc/geoip/GeoLite2-Country.mmdb
GEOBLOCK=CN,RU,KP
```

If `GEOBLOCK` is empty or `GEOIP_DB` is not set, geo-blocking is silently disabled. Invalid or private IP addresses that have no GeoIP entry are always allowed through.

---

#### Local email testing with MailHog

```bash
docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog
```

Then set in `.env`:

```
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_NO_TLS=true
SMTP_FROM=test@example.com
APP_BASE_URL=http://localhost:8081
```

Emails are visible at `http://localhost:8025`.

---

## Database schema

Migrations are applied in order:

| Migration | Tables / changes |
|-----------|-----------------|
| `001_initial.sql` | `users`, `password_reset_tokens` |
| `002_email_confirmation.sql` | Adds `confirmation_token` columns to `users` |
| `003_rbac.sql` | `roles`, `permissions`, `role_permissions`, `user_roles`; seeds `admin` and `user` roles |
| `004_collection_permissions.sql` | Seeds collection permissions and roles: `collection_admin`, `curator`, `registrar` |
| `005_products.sql` | `products` table; seeds the `clann` product |
| `006_subscriptions.sql` | `subscriptions`, `subscription_seats` tables with indexes |
| `007_grandfather_subscriptions.sql` | Seeds all existing users with an Individual (free) Clann subscription |

In production, migrations are applied automatically by the `migrate` service on each deploy (idempotent — already-applied files are skipped). For local development without Docker, apply them manually with `psql` as shown above.
