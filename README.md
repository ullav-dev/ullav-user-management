# ullav-user-management

A user management microservice built in Rust that provides:

- **User account creation** — register with email, username, and password; assigned the `user` role automatically.
- **Email confirmation** — account is inactive until the confirmation token is verified; a confirmation email is sent automatically when SMTP is configured.
- **Authentication** — log in and receive a signed JWT carrying roles and permissions.
- **Role-based access control** — middleware enforces JWT validity and permission checks on protected routes.
- **Password management** — users change their own password; admins can change any user's password.
- **Password reset** — request and confirm a secure password-reset token; a reset link is emailed automatically when SMTP is configured.
- **Multi-tenant email links** — `POST /users` and `POST /auth/password-reset/request` accept an optional `app_url` field; the service validates it against an allowlist (`ALLOWED_APP_URLS`) and uses it as the base for confirmation and reset links, enabling one auth service to serve multiple front-end applications.
- **Admin API** — JWT-protected (`users:read`) endpoints for managing users, roles, permissions, subscriptions, products, and plans; user list supports pagination, search, and sorting.
- **Docker secrets** — `DATABASE_URL`, `JWT_SECRET`, `SMTP_PASSWORD`, `ADMIN_PASSWORD`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `PAYPAL_CLIENT_ID`, and `PAYPAL_CLIENT_SECRET` each support a `_FILE` variant for use with Docker / Compose secrets.
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
| `GET`  | `/admin/users` | Bearer JWT (`users:read`) | List users (paginated, searchable; `sort_by=username\|email\|created_at`, `sort_dir=asc\|desc`) |
| `GET`  | `/admin/users/{id}` | Bearer JWT (`users:read`) | Get single user with roles |
| `PATCH` | `/admin/users/{id}` | Bearer JWT (`users:read`) | Update user profile |
| `DELETE` | `/admin/users/{id}` | Bearer JWT (`users:read`) | Delete user |
| `POST` | `/admin/users/{id}/roles/{role}` | Bearer JWT (`users:read`) | Assign role to user |
| `DELETE` | `/admin/users/{id}/roles/{role}` | Bearer JWT (`users:read`) | Remove role from user |
| `POST` | `/admin/users/{id}/subscriptions` | Bearer JWT (`users:read`) | Create subscription for user |
| `GET`  | `/admin/roles` | Bearer JWT (`users:read`) | List roles with permissions |
| `POST` | `/admin/roles` | Bearer JWT (`users:read`) | Create role |
| `DELETE` | `/admin/roles/{name}` | Bearer JWT (`users:read`) | Delete role |
| `GET`  | `/admin/permissions` | Bearer JWT (`users:read`) | List all permissions |
| `POST` | `/admin/permissions` | Bearer JWT (`users:read`) | Create permission |
| `POST` | `/admin/roles/{name}/permissions/{perm}` | Bearer JWT (`users:read`) | Assign permission to role |
| `DELETE` | `/admin/roles/{name}/permissions/{perm}` | Bearer JWT (`users:read`) | Remove permission from role |
| `GET`  | `/admin/subscriptions` | Bearer JWT (`users:read`) | List subscriptions (paginated, filterable by product) |
| `PATCH` | `/admin/subscriptions/{id}` | Bearer JWT (`users:read`) | Update plan / status / seat count |
| `DELETE` | `/admin/subscriptions/{id}` | Bearer JWT (`users:read`) | Delete subscription |
| `GET`  | `/admin/products` | Bearer JWT (`users:read`) | List products |
| `GET`  | `/admin/plans` | Bearer JWT (`users:read`) | List plans (optionally filtered by `?product=<slug>`) |
| `POST` | `/admin/plans` | Bearer JWT (`users:read`) | Create plan |
| `DELETE` | `/admin/plans/{id}` | Bearer JWT (`users:read`) | Delete plan |
| `GET`  | `/openapi.yaml` | — | OpenAPI spec (YAML) |
| `GET`  | `/openapi.json` | — | OpenAPI spec (JSON) |
| `GET`  | `/docs` | — | Swagger UI |
| `GET`  | `/.well-known/oauth-authorization-server` | — | RFC 8414 AS metadata |
| `GET`  | `/oauth2/jwks` | — | RS256 public keys (JWKS) |
| `POST` | `/oauth2/register` | — | RFC 7591 Dynamic Client Registration |
| `GET`  | `/oauth2/authorize` | — | Begin authorization code + PKCE flow |
| `POST` | `/oauth2/authorize` | — | Submit login credentials or account chooser action |
| `POST` | `/oauth2/token` | — | Exchange code for tokens; refresh token rotation |
| `POST` | `/oauth2/revoke` | — | Revoke a refresh token |

---

## OAuth2 Authorization Server

UUM acts as an OAuth2 Authorization Server (RFC 6749 / RFC 7636 PKCE) for all Ullav MCP resource servers. Clients — such as Claude Code's native MCP transport or `mcp-remote` — use the standard Authorization Code + PKCE flow to obtain audience-bound RS256 tokens.

### Discovery endpoints

| Path | Description |
|------|-------------|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 AS metadata (issuer, endpoints, supported scopes) |
| `GET /oauth2/jwks` | JSON Web Key Set for RS256 token verification |
| `GET /oauth2/register` | RFC 7591 Dynamic Client Registration |

### Authorization flow

```
Client                        Browser                        UUM
  │                              │                             │
  │── open /oauth2/authorize ──▶ │                             │
  │   (PKCE code_challenge)      │── GET /oauth2/authorize ──▶ │
  │                              │                             │ check session cookie
  │                              │◀── account chooser / ───── │
  │                              │    login form               │
  │                              │── POST /oauth2/authorize ─▶ │
  │                              │   (credentials or continue) │
  │                              │◀── redirect with code ───── │
  │◀── code via callback ────── │                             │
  │── POST /oauth2/token ───────────────────────────────────▶ │
  │◀── access_token + refresh_token ──────────────────────── │
```

### Account chooser and switching accounts

When a browser session already exists and the client is first-party (e.g. all MCP clients), UUM shows an **account chooser** page instead of silently redirecting:

- **"Continue as [email]"** — auto-focused button; press Enter to proceed with the existing account. This is the default path — no account switch needed.
- **"Use a different account"** — link that reloads the authorize flow with `prompt=login`, clearing session reuse and showing the login form directly.

This is important for users with multiple accounts (e.g. a personal account and a business account, or different roles on different products). Without it, whichever account was last used in the browser would be silently picked.

### `prompt=login`

Append `prompt=login` to any `/oauth2/authorize` URL to force re-authentication regardless of an existing session:

```
/oauth2/authorize?...&prompt=login
```

The session cookie is ignored and the login form is shown directly. This is the mechanism the "Use a different account" link uses. MCP clients that support the `prompt` parameter can also send it in the initial authorization request.

### Scopes

| Scope | Meaning |
|-------|---------|
| `mcp:tools` | Use AI-assisted tools on the user's behalf |
| `obair:tools` | Use AI tools on AWE projects and workflows (requires the `obair` product) |

UUM enforces a product access gate at token issuance: if the requested `resource` maps to a gated product and the user does not have access, the authorization code is not issued and the browser is redirected back to the client with `error=access_denied`.

### OAuth2 configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH2_ISSUER` | — | Issuer URL embedded in tokens and AS metadata (required for OAuth2) |
| `OAUTH2_PRIVATE_KEY_FILE` | — | Path to PEM-encoded RSA private key for RS256 token signing |
| `OAUTH2_SESSION_TTL_DAYS` | `30` | Browser session cookie lifetime |
| `OAUTH2_AUTH_CODE_TTL_MINUTES` | `10` | Authorization code lifetime |
| `OAUTH2_ACCESS_TOKEN_TTL_MINUTES` | `60` | Access token lifetime |
| `OAUTH2_REFRESH_TOKEN_TTL_DAYS` | `90` | Refresh token lifetime |

### Service clients (`client_credentials` grant)

A **service client** is a confidential OAuth2 client for unattended, machine-to-machine callers (an MCP server, an AWE automated task) with no human present to complete an interactive login. It authenticates via the `client_credentials` grant with a `client_id` + `client_secret`, and is bound to a dedicated `users` row (its "service account") so minted tokens flow through the same identity/claims pipeline as a human user's token.

Two ways to provision one:

| | Endpoint | Who | Scope of clients returned |
|---|---|---|---|
| Self-service | `POST` / `GET` / `DELETE /service-clients` | Any authenticated user | Only clients the caller created, bound to their own account. Requested scopes may not end in `:manage` or equal `admin`. |
| Admin | `POST` / `GET` / `DELETE /admin/oauth2/service-clients` | Requires `oauth2:manage` permission (admin role) | All service clients platform-wide; can bind to any service account, including a newly-created one. |

**How the secret is stored — `GET` can never return it.** `POST` generates a random secret and returns it in the response body **exactly once**; only its Argon2 hash (`client_secret_hash`, same hashing as user account passwords) is written to the `oauth2_clients` table. The `GET` (list) endpoints query only `client_id, client_name, allowed_scopes, created_at` — the hash column isn't in the select list, so there's no code path where it could leak, regardless of caller. The hash itself is one-way: it can verify a secret presented at `POST /oauth2/token` (`client_credentials` grant), but the raw secret can't be recovered from it. If a secret is lost, the fix is to delete the client and create a new one — there is no "reveal" or "reset" endpoint.

---

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
- Docker & Docker Compose — on macOS, use **[Colima](https://github.com/abiosoft/colima)** (not Docker Desktop): `brew install colima docker docker-compose && colima start`

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
>   -f migrations/009_comad_product.sql \
>   -f migrations/010_plans.sql
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
psql "$DATABASE_URL" -f migrations/010_plans.sql

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
| `SMTP_NO_TLS` | `false` | Set `true` to use an unencrypted connection (e.g. for Mailpit) |
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

#### Local email testing with Mailpit

Real MailHog has no Apple Silicon build and is unmaintained upstream; local dev uses
[Mailpit](https://mailpit.axllent.org/) instead — a drop-in replacement with the same default
ports and API, run as a native launchd service (see `ullav-platform`'s README for install/setup;
already running if you used `scripts/start-all.sh`). SMTP on `1025`, web UI on `8025`.

Set in `.env`:

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
| `008_admin_user_permissions.sql` | Adds `users:read` and `users:write` permissions; grants them to `admin` role |
| `009_comad_product.sql` | Seeds the `comad` product |
| `010_plans.sql` | Adds `plans` table; seeds default plans for `clann` and `comad` |

In production, migrations are applied automatically by the `migrate` service on each deploy (idempotent — already-applied files are skipped). For local development without Docker, apply them manually with `psql` as shown above.
