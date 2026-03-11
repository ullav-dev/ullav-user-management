//! Startup seed: ensure the initial admin user exists.
//!
//! Reads `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `ADMIN_EMAIL` from the
//! environment (defaults: "theboss", "changeme", "admin@localhost").
//! Idempotent — skips silently if the username or email is already taken.

use crate::errors::AppError;
use crate::utils::password::hash_password;
use deadpool_postgres::Pool;
use uuid::Uuid;

pub async fn seed_admin(
    pool: &Pool,
    username: &str,
    email: &str,
    password: &str,
) -> Result<(), AppError> {
    let hash = hash_password(password)?;
    let client = pool.get().await?;

    // Insert admin user as already-active, skip if username/email already taken.
    let rows = client
        .query(
            "INSERT INTO users (email, username, password_hash, is_active)
             VALUES ($1, $2, $3, TRUE)
             ON CONFLICT DO NOTHING
             RETURNING id",
            &[&email, &username, &hash],
        )
        .await?;

    if rows.is_empty() {
        log::info!("Admin user '{}' already exists — skipping seed", username);
        return Ok(());
    }

    let user_id: Uuid = rows[0].get("id");

    // Assign the admin role (grants health:read and users:change_any_password).
    client
        .execute(
            "INSERT INTO user_roles (user_id, role_id)
             SELECT $1, id FROM roles WHERE name = 'admin'
             ON CONFLICT DO NOTHING",
            &[&user_id],
        )
        .await?;

    log::info!(
        "Admin user '{}' <{}> seeded and assigned admin role",
        username,
        email
    );
    Ok(())
}
