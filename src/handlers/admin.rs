use crate::{
    db,
    errors::AppError,
    models::{
        AdminAddTeamMemberRequest, AdminCreateSubscriptionRequest, AdminCreateTeamRequest,
        AdminUpdateSubscriptionRequest, AdminUpdateTeamRequest, AdminUpdateUserRequest,
        AssignProductRoleRequest, CreatePermissionRequest, CreatePlanRequest, CreateRoleRequest,
    },
    AppState,
};
use actix_web::{delete, get, patch, post, web, HttpRequest, HttpResponse};
use crate::middleware::auth::claims_from_req;
use serde::Deserialize;
use uuid::Uuid;

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct UsersQuery {
    #[serde(default = "one")]
    pub page: i64,
    #[serde(default = "twenty")]
    pub page_size: i64,
    #[serde(default)]
    pub search: String,
    #[serde(default = "default_sort_by")]
    pub sort_by: String,
    #[serde(default = "default_sort_dir")]
    pub sort_dir: String,
}

fn default_sort_by() -> String { "created_at".to_string() }
fn default_sort_dir() -> String { "desc".to_string() }

#[derive(Debug, Deserialize)]
pub struct SubscriptionsQuery {
    #[serde(default = "one")]
    pub page: i64,
    #[serde(default = "twenty")]
    pub page_size: i64,
    #[serde(default)]
    pub search: String,
    #[serde(default)]
    pub product: String,
}

#[derive(Debug, Deserialize)]
pub struct PlansQuery {
    #[serde(default)]
    pub product: String,
}

fn one() -> i64 { 1 }
fn twenty() -> i64 { 20 }

// ── Users ─────────────────────────────────────────────────────────────────────

/// `GET /admin/users` — paginated list of all users.
#[get("/users")]
pub async fn list_users(
    state: web::Data<AppState>,
    query: web::Query<UsersQuery>,
) -> Result<HttpResponse, AppError> {
    let page = query.page.max(1);
    let page_size = query.page_size.clamp(1, 100);
    let result = db::list_users_paginated(&state.pool, page, page_size, &query.search, &query.sort_by, &query.sort_dir).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /admin/users/{id}` — single user with roles.
#[get("/users/{id}")]
pub async fn get_user(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let user = db::get_user_with_roles(&state.pool, *path).await?;
    Ok(HttpResponse::Ok().json(user))
}

/// `PATCH /admin/users/{id}` — partial update of a user's profile.
#[patch("/users/{id}")]
pub async fn update_user(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    body: web::Json<AdminUpdateUserRequest>,
) -> Result<HttpResponse, AppError> {
    let user = db::admin_update_user(
        &state.pool,
        *path,
        body.email.as_deref(),
        body.username.as_deref(),
        body.is_active,
        body.first_name.as_ref().map(|o| o.as_deref()),
        body.last_name.as_ref().map(|o| o.as_deref()),
        body.avatar_url.as_ref().map(|o| o.as_deref()),
    )
    .await?;
    Ok(HttpResponse::Ok().json(user))
}

/// `DELETE /admin/users/{id}` — delete a user.
#[delete("/users/{id}")]
pub async fn delete_user(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    db::admin_delete_user(&state.pool, *path).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /admin/users/{id}/roles/{role}` — assign a role to a user.
#[post("/users/{id}/roles/{role}")]
pub async fn add_user_role(
    state: web::Data<AppState>,
    path: web::Path<(Uuid, String)>,
) -> Result<HttpResponse, AppError> {
    let (user_id, role_name) = path.into_inner();
    db::assign_role(&state.pool, user_id, &role_name).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `DELETE /admin/users/{id}/roles/{role}` — remove a role from a user.
#[delete("/users/{id}/roles/{role}")]
pub async fn remove_user_role(
    state: web::Data<AppState>,
    path: web::Path<(Uuid, String)>,
) -> Result<HttpResponse, AppError> {
    let (user_id, role_name) = path.into_inner();
    db::remove_role(&state.pool, user_id, &role_name).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `GET /admin/users/{id}/subscriptions` — list all subscriptions for a user.
#[get("/users/{id}/subscriptions")]
pub async fn list_user_subscriptions(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let subs = db::admin_list_user_subscriptions(&state.pool, *path).await?;
    Ok(HttpResponse::Ok().json(subs))
}

/// `GET /admin/users/{id}/teams` — list teams a user belongs to, with enabled products.
#[get("/users/{id}/teams")]
pub async fn list_user_teams(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let teams = db::admin_list_user_teams(&state.pool, *path).await?;
    Ok(HttpResponse::Ok().json(teams))
}

/// `POST /admin/users/{id}/subscriptions` — create a subscription for a user.
#[post("/users/{id}/subscriptions")]
pub async fn create_user_subscription(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    body: web::Json<AdminCreateSubscriptionRequest>,
) -> Result<HttpResponse, AppError> {
    let sub = db::admin_create_subscription(
        &state.pool,
        *path,
        &body.product_slug,
        &body.plan,
        &body.status,
        body.seat_count,
    )
    .await?;
    Ok(HttpResponse::Created().json(sub))
}

// ── Roles & permissions ───────────────────────────────────────────────────────

/// `GET /admin/roles` — list all roles with their permissions.
#[get("/roles")]
pub async fn list_roles(
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let roles = db::list_roles_with_permissions(&state.pool).await?;
    Ok(HttpResponse::Ok().json(roles))
}

/// `POST /admin/roles` — create a new role.
#[post("/roles")]
pub async fn create_role(
    state: web::Data<AppState>,
    body: web::Json<CreateRoleRequest>,
) -> Result<HttpResponse, AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("role name must not be empty".into()));
    }
    db::create_role(&state.pool, body.name.trim()).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `DELETE /admin/roles/{name}` — delete a role.
#[delete("/roles/{name}")]
pub async fn delete_role(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    db::delete_role(&state.pool, &path).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `GET /admin/permissions` — list all permissions.
#[get("/permissions")]
pub async fn list_permissions(
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let perms = db::list_all_permissions(&state.pool).await?;
    Ok(HttpResponse::Ok().json(perms))
}

/// `POST /admin/permissions` — create a new permission.
#[post("/permissions")]
pub async fn create_permission(
    state: web::Data<AppState>,
    body: web::Json<CreatePermissionRequest>,
) -> Result<HttpResponse, AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("permission name must not be empty".into()));
    }
    db::create_permission(&state.pool, body.name.trim()).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /admin/roles/{name}/permissions/{permission}` — grant a permission to a role.
#[post("/roles/{name}/permissions/{permission}")]
pub async fn add_role_permission(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, AppError> {
    let (role, permission) = path.into_inner();
    db::add_permission_to_role(&state.pool, &role, &permission).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `DELETE /admin/roles/{name}/permissions/{permission}` — revoke a permission from a role.
#[delete("/roles/{name}/permissions/{permission}")]
pub async fn remove_role_permission(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, AppError> {
    let (role, permission) = path.into_inner();
    db::remove_permission_from_role(&state.pool, &role, &permission).await?;
    Ok(HttpResponse::NoContent().finish())
}

// ── Subscriptions ─────────────────────────────────────────────────────────────

/// `GET /admin/subscriptions` — paginated list of all subscriptions.
#[get("/subscriptions")]
pub async fn list_subscriptions(
    state: web::Data<AppState>,
    query: web::Query<SubscriptionsQuery>,
) -> Result<HttpResponse, AppError> {
    let page = query.page.max(1);
    let page_size = query.page_size.clamp(1, 100);
    let result = db::list_subscriptions_paginated(
        &state.pool, page, page_size, &query.search, &query.product,
    )
    .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `PATCH /admin/subscriptions/{id}` — partial update of a subscription.
#[patch("/subscriptions/{id}")]
pub async fn update_subscription(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    body: web::Json<AdminUpdateSubscriptionRequest>,
) -> Result<HttpResponse, AppError> {
    let sub = db::admin_update_subscription(
        &state.pool,
        *path,
        body.plan.as_deref(),
        body.status.as_deref(),
        body.seat_count,
    )
    .await?;
    Ok(HttpResponse::Ok().json(sub))
}

/// `DELETE /admin/subscriptions/{id}` — delete a subscription.
#[delete("/subscriptions/{id}")]
pub async fn delete_subscription(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    db::admin_delete_subscription(&state.pool, *path).await?;
    Ok(HttpResponse::NoContent().finish())
}

// ── Products ──────────────────────────────────────────────────────────────────

/// `GET /admin/products` — list all registered products.
#[get("/products")]
pub async fn list_products(
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let products = db::list_products(&state.pool).await?;
    Ok(HttpResponse::Ok().json(products))
}

// ── Plans ─────────────────────────────────────────────────────────────────────

/// `GET /admin/plans?product=<slug>` — list plans, optionally filtered by product slug.
#[get("/plans")]
pub async fn list_plans(
    state: web::Data<AppState>,
    query: web::Query<PlansQuery>,
) -> Result<HttpResponse, AppError> {
    let plans = db::list_plans(&state.pool, &query.product).await?;
    Ok(HttpResponse::Ok().json(plans))
}

/// `POST /admin/plans` — create a new plan for a product.
#[post("/plans")]
pub async fn create_plan(
    state: web::Data<AppState>,
    body: web::Json<CreatePlanRequest>,
) -> Result<HttpResponse, AppError> {
    if body.slug.trim().is_empty() {
        return Err(AppError::Validation("plan slug must not be empty".into()));
    }
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("plan name must not be empty".into()));
    }
    let plan = db::create_plan(&state.pool, &body.product_slug, body.slug.trim(), body.name.trim()).await?;
    Ok(HttpResponse::Created().json(plan))
}

/// `DELETE /admin/plans/{id}` — delete a plan by ID.
#[delete("/plans/{id}")]
pub async fn delete_plan(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    db::delete_plan(&state.pool, *path).await?;
    Ok(HttpResponse::NoContent().finish())
}

// ── Admin: Teams ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TeamsQuery {
    #[serde(default = "one")]
    pub page: i64,
    #[serde(default = "twenty")]
    pub page_size: i64,
    #[serde(default)]
    pub search: String,
}

/// `GET /admin/teams` — paginated list of all teams.
#[get("/teams")]
pub async fn list_teams(
    state: web::Data<AppState>,
    query: web::Query<TeamsQuery>,
) -> Result<HttpResponse, AppError> {
    let page = db::list_teams_paginated(&state.pool, query.page, query.page_size, &query.search).await?;
    Ok(HttpResponse::Ok().json(page))
}

/// `POST /admin/teams` — create a team with an explicit owner.
#[post("/teams")]
pub async fn create_team(
    state: web::Data<AppState>,
    body: web::Json<AdminCreateTeamRequest>,
) -> Result<HttpResponse, AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    let team_id = db::create_team(
        &state.pool,
        body.name.trim(),
        body.description.as_deref(),
        body.purpose.as_deref(),
        body.avatar_url.as_deref(),
        body.owner_id,
    )
    .await?;
    let team = db::get_team_response(&state.pool, team_id).await?;
    Ok(HttpResponse::Created().json(team))
}

/// `GET /admin/teams/{id}` — full team detail including all members.
#[get("/teams/{id}")]
pub async fn get_team(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let team = db::get_team_response(&state.pool, *path).await?;
    Ok(HttpResponse::Ok().json(team))
}

/// `PATCH /admin/teams/{id}` — update any team field, including owner.
#[patch("/teams/{id}")]
pub async fn update_team(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    body: web::Json<AdminUpdateTeamRequest>,
) -> Result<HttpResponse, AppError> {
    db::admin_update_team(
        &state.pool,
        *path,
        body.name.as_deref(),
        body.description.as_deref(),
        body.purpose.as_deref(),
        body.avatar_url.as_deref(),
        body.owner_id,
        body.leader_id,
    )
    .await?;
    let team = db::get_team_response(&state.pool, *path).await?;
    Ok(HttpResponse::Ok().json(team))
}

/// `DELETE /admin/teams/{id}` — delete a team and all its memberships.
#[delete("/teams/{id}")]
pub async fn delete_team(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    db::delete_team(&state.pool, *path).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /admin/teams/{id}/members` — directly add an active member (bypasses invite).
#[post("/teams/{id}/members")]
pub async fn add_team_member(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    body: web::Json<AdminAddTeamMemberRequest>,
) -> Result<HttpResponse, AppError> {
    let team_id = path.into_inner();
    // Verify the team exists before trying to add a member.
    db::get_team_ownership(&state.pool, team_id).await?;
    db::add_team_member_active(&state.pool, team_id, body.user_id, body.user_id).await?;
    let team = db::get_team_response(&state.pool, team_id).await?;
    Ok(HttpResponse::Created().json(team))
}

/// `DELETE /admin/teams/{id}/members/{user_id}` — remove a member from a team.
#[delete("/teams/{id}/members/{user_id}")]
pub async fn remove_team_member(
    state: web::Data<AppState>,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse, AppError> {
    let (team_id, user_id) = path.into_inner();
    db::remove_team_member(&state.pool, team_id, user_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

// ── Admin: Team product access ────────────────────────────────────────────────

/// Validate that `role` is a known value for the given product.
/// Obair: "admin" | "lead" | "member". Other products: non-empty string.
fn validate_product_role(product_slug: &str, role: &str) -> Result<(), AppError> {
    match product_slug {
        "obair" | "togra" => {
            if !matches!(role, "admin" | "lead" | "member") {
                return Err(AppError::Validation(format!(
                    "invalid {} role '{}': must be admin, lead, or member", product_slug, role
                )));
            }
        }
        _ => {
            if role.trim().is_empty() {
                return Err(AppError::Validation("role must not be empty".into()));
            }
        }
    }
    Ok(())
}

/// `GET /admin/teams/{id}/products` — list products enabled for the team.
#[get("/teams/{id}/products")]
pub async fn list_team_products(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let products = db::list_team_products(&state.pool, *path).await?;
    Ok(HttpResponse::Ok().json(products))
}

/// `POST /admin/teams/{id}/products/{slug}` — enable a product for a team.
/// Requires `obair:manage` or `togra:manage` (in addition to the scope-level `users:read` gate).
/// This is a contract-level operation — only platform admins may grant product access.
#[post("/teams/{id}/products/{slug}")]
pub async fn enable_team_product(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, String)>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let has_manage = claims.permissions.contains(&"obair:manage".to_string())
        || claims.permissions.contains(&"togra:manage".to_string());
    if !has_manage {
        return Err(AppError::Forbidden);
    }
    let admin_id = uuid::Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let (team_id, product_slug) = path.into_inner();
    db::enable_team_product(&state.pool, team_id, &product_slug, admin_id).await?;
    let products = db::list_team_products(&state.pool, team_id).await?;
    Ok(HttpResponse::Ok().json(products))
}

/// `DELETE /admin/teams/{id}/products/{slug}` — disable a product for a team.
/// Requires `obair:manage` or `togra:manage`. Cascades: all member product roles are revoked automatically.
#[delete("/teams/{id}/products/{slug}")]
pub async fn disable_team_product(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, String)>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let has_manage = claims.permissions.contains(&"obair:manage".to_string())
        || claims.permissions.contains(&"togra:manage".to_string());
    if !has_manage {
        return Err(AppError::Forbidden);
    }
    let (team_id, product_slug) = path.into_inner();
    db::disable_team_product(&state.pool, team_id, &product_slug).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /admin/teams/{id}/members/{user_id}/product-roles/{slug}` — assign or update a product role.
#[post("/teams/{id}/members/{user_id}/product-roles/{slug}")]
pub async fn assign_member_product_role(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, Uuid, String)>,
    body: web::Json<AssignProductRoleRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let admin_id = uuid::Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let (team_id, user_id, product_slug) = path.into_inner();
    validate_product_role(&product_slug, &body.role)?;
    db::assign_member_product_role(&state.pool, team_id, user_id, &product_slug, &body.role, admin_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `DELETE /admin/teams/{id}/members/{user_id}/product-roles/{slug}` — revoke a product role.
#[delete("/teams/{id}/members/{user_id}/product-roles/{slug}")]
pub async fn revoke_member_product_role(
    state: web::Data<AppState>,
    path: web::Path<(Uuid, Uuid, String)>,
) -> Result<HttpResponse, AppError> {
    let (team_id, user_id, product_slug) = path.into_inner();
    db::revoke_member_product_role(&state.pool, team_id, user_id, &product_slug).await?;
    Ok(HttpResponse::NoContent().finish())
}
