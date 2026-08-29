use crate::{
    db,
    errors::AppError,
    middleware::auth::claims_from_req,
    models::{
        AssignProductRoleRequest, CreateTeamRequest, CreateTeamRoleRequest,
        InviteTeamMemberRequest, ResendInviteRequest, UpdateTeamRequest, UpdateTeamRoleRequest,
    },
    utils::{
        app_url::resolve_app_url,
        email::send_team_invitation_email,
        password::generate_secure_token,
    },
    AppState,
};
use actix_web::{delete, get, patch, post, web, HttpMessage, HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
use uuid::Uuid;

/// `GET /teams` — list teams the caller is an active member of.
#[get("/teams")]
pub async fn list_my_teams(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let teams = db::list_user_teams(&state.pool, user_id).await?;
    Ok(HttpResponse::Ok().json(teams))
}

/// `POST /teams` — create a team; caller becomes owner. Requires `teams:create` permission.
#[post("/teams")]
pub async fn create_team(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CreateTeamRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    if !claims.permissions.contains(&"teams:create".to_string()) {
        return Err(AppError::Forbidden);
    }
    let owner_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;

    if body.name.trim().is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }

    let team_id = db::create_team(
        &state.pool,
        body.name.trim(),
        body.description.as_deref(),
        body.purpose.as_deref(),
        body.avatar_url.as_deref(),
        owner_id,
        None,
    )
    .await?;

    let team = db::get_team_response(&state.pool, team_id).await?;
    Ok(HttpResponse::Created().json(team))
}

/// `GET /teams/by-slug/{slug}` — resolve a team slug to its id/name. Open to
/// any authenticated user (no membership check) — same tier as
/// `/users/resolve`: this is what lagan-server calls to translate
/// `{team-slug}/{repo-slug}` clone URLs, and exposes nothing beyond what a
/// team's own public slug/name already imply.
#[get("/teams/by-slug/{slug}")]
pub async fn get_team_by_slug(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    claims_from_req(&req)?;
    let team = db::get_team_by_slug(&state.pool, &path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(team))
}

/// `GET /teams/{id}/slug` — resolve a team id to its slug/name. Same auth
/// tier as `/teams/by-slug/{slug}` (any authenticated user, no membership
/// check) — the reverse lookup, used by lagan-server to backfill its local
/// slug cache for repos created before this field existed.
#[get("/teams/{id}/slug")]
pub async fn get_team_slug(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    claims_from_req(&req)?;
    let team = db::get_team_slug_by_id(&state.pool, path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(team))
}

#[derive(serde::Deserialize)]
pub struct SupportTeamQuery {
    /// Omit to resolve unambiguously across every organization — works only
    /// while at most one organization has a Support team flagged (today's
    /// reality, no app besides Tack has adopted organizations). Once a second
    /// organization gets its own Support team, an omitted `organization_id`
    /// returns 400 rather than guessing — see `db::SupportTeamLookup`.
    pub organization_id: Option<Uuid>,
}

/// `GET /teams/support` — resolve the team flagged as "the Support team" for
/// an organization. Same auth tier as `/teams/by-slug/{slug}` (any
/// authenticated user, no membership check) — downstream ticketing apps like
/// cunav need to resolve this without their service account being a member
/// of the team.
#[get("/teams/support")]
pub async fn get_support_team(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<SupportTeamQuery>,
) -> Result<HttpResponse, AppError> {
    claims_from_req(&req)?;
    match db::get_support_team(&state.pool, query.organization_id).await? {
        db::SupportTeamLookup::Found(team) => Ok(HttpResponse::Ok().json(team)),
        db::SupportTeamLookup::NotFound => Err(AppError::NotFound),
        db::SupportTeamLookup::Ambiguous => Err(AppError::Validation(
            "more than one organization has a Support team flagged; pass organization_id".into(),
        )),
    }
}

/// `GET /teams/{id}` — get team details; caller must be an active member.
#[get("/teams/{id}")]
pub async fn get_team(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let team_id = path.into_inner();

    require_active_member(&state, team_id, user_id).await?;

    let team = db::get_team_response(&state.pool, team_id).await?;
    Ok(HttpResponse::Ok().json(team))
}

/// `PATCH /teams/{id}` — update team details; owner or leader only.
/// Only the owner may change the leader.
#[patch("/teams/{id}")]
pub async fn update_team(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<UpdateTeamRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let team_id = path.into_inner();

    let (owner_id, leader_id) = db::get_team_ownership(&state.pool, team_id).await?;
    let is_owner = user_id == owner_id;
    let is_leader = user_id == leader_id;

    if !is_owner && !is_leader {
        return Err(AppError::Forbidden);
    }

    if body.leader_id.is_some() && !is_owner {
        return Err(AppError::Forbidden);
    }

    // Validate that the proposed new leader is an active member.
    if let Some(new_leader) = body.leader_id {
        match db::get_team_membership(&state.pool, team_id, new_leader).await? {
            Some(m) if m.status == "active" => {}
            _ => return Err(AppError::Validation("proposed leader is not an active team member".into())),
        }
    }

    db::update_team(
        &state.pool,
        team_id,
        body.name.as_deref(),
        body.slug.as_deref(),
        body.description.as_deref(),
        body.purpose.as_deref(),
        body.avatar_url.as_deref(),
        body.leader_id,
    )
    .await?;

    let team = db::get_team_response(&state.pool, team_id).await?;
    Ok(HttpResponse::Ok().json(team))
}

/// `DELETE /teams/{id}` — delete team; owner only.
#[delete("/teams/{id}")]
pub async fn delete_team(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let team_id = path.into_inner();

    let (owner_id, _) = db::get_team_ownership(&state.pool, team_id).await?;
    if user_id != owner_id {
        return Err(AppError::Forbidden);
    }

    db::delete_team(&state.pool, team_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /teams/{id}/invitations` — invite a user by email; owner or leader only.
#[post("/teams/{id}/invitations")]
pub async fn invite_member(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<InviteTeamMemberRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let inviter_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let team_id = path.into_inner();

    let (owner_id, leader_id) = db::get_team_ownership(&state.pool, team_id).await?;
    if inviter_id != owner_id && inviter_id != leader_id {
        return Err(AppError::Forbidden);
    }

    let base_url = resolve_app_url(
        body.app_url.as_deref(),
        &state.allowed_app_urls,
        &state.app_base_url,
    )?;

    let invitee = db::get_user_by_email(&state.pool, &body.email).await?;

    if db::get_team_membership(&state.pool, team_id, invitee.id).await?.is_some() {
        return Err(AppError::Conflict);
    }

    let token = generate_secure_token();
    let expires_at = Utc::now() + Duration::minutes(state.confirmation_token_ttl_minutes);

    db::invite_team_member(&state.pool, team_id, invitee.id, inviter_id, &token, expires_at).await?;

    let team = db::get_team_response(&state.pool, team_id).await?;

    if let Some(mailer) = &state.mailer {
        let inviter_username = db::get_user_by_id(&state.pool, inviter_id)
            .await
            .map(|u| u.username)
            .unwrap_or_else(|_| "A team member".into());

        if let Err(e) = send_team_invitation_email(
            mailer,
            &state.smtp_from,
            &invitee.email,
            &team.name,
            &inviter_username,
            &base_url,
            &token,
        )
        .await
        {
            log::error!("Failed to send team invitation email to {}: {}", invitee.email, e);
        }
    } else {
        log::info!(
            "Team invitation token for {} to join team {} — token: {}",
            invitee.email,
            team.name,
            token
        );
    }

    Ok(HttpResponse::Created().json(team))
}

/// `DELETE /teams/{id}/members/{user_id}` — remove a member.
/// Owner or leader can remove others; any active member may remove themselves.
/// The owner may not leave their own team.
#[delete("/teams/{id}/members/{user_id}")]
pub async fn remove_member(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let caller_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let (team_id, target_user_id) = path.into_inner();

    let (owner_id, leader_id) = db::get_team_ownership(&state.pool, team_id).await?;

    let is_self = caller_id == target_user_id;
    let is_owner = caller_id == owner_id;
    let is_leader = caller_id == leader_id;

    if !is_self && !is_owner && !is_leader {
        return Err(AppError::Forbidden);
    }

    // The owner may not be removed — they must transfer ownership or delete the team.
    if target_user_id == owner_id {
        return Err(AppError::Validation(
            "the team owner cannot be removed; transfer ownership or delete the team".into(),
        ));
    }

    db::remove_team_member(&state.pool, team_id, target_user_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /teams/invitations/{token}/accept` — accept a team invitation.
#[post("/teams/invitations/{token}/accept")]
pub async fn accept_invitation(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let caller_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let token = path.into_inner();

    let member = db::get_team_member_by_token(&state.pool, &token).await?;

    if member.user_id != caller_id {
        return Err(AppError::Forbidden);
    }
    if let Some(expires_at) = member.invite_token_expires_at {
        if expires_at < Utc::now() {
            return Err(AppError::InvalidToken);
        }
    }

    db::accept_team_invitation(&state.pool, member.id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /teams/invitations/{token}/decline` — decline a team invitation.
#[post("/teams/invitations/{token}/decline")]
pub async fn decline_invitation(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let caller_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let token = path.into_inner();

    let member = db::get_team_member_by_token(&state.pool, &token).await?;

    if member.user_id != caller_id {
        return Err(AppError::Forbidden);
    }

    db::decline_team_invitation(&state.pool, member.id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /teams/{id}/members/{user_id}/resend-invite` — resend invitation email; owner or leader only.
#[post("/teams/{id}/members/{user_id}/resend-invite")]
pub async fn resend_invitation(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, Uuid)>,
    body: web::Json<ResendInviteRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let caller_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let (team_id, invitee_id) = path.into_inner();

    let (owner_id, leader_id) = db::get_team_ownership(&state.pool, team_id).await?;
    if caller_id != owner_id && caller_id != leader_id {
        return Err(AppError::Forbidden);
    }

    let membership = db::get_team_membership(&state.pool, team_id, invitee_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if membership.status != "invited" {
        return Err(AppError::Validation("member is not in invited status".into()));
    }

    let base_url = resolve_app_url(
        body.app_url.as_deref(),
        &state.allowed_app_urls,
        &state.app_base_url,
    )?;

    let new_token = generate_secure_token();
    let new_expires_at = Utc::now() + Duration::minutes(state.confirmation_token_ttl_minutes);

    db::refresh_invite_token(&state.pool, team_id, invitee_id, &new_token, new_expires_at).await?;

    let team = db::get_team_response(&state.pool, team_id).await?;
    let invitee = db::get_user_by_id(&state.pool, invitee_id).await?;

    if let Some(mailer) = &state.mailer {
        let inviter_username = db::get_user_by_id(&state.pool, caller_id)
            .await
            .map(|u| u.username)
            .unwrap_or_else(|_| "A team member".into());

        if let Err(e) = send_team_invitation_email(
            mailer,
            &state.smtp_from,
            &invitee.email,
            &team.name,
            &inviter_username,
            &base_url,
            &new_token,
        )
        .await
        {
            log::error!("Failed to resend team invitation email to {}: {}", invitee.email, e);
        }
    } else {
        log::info!(
            "Resent team invitation token for {} to join team {} — token: {}",
            invitee.email,
            team.name,
            new_token
        );
    }

    Ok(HttpResponse::NoContent().finish())
}

// ── Team roles ────────────────────────────────────────────────────────────────

/// `GET /teams/{id}/roles` — list all roles defined for the team; any active member.
#[get("/teams/{id}/roles")]
pub async fn list_team_roles(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let team_id = path.into_inner();
    require_active_member(&state, team_id, user_id).await?;
    let roles = db::list_team_roles(&state.pool, team_id).await?;
    Ok(HttpResponse::Ok().json(roles))
}

/// `POST /teams/{id}/roles` — create a role for the team; owner only.
#[post("/teams/{id}/roles")]
pub async fn create_team_role(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<CreateTeamRoleRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let team_id = path.into_inner();

    let (owner_id, _) = db::get_team_ownership(&state.pool, team_id).await?;
    if user_id != owner_id {
        return Err(AppError::Forbidden);
    }

    if body.name.trim().is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }

    let role = db::create_team_role(
        &state.pool,
        team_id,
        body.name.trim(),
        body.description.as_deref(),
    )
    .await?;
    Ok(HttpResponse::Created().json(role))
}

/// `PATCH /teams/{id}/roles/{role_id}` — update a role's name or description; owner only.
#[patch("/teams/{id}/roles/{role_id}")]
pub async fn update_team_role(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, Uuid)>,
    body: web::Json<UpdateTeamRoleRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let (team_id, role_id) = path.into_inner();

    let (owner_id, _) = db::get_team_ownership(&state.pool, team_id).await?;
    if user_id != owner_id {
        return Err(AppError::Forbidden);
    }

    if let Some(ref name) = body.name {
        if name.trim().is_empty() {
            return Err(AppError::Validation("name must not be empty".into()));
        }
    }

    let role = db::update_team_role(
        &state.pool,
        team_id,
        role_id,
        body.name.as_deref().map(str::trim),
        body.description.as_deref(),
    )
    .await?;
    Ok(HttpResponse::Ok().json(role))
}

/// `DELETE /teams/{id}/roles/{role_id}` — delete a role; owner only.
/// Cascades to remove all member assignments for that role.
#[delete("/teams/{id}/roles/{role_id}")]
pub async fn delete_team_role(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let (team_id, role_id) = path.into_inner();

    let (owner_id, _) = db::get_team_ownership(&state.pool, team_id).await?;
    if user_id != owner_id {
        return Err(AppError::Forbidden);
    }

    db::delete_team_role(&state.pool, team_id, role_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /teams/{id}/members/{user_id}/roles/{role_id}` — assign a role to a member;
/// owner or leader only. The target must be an active member of the team.
#[post("/teams/{id}/members/{user_id}/roles/{role_id}")]
pub async fn assign_member_role(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, Uuid, Uuid)>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let caller_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let (team_id, target_user_id, role_id) = path.into_inner();

    let (owner_id, leader_id) = db::get_team_ownership(&state.pool, team_id).await?;
    if caller_id != owner_id && caller_id != leader_id {
        return Err(AppError::Forbidden);
    }

    db::assign_member_role(&state.pool, team_id, target_user_id, role_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `DELETE /teams/{id}/members/{user_id}/roles/{role_id}` — remove a role from a member;
/// owner or leader only.
#[delete("/teams/{id}/members/{user_id}/roles/{role_id}")]
pub async fn unassign_member_role(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, Uuid, Uuid)>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let caller_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let (team_id, target_user_id, role_id) = path.into_inner();

    let (owner_id, leader_id) = db::get_team_ownership(&state.pool, team_id).await?;
    if caller_id != owner_id && caller_id != leader_id {
        return Err(AppError::Forbidden);
    }

    db::unassign_member_role(&state.pool, team_id, target_user_id, role_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

// ── Team product roles ────────────────────────────────────────────────────────

/// `POST /teams/{id}/members/{user_id}/product-roles/{slug}` — assign or update a product role.
/// Owner only; the user must already be an active member and the team must have the product enabled.
#[post("/teams/{id}/members/{user_id}/product-roles/{slug}")]
pub async fn assign_member_product_role(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, Uuid, String)>,
    body: web::Json<AssignProductRoleRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let caller_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let (team_id, target_user_id, product_slug) = path.into_inner();

    let (owner_id, _) = db::get_team_ownership(&state.pool, team_id).await?;
    if caller_id != owner_id {
        return Err(AppError::Forbidden);
    }

    validate_product_role(&product_slug, &body.role)?;
    db::assign_member_product_role(
        &state.pool, team_id, target_user_id, &product_slug, &body.role, caller_id,
    ).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `DELETE /teams/{id}/members/{user_id}/product-roles/{slug}` — revoke a product role.
/// Owner only.
#[delete("/teams/{id}/members/{user_id}/product-roles/{slug}")]
pub async fn revoke_member_product_role(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, Uuid, String)>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let caller_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let (team_id, target_user_id, product_slug) = path.into_inner();

    let (owner_id, _) = db::get_team_ownership(&state.pool, team_id).await?;
    if caller_id != owner_id {
        return Err(AppError::Forbidden);
    }

    db::revoke_member_product_role(&state.pool, team_id, target_user_id, &product_slug).await?;
    Ok(HttpResponse::NoContent().finish())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Validate that `role` is a known value for the given product.
/// Obair: "admin" | "lead" | "member". Other products: non-empty string.
fn validate_product_role(product_slug: &str, role: &str) -> Result<(), AppError> {
    match product_slug {
        "obair" => {
            if !matches!(role, "admin" | "lead" | "member") {
                return Err(AppError::Validation(format!(
                    "invalid obair role '{}': must be admin, lead, or member", role
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

async fn require_active_member(
    state: &AppState,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    match db::get_team_membership(&state.pool, team_id, user_id).await? {
        Some(m) if m.status == "active" => Ok(()),
        Some(_) => Err(AppError::Forbidden),
        None => Err(AppError::Forbidden),
    }
}
