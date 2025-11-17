use axum::{
    extract::{Path, State},
    Extension, Json,
};
use infera_management_core::{
    entities::{Organization, OrganizationMember, OrganizationRole, OrganizationTier},
    error::Error as CoreError,
    IdGenerator, OrganizationMemberRepository, OrganizationRepository, UserEmailRepository,
};
use serde::{Deserialize, Serialize};

use crate::handlers::auth::{AppState, Result};
use crate::middleware::SessionContext;

/// Global limit on total organizations
const GLOBAL_ORGANIZATION_LIMIT: i64 = 100_000;

/// Per-user limit on organizations
const PER_USER_ORGANIZATION_LIMIT: i64 = 10;

/// Organization response
#[derive(Debug, Serialize, Deserialize)]
pub struct OrganizationResponse {
    /// Organization ID
    pub id: i64,
    /// Organization name
    pub name: String,
    /// Organization tier
    pub tier: String,
    /// When the organization was created
    pub created_at: String,
    /// Your role in the organization
    pub role: String,
}

/// Request body for creating an organization
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateOrganizationRequest {
    /// Organization name
    pub name: String,
}

/// Response body for organization creation
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateOrganizationResponse {
    /// Created organization
    pub organization: OrganizationResponse,
}

/// Create a new organization
///
/// POST /v1/organizations
///
/// Creates a new organization with the authenticated user as owner.
/// Requires verified email and enforces per-user and global limits.
pub async fn create_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Json(payload): Json<CreateOrganizationRequest>,
) -> Result<Json<CreateOrganizationResponse>> {
    // Validate organization name
    Organization::validate_name(&payload.name)?;

    // Check if user has a verified email
    let email_repo = UserEmailRepository::new((*state.storage).clone());
    let user_emails = email_repo.get_user_emails(ctx.user_id).await?;
    let has_verified_email = user_emails.iter().any(|e| e.verified_at.is_some());

    if !has_verified_email {
        return Err(CoreError::Validation(
            "You must verify your email before creating an organization".to_string(),
        )
        .into());
    }

    // Check per-user organization limit
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    let user_org_count = member_repo.get_user_organization_count(ctx.user_id).await?;

    if user_org_count >= PER_USER_ORGANIZATION_LIMIT {
        return Err(CoreError::TierLimit(format!(
            "You have reached the maximum number of organizations ({})",
            PER_USER_ORGANIZATION_LIMIT
        ))
        .into());
    }

    // Check global organization limit
    let org_repo = OrganizationRepository::new((*state.storage).clone());
    let total_org_count = org_repo.get_total_count().await?;

    if total_org_count >= GLOBAL_ORGANIZATION_LIMIT {
        return Err(CoreError::TierLimit(
            "Global organization limit reached. Please contact support.".to_string(),
        )
        .into());
    }

    // Generate IDs
    let org_id = IdGenerator::next_id();
    let member_id = IdGenerator::next_id();

    // Create organization with TIER_DEV_V1
    let organization = Organization::new(org_id, payload.name, OrganizationTier::TierDevV1)?;

    // Create organization
    org_repo.create(organization.clone()).await?;

    // Create organization member (owner role)
    let member = OrganizationMember::new(member_id, org_id, ctx.user_id, OrganizationRole::Owner);

    // Create member
    member_repo.create(member).await?;

    Ok(Json(CreateOrganizationResponse {
        organization: OrganizationResponse {
            id: organization.id,
            name: organization.name,
            tier: tier_to_string(&organization.tier),
            created_at: organization.created_at.to_rfc3339(),
            role: role_to_string(&OrganizationRole::Owner),
        },
    }))
}

/// Convert OrganizationTier to string
fn tier_to_string(tier: &OrganizationTier) -> String {
    match tier {
        OrganizationTier::TierDevV1 => "TIER_DEV_V1".to_string(),
        OrganizationTier::TierProV1 => "TIER_PRO_V1".to_string(),
        OrganizationTier::TierMaxV1 => "TIER_MAX_V1".to_string(),
    }
}

/// Convert OrganizationRole to string
fn role_to_string(role: &OrganizationRole) -> String {
    match role {
        OrganizationRole::Member => "MEMBER".to_string(),
        OrganizationRole::Admin => "ADMIN".to_string(),
        OrganizationRole::Owner => "OWNER".to_string(),
    }
}

/// Response body for listing organizations
#[derive(Debug, Serialize, Deserialize)]
pub struct ListOrganizationsResponse {
    /// List of organizations the user is a member of
    pub organizations: Vec<OrganizationResponse>,
}

/// List organizations
///
/// GET /v1/organizations
///
/// Returns all organizations the authenticated user is a member of.
pub async fn list_organizations(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<Json<ListOrganizationsResponse>> {
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    let org_repo = OrganizationRepository::new((*state.storage).clone());

    // Get all memberships for the user
    let memberships = member_repo.get_by_user(ctx.user_id).await?;

    // Fetch organization details for each membership
    let mut organizations = Vec::new();
    for member in memberships {
        if let Some(org) = org_repo.get(member.organization_id).await? {
            // Skip deleted organizations
            if org.is_deleted() {
                continue;
            }

            organizations.push(OrganizationResponse {
                id: org.id,
                name: org.name,
                tier: tier_to_string(&org.tier),
                created_at: org.created_at.to_rfc3339(),
                role: role_to_string(&member.role),
            });
        }
    }

    Ok(Json(ListOrganizationsResponse { organizations }))
}

/// Response body for getting organization details
#[derive(Debug, Serialize, Deserialize)]
pub struct GetOrganizationResponse {
    /// Organization details
    pub organization: OrganizationResponse,
}

/// Get organization details
///
/// GET /v1/organizations/:org
///
/// Returns details of a specific organization. User must be a member.
pub async fn get_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(org_id): Path<i64>,
) -> Result<Json<GetOrganizationResponse>> {
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    let org_repo = OrganizationRepository::new((*state.storage).clone());

    // Check if user is a member
    let member = member_repo
        .get_by_org_and_user(org_id, ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::Authz("You are not a member of this organization".to_string()))?;

    // Get organization
    let org = org_repo
        .get(org_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    // Check if deleted
    if org.is_deleted() {
        return Err(CoreError::NotFound("Organization not found".to_string()).into());
    }

    Ok(Json(GetOrganizationResponse {
        organization: OrganizationResponse {
            id: org.id,
            name: org.name,
            tier: tier_to_string(&org.tier),
            created_at: org.created_at.to_rfc3339(),
            role: role_to_string(&member.role),
        },
    }))
}

/// Request body for updating an organization
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateOrganizationRequest {
    /// Updated organization name
    pub name: String,
}

/// Response body for organization update
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateOrganizationResponse {
    /// Updated organization
    pub organization: OrganizationResponse,
}

/// Update organization
///
/// PATCH /v1/organizations/:org
///
/// Updates organization details. Requires admin or owner role.
pub async fn update_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(org_id): Path<i64>,
    Json(payload): Json<UpdateOrganizationRequest>,
) -> Result<Json<UpdateOrganizationResponse>> {
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    let org_repo = OrganizationRepository::new((*state.storage).clone());

    // Check if user is a member with admin or owner role
    let member = member_repo
        .get_by_org_and_user(org_id, ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::Authz("You are not a member of this organization".to_string()))?;

    // Check if user has admin permission
    if !member.role.has_permission(OrganizationRole::Admin) {
        return Err(CoreError::Authz(
            "You must be an admin or owner to update this organization".to_string(),
        )
        .into());
    }

    // Get organization
    let mut org = org_repo
        .get(org_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    // Check if deleted
    if org.is_deleted() {
        return Err(CoreError::NotFound("Organization not found".to_string()).into());
    }

    // Update name
    org.set_name(payload.name)?;
    org_repo.update(org.clone()).await?;

    Ok(Json(UpdateOrganizationResponse {
        organization: OrganizationResponse {
            id: org.id,
            name: org.name,
            tier: tier_to_string(&org.tier),
            created_at: org.created_at.to_rfc3339(),
            role: role_to_string(&member.role),
        },
    }))
}

/// Response body for organization deletion
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteOrganizationResponse {
    /// Confirmation message
    pub message: String,
}

/// Delete organization
///
/// DELETE /v1/organizations/:org
///
/// Soft-deletes an organization. Requires owner role.
pub async fn delete_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(org_id): Path<i64>,
) -> Result<Json<DeleteOrganizationResponse>> {
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    let org_repo = OrganizationRepository::new((*state.storage).clone());

    // Check if user is a member with owner role
    let member = member_repo
        .get_by_org_and_user(org_id, ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::Authz("You are not a member of this organization".to_string()))?;

    // Check if user has owner permission
    if !member.role.has_permission(OrganizationRole::Owner) {
        return Err(CoreError::Authz(
            "You must be an owner to delete this organization".to_string(),
        )
        .into());
    }

    // Soft delete organization
    org_repo.delete(org_id).await?;

    Ok(Json(DeleteOrganizationResponse {
        message: "Organization deleted successfully".to_string(),
    }))
}

// ============================================================================
// Organization Member Management
// ============================================================================

/// Organization member response
#[derive(Debug, Serialize, Deserialize)]
pub struct OrganizationMemberResponse {
    /// Member ID
    pub id: i64,
    /// User ID
    pub user_id: i64,
    /// Member role
    pub role: String,
    /// When the member joined
    pub joined_at: String,
}

/// Response body for listing organization members
#[derive(Debug, Serialize, Deserialize)]
pub struct ListMembersResponse {
    /// List of organization members
    pub members: Vec<OrganizationMemberResponse>,
}

/// List organization members
///
/// GET /v1/organizations/:org/members
///
/// Returns all members of an organization. User must be a member.
pub async fn list_members(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(org_id): Path<i64>,
) -> Result<Json<ListMembersResponse>> {
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());

    // Check if user is a member
    let _user_member = member_repo
        .get_by_org_and_user(org_id, ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::Authz("You are not a member of this organization".to_string()))?;

    // Get all members
    let members = member_repo.get_by_organization(org_id).await?;

    let member_responses: Vec<OrganizationMemberResponse> = members
        .into_iter()
        .map(|m| OrganizationMemberResponse {
            id: m.id,
            user_id: m.user_id,
            role: role_to_string(&m.role),
            joined_at: m.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(ListMembersResponse {
        members: member_responses,
    }))
}

/// Request body for updating a member's role
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateMemberRoleRequest {
    /// New role for the member
    pub role: String,
}

/// Response body for member role update
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateMemberRoleResponse {
    /// Updated member
    pub member: OrganizationMemberResponse,
}

/// Update organization member's role
///
/// PATCH /v1/organizations/:org/members/:member
///
/// Updates a member's role. Requires admin or owner role.
/// Cannot demote the last owner.
pub async fn update_member_role(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path((org_id, member_id)): Path<(i64, i64)>,
    Json(payload): Json<UpdateMemberRoleRequest>,
) -> Result<Json<UpdateMemberRoleResponse>> {
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());

    // Check if user is a member with admin or owner role
    let user_member = member_repo
        .get_by_org_and_user(org_id, ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::Authz("You are not a member of this organization".to_string()))?;

    if !user_member.role.has_permission(OrganizationRole::Admin) {
        return Err(CoreError::Authz(
            "You must be an admin or owner to update member roles".to_string(),
        )
        .into());
    }

    // Get the target member
    let mut target_member = member_repo
        .get(member_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Member not found".to_string()))?;

    // Verify the member belongs to this organization
    if target_member.organization_id != org_id {
        return Err(
            CoreError::NotFound("Member not found in this organization".to_string()).into(),
        );
    }

    // Parse new role
    let new_role = match payload.role.as_str() {
        "MEMBER" => OrganizationRole::Member,
        "ADMIN" => OrganizationRole::Admin,
        "OWNER" => OrganizationRole::Owner,
        _ => {
            return Err(CoreError::Validation(format!(
                "Invalid role '{}'. Must be MEMBER, ADMIN, or OWNER",
                payload.role
            ))
            .into())
        }
    };

    // If demoting from owner, check if there are other owners
    if target_member.role == OrganizationRole::Owner && new_role != OrganizationRole::Owner {
        let owner_count = member_repo.count_owners(org_id).await?;
        if owner_count <= 1 {
            return Err(CoreError::Validation(
                "Cannot demote the last owner. Transfer ownership first or promote another member."
                    .to_string(),
            )
            .into());
        }
    }

    // Update role
    target_member.set_role(new_role);
    member_repo.update(target_member.clone()).await?;

    Ok(Json(UpdateMemberRoleResponse {
        member: OrganizationMemberResponse {
            id: target_member.id,
            user_id: target_member.user_id,
            role: role_to_string(&target_member.role),
            joined_at: target_member.created_at.to_rfc3339(),
        },
    }))
}

/// Response body for member removal
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveMemberResponse {
    /// Confirmation message
    pub message: String,
}

/// Remove organization member
///
/// DELETE /v1/organizations/:org/members/:member
///
/// Removes a member from the organization. Requires admin or owner role.
/// Cannot remove the last owner.
pub async fn remove_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path((org_id, member_id)): Path<(i64, i64)>,
) -> Result<Json<RemoveMemberResponse>> {
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());

    // Check if user is a member with admin or owner role
    let user_member = member_repo
        .get_by_org_and_user(org_id, ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::Authz("You are not a member of this organization".to_string()))?;

    if !user_member.role.has_permission(OrganizationRole::Admin) {
        return Err(CoreError::Authz(
            "You must be an admin or owner to remove members".to_string(),
        )
        .into());
    }

    // Get the target member
    let target_member = member_repo
        .get(member_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Member not found".to_string()))?;

    // Verify the member belongs to this organization
    if target_member.organization_id != org_id {
        return Err(
            CoreError::NotFound("Member not found in this organization".to_string()).into(),
        );
    }

    // If removing an owner, check if there are other owners
    if target_member.role == OrganizationRole::Owner {
        let owner_count = member_repo.count_owners(org_id).await?;
        if owner_count <= 1 {
            return Err(CoreError::Validation(
                "Cannot remove the last owner. Transfer ownership first or delete the organization."
                    .to_string(),
            )
            .into());
        }
    }

    // Remove member
    member_repo.delete(member_id).await?;

    Ok(Json(RemoveMemberResponse {
        message: "Member removed successfully".to_string(),
    }))
}
