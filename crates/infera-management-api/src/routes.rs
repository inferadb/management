use crate::handlers::{auth, emails, organizations, sessions, users, AppState};
use crate::middleware::require_session;
use axum::{
    middleware,
    routing::{delete, get, patch, post},
    Router,
};

/// Create the Axum router with all API routes
pub fn create_router() -> Router<AppState> {
    Router::new()
        // Public routes (no authentication required)
        .route("/health", get(health_check))
        .route("/v1/auth/register", post(auth::register))
        .route("/v1/auth/login/password", post(auth::login))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/auth/verify-email", post(auth::verify_email))
        .route(
            "/v1/auth/password-reset/request",
            post(auth::request_password_reset),
        )
        .route(
            "/v1/auth/password-reset/confirm",
            post(auth::confirm_password_reset),
        )
        // Protected session management routes
        .route("/v1/users/sessions", get(sessions::list_sessions))
        .route("/v1/users/sessions/{id}", delete(sessions::revoke_session))
        .route(
            "/v1/users/sessions/revoke-others",
            post(sessions::revoke_other_sessions),
        )
        // User profile management routes
        .route("/v1/users/me", get(users::get_profile))
        .route("/v1/users/me", patch(users::update_profile))
        .route("/v1/users/me", delete(users::delete_user))
        // Email management routes
        .route("/v1/users/emails", post(emails::add_email))
        .route("/v1/users/emails", get(emails::list_emails))
        .route("/v1/users/emails/{id}", patch(emails::update_email))
        .route("/v1/users/emails/{id}", delete(emails::delete_email))
        // Organization management routes
        .route(
            "/v1/organizations",
            post(organizations::create_organization),
        )
        .route("/v1/organizations", get(organizations::list_organizations))
        .route(
            "/v1/organizations/{org}",
            get(organizations::get_organization),
        )
        .route(
            "/v1/organizations/{org}",
            patch(organizations::update_organization),
        )
        .route(
            "/v1/organizations/{org}",
            delete(organizations::delete_organization),
        )
        // Organization member management routes
        .route(
            "/v1/organizations/{org}/members",
            get(organizations::list_members),
        )
        .route(
            "/v1/organizations/{org}/members/{member}",
            patch(organizations::update_member_role),
        )
        .route(
            "/v1/organizations/{org}/members/{member}",
            delete(organizations::remove_member),
        )
}

/// Create router with state and middleware applied
///
/// Applies session middleware only to protected routes, leaving public routes (like register/login)
/// accessible without authentication.
pub fn create_router_with_state(state: AppState) -> axum::Router {
    // Create router with protected routes that need session middleware
    let protected = Router::new()
        // Protected session management routes
        .route("/v1/users/sessions", get(sessions::list_sessions))
        .route("/v1/users/sessions/{id}", delete(sessions::revoke_session))
        .route(
            "/v1/users/sessions/revoke-others",
            post(sessions::revoke_other_sessions),
        )
        // User profile management routes
        .route("/v1/users/me", get(users::get_profile))
        .route("/v1/users/me", patch(users::update_profile))
        .route("/v1/users/me", delete(users::delete_user))
        // Email management routes
        .route("/v1/users/emails", post(emails::add_email))
        .route("/v1/users/emails", get(emails::list_emails))
        .route("/v1/users/emails/{id}", patch(emails::update_email))
        .route("/v1/users/emails/{id}", delete(emails::delete_email))
        // Organization management routes
        .route(
            "/v1/organizations",
            post(organizations::create_organization),
        )
        .route("/v1/organizations", get(organizations::list_organizations))
        .route(
            "/v1/organizations/{org}",
            get(organizations::get_organization),
        )
        .route(
            "/v1/organizations/{org}",
            patch(organizations::update_organization),
        )
        .route(
            "/v1/organizations/{org}",
            delete(organizations::delete_organization),
        )
        // Organization member management routes
        .route(
            "/v1/organizations/{org}/members",
            get(organizations::list_members),
        )
        .route(
            "/v1/organizations/{org}/members/{member}",
            patch(organizations::update_member_role),
        )
        .route(
            "/v1/organizations/{org}/members/{member}",
            delete(organizations::remove_member),
        )
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));

    // Combine public and protected routes
    Router::new()
        .route("/health", get(health_check))
        .route("/v1/auth/register", post(auth::register))
        .route("/v1/auth/login/password", post(auth::login))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/auth/verify-email", post(auth::verify_email))
        .route(
            "/v1/auth/password-reset/request",
            post(auth::request_password_reset),
        )
        .route(
            "/v1/auth/password-reset/confirm",
            post(auth::confirm_password_reset),
        )
        .with_state(state)
        .merge(protected)
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}
