use crate::handlers::{auth, emails, sessions, users, AppState};
use axum::{
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
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}
