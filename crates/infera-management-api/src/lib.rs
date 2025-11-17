// REST API handlers and routes

pub mod handlers;
pub mod middleware;
pub mod routes;

pub use handlers::{AppState, ErrorResponse};
pub use middleware::{extract_session_context, require_session, SessionContext};
pub use routes::create_router;
