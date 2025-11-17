use infera_management_core::Result;

/// gRPC client for communicating with @server API
/// Will be implemented in Phase 5
pub struct ServerApiClient;

impl ServerApiClient {
    pub fn new(_endpoint: String) -> Result<Self> {
        Ok(Self)
    }
}
