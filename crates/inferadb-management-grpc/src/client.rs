use inferadb_management_types::Result;

/// gRPC client for communicating with policy service (server) API
///
/// This is a stub implementation. In production, this would:
/// - Connect to policy service via gRPC with discovery
/// - Authenticate using Client Assertion (JWT signed with system Ed25519 key)
/// - Send CreateVault/DeleteVault RPCs
/// - Handle retries and failures
///
/// For now, all operations succeed immediately (mocked)
pub struct ServerApiClient {
    #[allow(dead_code)]
    grpc_url: String,
}

impl ServerApiClient {
    /// Create a new server API client
    ///
    /// # Arguments
    ///
    /// * `service_url` - Base service URL without port (e.g., "http://localhost")
    /// * `grpc_port` - gRPC port for server communication (e.g., 8080)
    pub fn new(service_url: String, grpc_port: u16) -> Result<Self> {
        let grpc_url = format!("{}:{}", service_url.trim_end_matches('/'), grpc_port);
        Ok(Self { grpc_url })
    }

    /// Create a vault on @server
    ///
    /// In production this would:
    /// 1. Generate a client assertion JWT
    /// 2. Call CreateVault RPC with vault_id and organization_id
    /// 3. Return success or error
    ///
    /// For now: Always succeeds (stub)
    pub async fn create_vault(&self, _vault_id: i64, _organization_id: i64) -> Result<()> {
        // TODO: Implement actual gRPC call to @server
        // For now, simulate success
        Ok(())
    }

    /// Delete a vault on @server
    ///
    /// In production this would:
    /// 1. Generate a client assertion JWT
    /// 2. Call DeleteVault RPC with vault_id
    /// 3. Return success or error
    ///
    /// For now: Always succeeds (stub)
    pub async fn delete_vault(&self, _vault_id: i64) -> Result<()> {
        // TODO: Implement actual gRPC call to @server
        // For now, simulate success
        Ok(())
    }
}
