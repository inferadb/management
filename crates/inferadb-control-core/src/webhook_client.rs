//! Webhook client for invalidating server-side caches
//!
//! This module provides a client for sending cache invalidation webhooks to InferaDB server
//! instances when vaults or organizations are updated in the Control API.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use inferadb_control_discovery::{DiscoveryMode, EndpointDiscovery, create_discovery};
use inferadb_control_types::ControlIdentity;
use parking_lot::RwLock;
use reqwest::Client as HttpClient;
use tracing::{debug, error, info, warn};

/// Cached endpoints with TTL validation
#[derive(Debug, Clone)]
struct CachedEndpoints {
    endpoints: Vec<String>,
    cached_at: Instant,
    ttl: Duration,
}

impl CachedEndpoints {
    fn is_valid(&self) -> bool {
        self.cached_at.elapsed() < self.ttl
    }
}

/// Webhook client for sending cache invalidation requests to server instances
pub struct WebhookClient {
    /// HTTP client for making requests
    http_client: HttpClient,
    /// Discovery service for finding endpoints
    discovery: Box<dyn EndpointDiscovery>,
    /// Service URL (for static fallback and discovery context)
    service_url: String,
    /// Internal port for webhooks
    internal_port: u16,
    /// Control identity for signing webhook JWTs
    control_identity: Arc<ControlIdentity>,
    /// Cached discovered endpoints
    endpoint_cache: Arc<RwLock<Option<CachedEndpoints>>>,
    /// Cache TTL in seconds
    cache_ttl: u64,
}

impl std::fmt::Debug for WebhookClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookClient")
            .field("discovery", &self.discovery)
            .field("service_url", &self.service_url)
            .field("internal_port", &self.internal_port)
            .field("cache_ttl", &self.cache_ttl)
            .finish()
    }
}

impl WebhookClient {
    /// Create a new webhook client with discovery support
    ///
    /// # Arguments
    ///
    /// * `service_url` - Base service URL without port (e.g., "http://localhost" or "http://inferadb-engine.inferadb")
    /// * `internal_port` - Internal API port for webhooks (e.g., 9090)
    /// * `control_identity` - Control identity for signing webhook JWTs
    /// * `timeout_ms` - Request timeout in milliseconds (default: 5000)
    /// * `discovery_mode` - Service discovery mode (None or Kubernetes)
    /// * `cache_ttl` - Cache TTL for discovered endpoints in seconds (default: 300)
    pub fn new(
        service_url: String,
        internal_port: u16,
        control_identity: Arc<ControlIdentity>,
        timeout_ms: u64,
        discovery_mode: DiscoveryMode,
        cache_ttl: u64,
    ) -> Result<Self, String> {
        let http_client = HttpClient::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .pool_max_idle_per_host(10)
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        // Create discovery service based on mode
        let discovery = create_discovery(&discovery_mode);

        info!(
            service_url = %service_url,
            internal_port = internal_port,
            discovery_mode = ?discovery_mode,
            "Created webhook client"
        );

        Ok(Self {
            http_client,
            discovery,
            service_url,
            internal_port,
            control_identity,
            endpoint_cache: Arc::new(RwLock::new(None)),
            cache_ttl,
        })
    }

    /// Get endpoints (with discovery and caching)
    async fn get_endpoints(&self) -> Vec<String> {
        // Check cache first
        {
            let cache = self.endpoint_cache.read();
            if let Some(cached) = cache.as_ref() {
                if cached.is_valid() {
                    debug!(count = cached.endpoints.len(), "Using cached endpoints");
                    crate::metrics::record_discovery_cache_hit();
                    return cached.endpoints.clone();
                }
            }
        }

        // Cache miss or expired
        crate::metrics::record_discovery_cache_miss();
        debug!("Cache miss or expired, discovering endpoints");

        // Build the service URL for discovery
        let full_service_url =
            format!("{}:{}", self.service_url.trim_end_matches('/'), self.internal_port);

        // Discover endpoints using the discovery service
        let endpoints = match self.discovery.discover(&full_service_url).await {
            Ok(discovered) => {
                info!(count = discovered.len(), "Discovered endpoints");
                discovered.into_iter().map(|e| e.url).collect()
            },
            Err(e) => {
                warn!(
                    error = %e,
                    service_url = %full_service_url,
                    "Discovery failed, using static fallback"
                );
                vec![full_service_url]
            },
        };

        // Update cache
        {
            let mut cache = self.endpoint_cache.write();
            *cache = Some(CachedEndpoints {
                endpoints: endpoints.clone(),
                cached_at: Instant::now(),
                ttl: Duration::from_secs(self.cache_ttl),
            });
        }

        // Update metrics
        crate::metrics::set_discovered_endpoints(endpoints.len() as i64);

        endpoints
    }

    /// Get the number of configured server endpoints (from cache or discovery)
    pub async fn endpoint_count(&self) -> usize {
        self.get_endpoints().await.len()
    }

    /// Invalidate vault cache on all server instances
    ///
    /// Sends cache invalidation webhooks to all configured server endpoints in parallel.
    /// This is a fire-and-forget operation - errors are logged but don't fail the operation.
    ///
    /// # Arguments
    ///
    /// * `vault_id` - The vault ID to invalidate
    pub async fn invalidate_vault(&self, vault_id: i64) {
        let endpoints = self.get_endpoints().await;

        if endpoints.is_empty() {
            warn!(vault_id = %vault_id, "No server endpoints configured, skipping cache invalidation");
            return;
        }

        info!(
            vault_id = %vault_id,
            endpoints_count = endpoints.len(),
            "Invalidating vault cache across all servers"
        );

        // Send requests to all endpoints in parallel
        let mut tasks = Vec::new();

        for endpoint in &endpoints {
            let http_client = self.http_client.clone();
            let url = format!("{}/internal/cache/invalidate/vault/{}", endpoint, vault_id);
            let endpoint_clone = endpoint.clone();
            let control_identity = Arc::clone(&self.control_identity);

            let task = tokio::spawn(async move {
                debug!(
                    vault_id = %vault_id,
                    endpoint = %endpoint_clone,
                    "Sending vault invalidation webhook"
                );

                // Sign JWT for server authentication
                let jwt = match control_identity.sign_jwt(&endpoint_clone) {
                    Ok(token) => token,
                    Err(e) => {
                        error!(
                            vault_id = %vault_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to sign JWT for vault invalidation webhook"
                        );
                        return;
                    },
                };

                let request =
                    http_client.post(&url).header("Authorization", format!("Bearer {}", jwt));

                match request.send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            debug!(
                                vault_id = %vault_id,
                                endpoint = %endpoint_clone,
                                "Vault invalidation webhook succeeded"
                            );
                        } else {
                            warn!(
                                vault_id = %vault_id,
                                endpoint = %endpoint_clone,
                                status = %response.status(),
                                "Vault invalidation webhook returned non-success status"
                            );
                        }
                    },
                    Err(e) => {
                        error!(
                            vault_id = %vault_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to send vault invalidation webhook"
                        );
                    },
                }
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete (fire-and-forget)
        for task in tasks {
            let _ = task.await;
        }

        info!(
            vault_id = %vault_id,
            endpoints_count = endpoints.len(),
            "Completed vault invalidation webhooks"
        );
    }

    /// Invalidate organization cache on all server instances
    ///
    /// Sends cache invalidation webhooks to all configured server endpoints in parallel.
    /// This is a fire-and-forget operation - errors are logged but don't fail the operation.
    ///
    /// # Arguments
    ///
    /// * `org_id` - The organization ID to invalidate
    pub async fn invalidate_organization(&self, org_id: i64) {
        let endpoints = self.get_endpoints().await;

        if endpoints.is_empty() {
            warn!(org_id = %org_id, "No server endpoints configured, skipping cache invalidation");
            return;
        }

        info!(
            org_id = %org_id,
            endpoints_count = endpoints.len(),
            "Invalidating organization cache across all servers"
        );

        // Send requests to all endpoints in parallel
        let mut tasks = Vec::new();

        for endpoint in &endpoints {
            let http_client = self.http_client.clone();
            let url = format!("{}/internal/cache/invalidate/organization/{}", endpoint, org_id);
            let endpoint_clone = endpoint.clone();
            let control_identity = Arc::clone(&self.control_identity);

            let task = tokio::spawn(async move {
                debug!(
                    org_id = %org_id,
                    endpoint = %endpoint_clone,
                    "Sending organization invalidation webhook"
                );

                // Sign JWT for server authentication
                let jwt = match control_identity.sign_jwt(&endpoint_clone) {
                    Ok(token) => token,
                    Err(e) => {
                        error!(
                            org_id = %org_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to sign JWT for organization invalidation webhook"
                        );
                        return;
                    },
                };

                let request =
                    http_client.post(&url).header("Authorization", format!("Bearer {}", jwt));

                match request.send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            debug!(
                                org_id = %org_id,
                                endpoint = %endpoint_clone,
                                "Organization invalidation webhook succeeded"
                            );
                        } else {
                            warn!(
                                org_id = %org_id,
                                endpoint = %endpoint_clone,
                                status = %response.status(),
                                "Organization invalidation webhook returned non-success status"
                            );
                        }
                    },
                    Err(e) => {
                        error!(
                            org_id = %org_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to send organization invalidation webhook"
                        );
                    },
                }
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete (fire-and-forget)
        for task in tasks {
            let _ = task.await;
        }

        info!(
            org_id = %org_id,
            endpoints_count = endpoints.len(),
            "Completed organization invalidation webhooks"
        );
    }

    /// Invalidate certificate cache on all server instances
    ///
    /// Sends cache invalidation webhooks to all configured server endpoints in parallel.
    /// This is a fire-and-forget operation - errors are logged but don't fail the operation.
    ///
    /// # Arguments
    ///
    /// * `org_id` - The organization ID
    /// * `client_id` - The client ID
    /// * `cert_id` - The certificate ID to invalidate
    pub async fn invalidate_certificate(&self, org_id: i64, client_id: i64, cert_id: i64) {
        let endpoints = self.get_endpoints().await;

        if endpoints.is_empty() {
            warn!(
                org_id = %org_id,
                client_id = %client_id,
                cert_id = %cert_id,
                "No server endpoints configured, skipping cache invalidation"
            );
            return;
        }

        info!(
            org_id = %org_id,
            client_id = %client_id,
            cert_id = %cert_id,
            endpoints_count = endpoints.len(),
            "Invalidating certificate cache across all servers"
        );

        // Send requests to all endpoints in parallel
        let mut tasks = Vec::new();

        for endpoint in &endpoints {
            let http_client = self.http_client.clone();
            let url = format!(
                "{}/internal/cache/invalidate/certificate/{}/{}/{}",
                endpoint, org_id, client_id, cert_id
            );
            let endpoint_clone = endpoint.clone();
            let control_identity = Arc::clone(&self.control_identity);

            let task = tokio::spawn(async move {
                debug!(
                    org_id = %org_id,
                    client_id = %client_id,
                    cert_id = %cert_id,
                    endpoint = %endpoint_clone,
                    "Sending certificate invalidation webhook"
                );

                // Sign JWT for server authentication
                let jwt = match control_identity.sign_jwt(&endpoint_clone) {
                    Ok(token) => token,
                    Err(e) => {
                        error!(
                            org_id = %org_id,
                            client_id = %client_id,
                            cert_id = %cert_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to sign JWT for certificate invalidation webhook"
                        );
                        return;
                    },
                };

                let request =
                    http_client.post(&url).header("Authorization", format!("Bearer {}", jwt));

                match request.send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            debug!(
                                org_id = %org_id,
                                client_id = %client_id,
                                cert_id = %cert_id,
                                endpoint = %endpoint_clone,
                                "Certificate invalidation webhook succeeded"
                            );
                        } else {
                            warn!(
                                org_id = %org_id,
                                client_id = %client_id,
                                cert_id = %cert_id,
                                endpoint = %endpoint_clone,
                                status = %response.status(),
                                "Certificate invalidation webhook returned non-success status"
                            );
                        }
                    },
                    Err(e) => {
                        error!(
                            org_id = %org_id,
                            client_id = %client_id,
                            cert_id = %cert_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to send certificate invalidation webhook"
                        );
                    },
                }
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete (fire-and-forget)
        for task in tasks {
            let _ = task.await;
        }

        info!(
            org_id = %org_id,
            client_id = %client_id,
            cert_id = %cert_id,
            endpoints_count = endpoints.len(),
            "Completed certificate invalidation webhooks"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_webhook_client_creation() {
        let identity = Arc::new(ControlIdentity::generate());
        let client = WebhookClient::new(
            "http://localhost".to_string(),
            9090,
            identity,
            5000,
            DiscoveryMode::None,
            300,
        );
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_webhook_client_creation_with_discovery() {
        let identity = Arc::new(ControlIdentity::generate());

        // Test with DiscoveryMode::None
        let client = WebhookClient::new(
            "http://localhost".to_string(),
            9090,
            identity.clone(),
            5000,
            DiscoveryMode::None,
            300,
        );
        assert!(client.is_ok());

        // Test with DiscoveryMode::Kubernetes
        let client = WebhookClient::new(
            "http://inferadb-engine".to_string(),
            9090,
            identity,
            5000,
            DiscoveryMode::Kubernetes,
            300,
        );
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_cached_endpoints_is_valid() {
        let cached = CachedEndpoints {
            endpoints: vec!["http://test:8080".to_string()],
            cached_at: Instant::now(),
            ttl: Duration::from_secs(30),
        };
        assert!(cached.is_valid());

        // Test expired cache
        let expired = CachedEndpoints {
            endpoints: vec!["http://test:8080".to_string()],
            cached_at: Instant::now() - Duration::from_secs(31),
            ttl: Duration::from_secs(30),
        };
        assert!(!expired.is_valid());
    }

    #[tokio::test]
    async fn test_get_endpoints_caching() {
        let identity = Arc::new(ControlIdentity::generate());

        let client = WebhookClient::new(
            "http://server1".to_string(),
            9090,
            identity,
            5000,
            DiscoveryMode::None,
            30,
        )
        .unwrap();

        // First call should cache
        let result1 = client.get_endpoints().await;
        assert_eq!(result1, vec!["http://server1:9090".to_string()]);

        // Second call should use cache (same result)
        let result2 = client.get_endpoints().await;
        assert_eq!(result2, vec!["http://server1:9090".to_string()]);
    }

    #[tokio::test]
    async fn test_endpoint_count() {
        let identity = Arc::new(ControlIdentity::generate());

        // With static discovery, we get a single endpoint
        let client = WebhookClient::new(
            "http://server1".to_string(),
            9090,
            identity,
            5000,
            DiscoveryMode::None,
            300,
        )
        .unwrap();

        assert_eq!(client.endpoint_count().await, 1);
    }

    #[tokio::test]
    async fn test_kubernetes_discovery_mode() {
        let identity = Arc::new(ControlIdentity::generate());

        // Simple service name
        let client = WebhookClient::new(
            "http://inferadb-engine".to_string(),
            9090,
            identity.clone(),
            5000,
            DiscoveryMode::Kubernetes,
            300,
        );
        assert!(client.is_ok());

        // Service with namespace
        let client = WebhookClient::new(
            "http://inferadb-engine.default".to_string(),
            9090,
            identity.clone(),
            5000,
            DiscoveryMode::Kubernetes,
            300,
        );
        assert!(client.is_ok());

        // Full FQDN
        let client = WebhookClient::new(
            "http://inferadb-engine.default.svc.cluster.local".to_string(),
            9090,
            identity,
            5000,
            DiscoveryMode::Kubernetes,
            300,
        );
        assert!(client.is_ok());
    }

}
