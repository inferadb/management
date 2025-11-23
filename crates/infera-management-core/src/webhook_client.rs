//! Webhook client for invalidating server-side caches
//!
//! This module provides a client for sending cache invalidation webhooks to InferaDB server
//! instances when vaults or organizations are updated in the Management API.

use infera_management_types::ManagementIdentity;
use reqwest::Client as HttpClient;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Webhook client for sending cache invalidation requests to server instances
pub struct WebhookClient {
    /// HTTP client for making requests
    http_client: HttpClient,
    /// List of server endpoints to notify
    server_endpoints: Vec<String>,
    /// Management identity for signing webhook JWTs
    management_identity: Arc<ManagementIdentity>,
}

impl WebhookClient {
    /// Create a new webhook client
    ///
    /// # Arguments
    ///
    /// * `server_endpoints` - List of server URLs to send webhooks to
    /// * `management_identity` - Management identity for signing webhook JWTs
    /// * `timeout_ms` - Request timeout in milliseconds (default: 5000)
    ///
    /// # Example
    ///
    /// ```rust
    /// let identity = Arc::new(ManagementIdentity::generate("mgmt-1".to_string(), "key-1".to_string()));
    /// let endpoints = vec!["http://server1:8080".to_string(), "http://server2:8080".to_string()];
    /// let client = WebhookClient::new(endpoints, identity, 5000)?;
    /// ```
    pub fn new(
        server_endpoints: Vec<String>,
        management_identity: Arc<ManagementIdentity>,
        timeout_ms: u64,
    ) -> Result<Self, String> {
        let http_client = HttpClient::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .pool_max_idle_per_host(10)
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            http_client,
            server_endpoints,
            management_identity,
        })
    }

    /// Get the number of configured server endpoints
    pub fn endpoint_count(&self) -> usize {
        self.server_endpoints.len()
    }

    /// Invalidate vault cache on all server instances
    ///
    /// Sends cache invalidation webhooks to all configured server endpoints in parallel.
    /// This is a fire-and-forget operation - errors are logged but don't fail the operation.
    ///
    /// # Arguments
    ///
    /// * `vault_id` - The vault ID to invalidate
    ///
    /// # Example
    ///
    /// ```rust
    /// client.invalidate_vault(12345).await;
    /// ```
    pub async fn invalidate_vault(&self, vault_id: i64) {
        info!(vault_id = %vault_id, "Invalidating vault cache across all servers");

        // Send requests to all endpoints in parallel
        let mut tasks = Vec::new();

        for endpoint in &self.server_endpoints {
            let http_client = self.http_client.clone();
            let url = format!("{}/internal/cache/invalidate/vault/{}", endpoint, vault_id);
            let endpoint_clone = endpoint.clone();
            let management_identity = Arc::clone(&self.management_identity);

            let task = tokio::spawn(async move {
                debug!(
                    vault_id = %vault_id,
                    endpoint = %endpoint_clone,
                    "Sending vault invalidation webhook"
                );

                // Sign JWT for server authentication
                let jwt = match management_identity.sign_jwt(&endpoint_clone) {
                    Ok(token) => token,
                    Err(e) => {
                        error!(
                            vault_id = %vault_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to sign JWT for vault invalidation webhook"
                        );
                        return;
                    }
                };

                let request = http_client
                    .post(&url)
                    .header("Authorization", format!("Bearer {}", jwt));

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
                    }
                    Err(e) => {
                        error!(
                            vault_id = %vault_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to send vault invalidation webhook"
                        );
                    }
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
            endpoints_count = self.server_endpoints.len(),
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
    ///
    /// # Example
    ///
    /// ```rust
    /// client.invalidate_organization(67890).await;
    /// ```
    pub async fn invalidate_organization(&self, org_id: i64) {
        info!(org_id = %org_id, "Invalidating organization cache across all servers");

        // Send requests to all endpoints in parallel
        let mut tasks = Vec::new();

        for endpoint in &self.server_endpoints {
            let http_client = self.http_client.clone();
            let url = format!("{}/internal/cache/invalidate/organization/{}", endpoint, org_id);
            let endpoint_clone = endpoint.clone();
            let management_identity = Arc::clone(&self.management_identity);

            let task = tokio::spawn(async move {
                debug!(
                    org_id = %org_id,
                    endpoint = %endpoint_clone,
                    "Sending organization invalidation webhook"
                );

                // Sign JWT for server authentication
                let jwt = match management_identity.sign_jwt(&endpoint_clone) {
                    Ok(token) => token,
                    Err(e) => {
                        error!(
                            org_id = %org_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to sign JWT for organization invalidation webhook"
                        );
                        return;
                    }
                };

                let request = http_client
                    .post(&url)
                    .header("Authorization", format!("Bearer {}", jwt));

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
                    }
                    Err(e) => {
                        error!(
                            org_id = %org_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to send organization invalidation webhook"
                        );
                    }
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
            endpoints_count = self.server_endpoints.len(),
            "Completed organization invalidation webhooks"
        );
    }

    /// Discover server endpoints, with support for Kubernetes service discovery
    ///
    /// If the endpoint is a Kubernetes service format (e.g., "http://service-name:port")
    /// and running in Kubernetes (KUBERNETES_SERVICE_HOST env var is set), this will
    /// use the Kubernetes API to discover all pod endpoints behind the service.
    ///
    /// Otherwise, it returns the static endpoints as-is.
    ///
    /// # Arguments
    ///
    /// * `endpoints` - List of static endpoints or Kubernetes service names
    ///
    /// # Returns
    ///
    /// Discovered endpoints (either from k8s or static)
    ///
    /// # Example
    ///
    /// ```rust
    /// let endpoints = vec!["http://inferadb-server:8080".to_string()];
    /// let discovered = WebhookClient::discover_endpoints(endpoints).await;
    /// ```
    pub async fn discover_endpoints(endpoints: Vec<String>) -> Vec<String> {
        // Check if running in Kubernetes
        let in_kubernetes = std::env::var("KUBERNETES_SERVICE_HOST").is_ok();

        if !in_kubernetes {
            debug!(
                "Not running in Kubernetes - using static endpoints: {:?}",
                endpoints
            );
            return endpoints;
        }

        debug!("Running in Kubernetes - attempting service discovery");

        let mut discovered_endpoints = Vec::new();

        for endpoint in &endpoints {
            // Check if this looks like a Kubernetes service (no dots in hostname, simple format)
            if is_kubernetes_service(endpoint) {
                match discover_k8s_service_endpoints(endpoint).await {
                    Ok(pod_endpoints) => {
                        info!(
                            service = %endpoint,
                            pod_count = pod_endpoints.len(),
                            "Discovered Kubernetes service endpoints"
                        );
                        discovered_endpoints.extend(pod_endpoints);
                    }
                    Err(e) => {
                        warn!(
                            service = %endpoint,
                            error = %e,
                            "Failed to discover Kubernetes endpoints, falling back to service URL"
                        );
                        discovered_endpoints.push(endpoint.clone());
                    }
                }
            } else {
                // Not a k8s service, use as-is
                discovered_endpoints.push(endpoint.clone());
            }
        }

        discovered_endpoints
    }
}

/// Check if an endpoint looks like a Kubernetes service
///
/// Kubernetes services typically have simple hostnames without dots:
/// - http://service-name:8080
/// - http://service-name.namespace:8080
/// - http://service-name.namespace.svc.cluster.local:8080
fn is_kubernetes_service(endpoint: &str) -> bool {
    // Parse the URL to extract hostname
    if let Ok(url) = url::Url::parse(endpoint) {
        if let Some(host) = url.host_str() {
            // Check if it's an IP address (not a k8s service)
            if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return false;
            }

            // Kubernetes services have specific patterns:
            // 1. No dots (simple service name): "service-name"
            // 2. Ends with .svc.cluster.local: "service.namespace.svc.cluster.local"
            // 3. Contains .svc.: "service.namespace.svc.something"
            // 4. Has exactly one dot (service.namespace format): "service.namespace"
            let dot_count = host.chars().filter(|&c| c == '.').count();

            return !host.contains('.')
                || host.ends_with(".svc.cluster.local")
                || host.contains(".svc.")
                || (dot_count == 1 && !host.contains(".com") && !host.contains(".io") && !host.contains(".net"));
        }
    }
    false
}

/// Discover Kubernetes service endpoints using the Kubernetes API
///
/// This queries the Kubernetes API to find all pod IPs behind a service.
///
/// # Arguments
///
/// * `service_endpoint` - The Kubernetes service URL (e.g., "http://service-name:8080")
///
/// # Returns
///
/// List of pod endpoints (e.g., ["http://10.0.1.2:8080", "http://10.0.1.3:8080"])
async fn discover_k8s_service_endpoints(service_endpoint: &str) -> Result<Vec<String>, String> {
    // Parse the service URL
    let url = url::Url::parse(service_endpoint)
        .map_err(|e| format!("Invalid service URL: {}", e))?;

    let service_host = url
        .host_str()
        .ok_or_else(|| "No host in service URL".to_string())?;
    let service_port = url
        .port_or_known_default()
        .ok_or_else(|| "No port in service URL".to_string())?;
    let _scheme = url.scheme();

    // Extract service name and namespace from hostname
    // Formats supported:
    // - "service-name" -> (service-name, default namespace from env)
    // - "service-name.namespace" -> (service-name, namespace)
    // - "service-name.namespace.svc.cluster.local" -> (service-name, namespace)
    let parts: Vec<&str> = service_host.split('.').collect();
    let default_namespace = std::env::var("KUBERNETES_NAMESPACE").unwrap_or_else(|_| "default".to_string());
    let (service_name, namespace) = if parts.len() >= 2 {
        (parts[0], parts[1])
    } else {
        (parts[0], default_namespace.as_str())
    };

    debug!(
        service_name = %service_name,
        namespace = %namespace,
        port = service_port,
        "Discovering Kubernetes service endpoints"
    );

    // In a real implementation, you would use the kube-rs library to query the Kubernetes API
    // For now, we'll return a placeholder that falls back to the service URL
    // TODO: Implement actual Kubernetes API integration using kube-rs

    // Placeholder: In production, this would use kube-rs to:
    // 1. Get the Endpoints resource for the service
    // 2. Extract all pod IPs
    // 3. Return list of "http://pod-ip:port" URLs

    // For now, just return the original service endpoint as fallback
    warn!(
        service_name = %service_name,
        namespace = %namespace,
        "Kubernetes service discovery not yet fully implemented - using service URL as fallback"
    );

    Ok(vec![service_endpoint.to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_kubernetes_service() {
        // Kubernetes services
        assert!(is_kubernetes_service("http://inferadb-server:8080"));
        assert!(is_kubernetes_service(
            "http://inferadb-server.default:8080"
        ));
        assert!(is_kubernetes_service(
            "http://inferadb-server.default.svc.cluster.local:8080"
        ));

        // Not Kubernetes services
        assert!(!is_kubernetes_service("http://192.168.1.1:8080"));
        assert!(!is_kubernetes_service("http://example.com:8080"));
        assert!(!is_kubernetes_service("https://api.inferadb.io:443"));
    }

    #[tokio::test]
    async fn test_webhook_client_creation() {
        let identity = Arc::new(ManagementIdentity::generate(
            "test-mgmt".to_string(),
            "test-key".to_string(),
        ));
        let endpoints = vec!["http://localhost:8080".to_string()];
        let client = WebhookClient::new(endpoints, identity, 5000);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_discover_endpoints_static() {
        let endpoints = vec![
            "http://server1:8080".to_string(),
            "http://server2:8080".to_string(),
        ];

        // When not in Kubernetes, should return static endpoints as-is
        std::env::remove_var("KUBERNETES_SERVICE_HOST");
        let discovered = WebhookClient::discover_endpoints(endpoints.clone()).await;
        assert_eq!(discovered, endpoints);
    }
}
