//! Tailscale service discovery implementation
//!
//! Discovers endpoints across multiple clusters using Tailscale MagicDNS.

use async_trait::async_trait;
use tokio::net::lookup_host;
use tracing::{debug, error, info, warn};

use crate::{DiscoveryError, Endpoint, EndpointDiscovery, RemoteCluster, Result};

/// Tailscale service discovery for multi-region deployments
///
/// Uses Tailscale MagicDNS to discover service endpoints across
/// multiple clusters in different regions.
#[derive(Debug)]
pub struct TailscaleServiceDiscovery {
    /// Local cluster name
    local_cluster: String,
    /// Remote clusters to discover
    remote_clusters: Vec<RemoteCluster>,
}

impl TailscaleServiceDiscovery {
    /// Create a new Tailscale service discovery instance
    pub fn new(local_cluster: String, remote_clusters: Vec<RemoteCluster>) -> Self {
        Self { local_cluster, remote_clusters }
    }

    /// Discover endpoints for a single cluster
    async fn discover_cluster(&self, cluster: &RemoteCluster) -> Vec<Endpoint> {
        let hostname = cluster.tailscale_hostname();

        debug!(
            cluster = %cluster.name,
            hostname = %hostname,
            port = cluster.port,
            "Resolving Tailscale MagicDNS name"
        );

        // Perform DNS lookup for the Tailscale hostname
        let lookup_target = format!("{}:{}", hostname, cluster.port);
        let addrs: Vec<std::net::SocketAddr> = match lookup_host(&lookup_target).await {
            Ok(iter) => iter.collect(),
            Err(e) => {
                warn!(
                    cluster = %cluster.name,
                    hostname = %hostname,
                    error = %e,
                    "Failed to resolve Tailscale hostname"
                );
                return vec![];
            },
        };

        // Build endpoint URLs from resolved IPs
        let mut endpoints = Vec::new();
        for addr in addrs {
            let endpoint_url = format!("http://{}:{}", addr.ip(), cluster.port);

            let endpoint = Endpoint::healthy(endpoint_url)
                .with_metadata("cluster".to_string(), cluster.name.clone())
                .with_metadata("tailscale_domain".to_string(), cluster.tailscale_domain.clone())
                .with_metadata("discovery_method".to_string(), "tailscale".to_string());

            endpoints.push(endpoint);
        }

        info!(
            cluster = %cluster.name,
            endpoint_count = endpoints.len(),
            "Discovered Tailscale endpoints for cluster"
        );

        endpoints
    }
}

#[async_trait]
impl EndpointDiscovery for TailscaleServiceDiscovery {
    async fn discover(&self, _service_url: &str) -> Result<Vec<Endpoint>> {
        debug!(
            local_cluster = %self.local_cluster,
            remote_cluster_count = self.remote_clusters.len(),
            "Discovering Tailscale endpoints across clusters"
        );

        if self.remote_clusters.is_empty() {
            return Err(DiscoveryError::Config(
                "No remote clusters configured for Tailscale discovery".to_string(),
            ));
        }

        // Discover endpoints for each remote cluster in parallel
        let mut tasks = Vec::new();

        for cluster in &self.remote_clusters {
            let cluster_clone = cluster.clone();
            let this = Self::new(self.local_cluster.clone(), vec![cluster_clone.clone()]);

            let task = tokio::spawn(async move { this.discover_cluster(&cluster_clone).await });

            tasks.push(task);
        }

        // Collect results from all tasks
        let mut all_endpoints = Vec::new();
        for task in tasks {
            match task.await {
                Ok(endpoints) => {
                    all_endpoints.extend(endpoints);
                },
                Err(e) => {
                    error!(error = %e, "Tailscale discovery task failed");
                },
            }
        }

        if all_endpoints.is_empty() {
            return Err(DiscoveryError::NoEndpoints(
                "No Tailscale endpoints discovered across any cluster".to_string(),
            ));
        }

        info!(
            total_endpoints = all_endpoints.len(),
            local_cluster = %self.local_cluster,
            "Completed Tailscale multi-cluster discovery"
        );

        Ok(all_endpoints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tailscale_discovery_creation() {
        let clusters = vec![RemoteCluster::new(
            "eu-west-1".to_string(),
            "prod.ts.net".to_string(),
            "inferadb-control".to_string(),
            9090,
        )];

        let discovery = TailscaleServiceDiscovery::new("us-west-1".to_string(), clusters);

        assert_eq!(discovery.local_cluster, "us-west-1");
        assert_eq!(discovery.remote_clusters.len(), 1);
    }

    #[tokio::test]
    async fn test_empty_remote_clusters() {
        let discovery = TailscaleServiceDiscovery::new("us-west-1".to_string(), vec![]);

        let result = discovery.discover("http://unused:8080").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DiscoveryError::Config(_)));
    }
}
