//! Configuration types for service discovery

use serde::{Deserialize, Serialize};

/// Service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery mode (none, kubernetes, or tailscale)
    #[serde(default)]
    pub mode: DiscoveryMode,

    /// Cache TTL for discovered endpoints (in seconds)
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,

    /// Health check interval (in seconds)
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: DiscoveryMode::None,
            cache_ttl: default_cache_ttl(),
            health_check_interval: default_health_check_interval(),
        }
    }
}

fn default_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_health_check_interval() -> u64 {
    30 // 30 seconds
}

/// Service discovery mode
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum DiscoveryMode {
    /// No service discovery - use service URL directly
    #[default]
    None,
    /// Kubernetes service discovery - resolve to pod IPs
    Kubernetes,
    /// Tailscale mesh networking for multi-region discovery
    Tailscale {
        /// Local cluster name (e.g., "us-west-1")
        local_cluster: String,
        /// Remote clusters to discover across
        #[serde(default)]
        remote_clusters: Vec<RemoteCluster>,
    },
}

/// Remote cluster configuration for Tailscale mesh networking
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCluster {
    /// Cluster name (e.g., "eu-west-1", "ap-southeast-1")
    pub name: String,

    /// Tailscale domain for this cluster (e.g., "eu-west-1.ts.net")
    pub tailscale_domain: String,

    /// Service name within the cluster (e.g., "inferadb-control")
    pub service_name: String,

    /// Service port
    pub port: u16,
}

impl RemoteCluster {
    /// Create a new remote cluster configuration
    pub fn new(name: String, tailscale_domain: String, service_name: String, port: u16) -> Self {
        Self { name, tailscale_domain, service_name, port }
    }

    /// Get the full Tailscale hostname for this cluster
    pub fn tailscale_hostname(&self) -> String {
        format!("{}.{}", self.service_name, self.tailscale_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_mode_default() {
        let mode = DiscoveryMode::default();
        assert_eq!(mode, DiscoveryMode::None);
    }

    #[test]
    fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.mode, DiscoveryMode::None);
        assert_eq!(config.cache_ttl, 300);
        assert_eq!(config.health_check_interval, 30);
    }

    #[test]
    fn test_remote_cluster_hostname() {
        let cluster = RemoteCluster::new(
            "eu-west-1".to_string(),
            "prod.ts.net".to_string(),
            "inferadb-control".to_string(),
            9090,
        );
        assert_eq!(cluster.tailscale_hostname(), "inferadb-control.prod.ts.net");
    }

    #[test]
    fn test_discovery_mode_serde() {
        // Test None mode
        let json = r#"{"type":"none"}"#;
        let mode: DiscoveryMode = serde_json::from_str(json).unwrap();
        assert_eq!(mode, DiscoveryMode::None);

        // Test Kubernetes mode
        let json = r#"{"type":"kubernetes"}"#;
        let mode: DiscoveryMode = serde_json::from_str(json).unwrap();
        assert_eq!(mode, DiscoveryMode::Kubernetes);

        // Test Tailscale mode
        let json = r#"{"type":"tailscale","local_cluster":"us-west-1","remote_clusters":[]}"#;
        let mode: DiscoveryMode = serde_json::from_str(json).unwrap();
        assert!(matches!(mode, DiscoveryMode::Tailscale { .. }));
    }
}
