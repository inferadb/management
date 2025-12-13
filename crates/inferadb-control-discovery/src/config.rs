//! Configuration types for service discovery

use serde::{Deserialize, Serialize};

/// Service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery mode (none or kubernetes)
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
    fn test_discovery_mode_serde() {
        // Test None mode
        let json = r#"{"type":"none"}"#;
        let mode: DiscoveryMode = serde_json::from_str(json).unwrap();
        assert_eq!(mode, DiscoveryMode::None);

        // Test Kubernetes mode
        let json = r#"{"type":"kubernetes"}"#;
        let mode: DiscoveryMode = serde_json::from_str(json).unwrap();
        assert_eq!(mode, DiscoveryMode::Kubernetes);
    }
}
