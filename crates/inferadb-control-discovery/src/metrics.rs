//! Prometheus metrics for service discovery

use prometheus::{IntCounter, IntCounterVec, IntGauge, Opts, Registry};

/// Discovery metrics
pub struct DiscoveryMetrics {
    /// Total discovery operations
    pub discovery_operations: IntCounterVec,
    /// Number of discovered endpoints
    pub discovered_endpoints: IntGauge,
    /// Cache hits
    pub cache_hits: IntCounter,
    /// Cache misses
    pub cache_misses: IntCounter,
    /// Load balancer requests
    pub lb_requests: IntCounterVec,
    /// Load balancer failovers
    pub lb_failovers: IntCounter,
    /// Circuit breaker state changes
    pub circuit_breaker_opens: IntCounter,
}

impl DiscoveryMetrics {
    /// Create and register discovery metrics
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let discovery_operations = IntCounterVec::new(
            Opts::new(
                "inferadb_discovery_operations_total",
                "Total number of discovery operations",
            ),
            &["mode", "status"],
        )?;
        registry.register(Box::new(discovery_operations.clone()))?;

        let discovered_endpoints = IntGauge::new(
            "inferadb_discovered_endpoints",
            "Current number of discovered endpoints",
        )?;
        registry.register(Box::new(discovered_endpoints.clone()))?;

        let cache_hits = IntCounter::new(
            "inferadb_discovery_cache_hits_total",
            "Total number of discovery cache hits",
        )?;
        registry.register(Box::new(cache_hits.clone()))?;

        let cache_misses = IntCounter::new(
            "inferadb_discovery_cache_misses_total",
            "Total number of discovery cache misses",
        )?;
        registry.register(Box::new(cache_misses.clone()))?;

        let lb_requests = IntCounterVec::new(
            Opts::new("inferadb_lb_requests_total", "Total number of load balanced requests"),
            &["status"],
        )?;
        registry.register(Box::new(lb_requests.clone()))?;

        let lb_failovers = IntCounter::new(
            "inferadb_lb_failovers_total",
            "Total number of load balancer failovers",
        )?;
        registry.register(Box::new(lb_failovers.clone()))?;

        let circuit_breaker_opens = IntCounter::new(
            "inferadb_circuit_breaker_opens_total",
            "Total number of circuit breaker opens",
        )?;
        registry.register(Box::new(circuit_breaker_opens.clone()))?;

        Ok(Self {
            discovery_operations,
            discovered_endpoints,
            cache_hits,
            cache_misses,
            lb_requests,
            lb_failovers,
            circuit_breaker_opens,
        })
    }

    /// Record a discovery operation
    pub fn record_discovery(&self, mode: &str, success: bool) {
        let status = if success { "success" } else { "error" };
        self.discovery_operations.with_label_values(&[mode, status]).inc();
    }

    /// Set the number of discovered endpoints
    pub fn set_discovered_endpoints(&self, count: i64) {
        self.discovered_endpoints.set(count);
    }

    /// Record a cache hit
    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }

    /// Record a cache miss
    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }

    /// Record a load balanced request
    pub fn record_lb_request(&self, success: bool) {
        let status = if success { "success" } else { "error" };
        self.lb_requests.with_label_values(&[status]).inc();
    }

    /// Record a failover
    pub fn record_failover(&self) {
        self.lb_failovers.inc();
    }

    /// Record a circuit breaker open
    pub fn record_circuit_breaker_open(&self) {
        self.circuit_breaker_opens.inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let registry = Registry::new();
        let metrics = DiscoveryMetrics::new(&registry);
        assert!(metrics.is_ok());
    }

    #[test]
    fn test_metrics_recording() {
        let registry = Registry::new();
        let metrics = DiscoveryMetrics::new(&registry).unwrap();

        metrics.record_discovery("kubernetes", true);
        metrics.record_cache_hit();
        metrics.record_cache_miss();
        metrics.record_lb_request(true);
        metrics.record_failover();
        metrics.record_circuit_breaker_open();
        metrics.set_discovered_endpoints(5);

        // Metrics should be recorded without errors
    }
}
