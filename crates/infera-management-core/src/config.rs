use serde::{Deserialize, Serialize};
use std::path::Path;

use infera_management_types::error::{Error, Result};

/// Root configuration for the Management API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementConfig {
    /// Server configuration
    pub server: ServerConfig,

    /// Storage configuration
    pub storage: StorageConfig,

    /// Authentication configuration
    pub auth: AuthConfig,

    /// Email configuration
    pub email: EmailConfig,

    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,

    /// Observability configuration
    pub observability: ObservabilityConfig,

    /// ID generation configuration
    pub id_generation: IdGenerationConfig,

    /// Server API configuration (for gRPC communication with @server)
    pub server_api: ServerApiConfig,

    /// Frontend base URL for email links (verification, password reset)
    /// Example: "https://app.inferadb.com" or "http://localhost:3000"
    /// Environment variable: INFERADB_MGMT__FRONTEND_BASE_URL
    #[serde(default = "default_frontend_base_url")]
    pub frontend_base_url: String,
}

/// Server/HTTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// HTTP server host
    #[serde(default = "default_http_host")]
    pub http_host: String,

    /// HTTP server port
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// gRPC server host
    #[serde(default = "default_grpc_host")]
    pub grpc_host: String,

    /// gRPC server port
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,

    /// Worker threads for async runtime
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
}

/// Storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend type: "memory" or "foundationdb"
    #[serde(default = "default_storage_backend")]
    pub backend: String,

    /// FoundationDB cluster file path (only used when backend = "foundationdb")
    pub fdb_cluster_file: Option<String>,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Session TTL for WEB sessions (seconds)
    #[serde(default = "default_session_ttl_web")]
    pub session_ttl_web: u64,

    /// Session TTL for CLI sessions (seconds)
    #[serde(default = "default_session_ttl_cli")]
    pub session_ttl_cli: u64,

    /// Session TTL for SDK sessions (seconds)
    #[serde(default = "default_session_ttl_sdk")]
    pub session_ttl_sdk: u64,

    /// Minimum password length
    #[serde(default = "default_password_min_length")]
    pub password_min_length: usize,

    /// Maximum concurrent sessions per user
    #[serde(default = "default_max_sessions_per_user")]
    pub max_sessions_per_user: usize,

    /// WebAuthn configuration
    pub webauthn: WebAuthnConfig,

    /// Key encryption secret for encrypting private keys at rest
    /// Should be set via environment variable INFERADB_MGMT_KEY_ENCRYPTION_SECRET
    pub key_encryption_secret: Option<String>,

    /// JWT issuer URL (this Management API instance)
    /// Used in vault-scoped JWTs issued to clients
    /// Example: "https://api.inferadb.com" or "http://localhost:8081"
    /// Environment variable: INFERA_MANAGEMENT__AUTH__JWT_ISSUER
    #[serde(default = "default_jwt_issuer")]
    pub jwt_issuer: String,

    /// JWT audience URL (the Server API)
    /// Used in vault-scoped JWTs issued to clients
    /// Example: "https://api.inferadb.com/evaluate" or "http://localhost:8080/evaluate"
    /// Environment variable: INFERA_MANAGEMENT__AUTH__JWT_AUDIENCE
    #[serde(default = "default_jwt_audience")]
    pub jwt_audience: String,
}

/// WebAuthn configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying Party ID (domain)
    pub rp_id: String,

    /// Relying Party name
    #[serde(default = "default_rp_name")]
    pub rp_name: String,

    /// Origin URL for WebAuthn
    pub origin: String,
}

/// Email configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP host
    pub smtp_host: String,

    /// SMTP port
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,

    /// SMTP username
    pub smtp_username: Option<String>,

    /// SMTP password (should be set via environment variable)
    pub smtp_password: Option<String>,

    /// From email address
    pub from_email: String,

    /// From name
    #[serde(default = "default_from_name")]
    pub from_name: String,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Login attempts per IP per hour
    #[serde(default = "default_login_attempts_per_ip_per_hour")]
    pub login_attempts_per_ip_per_hour: u32,

    /// Registrations per IP per day
    #[serde(default = "default_registrations_per_ip_per_day")]
    pub registrations_per_ip_per_day: u32,

    /// Email verification tokens per email per hour
    #[serde(default = "default_email_verification_tokens_per_hour")]
    pub email_verification_tokens_per_hour: u32,

    /// Password reset tokens per user per hour
    #[serde(default = "default_password_reset_tokens_per_hour")]
    pub password_reset_tokens_per_hour: u32,
}

/// Observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Enable Prometheus metrics
    #[serde(default = "default_metrics_enabled")]
    pub metrics_enabled: bool,

    /// Enable OpenTelemetry tracing
    #[serde(default = "default_tracing_enabled")]
    pub tracing_enabled: bool,

    /// OTLP endpoint for traces (if tracing enabled)
    pub otlp_endpoint: Option<String>,
}

/// ID generation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdGenerationConfig {
    /// Worker ID for Snowflake ID generation (0-1023)
    #[serde(default = "default_worker_id")]
    pub worker_id: u16,

    /// Maximum acceptable clock skew in milliseconds
    #[serde(default = "default_max_clock_skew_ms")]
    pub max_clock_skew_ms: u64,
}

/// Server API configuration (for gRPC communication with @server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerApiConfig {
    /// gRPC endpoint for @server
    pub grpc_endpoint: String,

    /// Enable TLS for gRPC communication
    #[serde(default = "default_grpc_tls_enabled")]
    pub tls_enabled: bool,
}

// Default value functions
fn default_http_host() -> String {
    "127.0.0.1".to_string()
}

fn default_http_port() -> u16 {
    3000
}

fn default_grpc_host() -> String {
    "127.0.0.1".to_string()
}

fn default_grpc_port() -> u16 {
    3001
}

fn default_worker_threads() -> usize {
    4
}

fn default_storage_backend() -> String {
    "memory".to_string()
}

fn default_session_ttl_web() -> u64 {
    30 * 24 * 60 * 60 // 30 days
}

fn default_session_ttl_cli() -> u64 {
    90 * 24 * 60 * 60 // 90 days
}

fn default_session_ttl_sdk() -> u64 {
    90 * 24 * 60 * 60 // 90 days
}

fn default_password_min_length() -> usize {
    12
}

fn default_max_sessions_per_user() -> usize {
    10
}

fn default_rp_name() -> String {
    "InferaDB".to_string()
}

fn default_smtp_port() -> u16 {
    587
}

fn default_from_name() -> String {
    "InferaDB".to_string()
}

fn default_login_attempts_per_ip_per_hour() -> u32 {
    100
}

fn default_registrations_per_ip_per_day() -> u32 {
    5
}

fn default_email_verification_tokens_per_hour() -> u32 {
    5
}

fn default_password_reset_tokens_per_hour() -> u32 {
    3
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_tracing_enabled() -> bool {
    false
}

fn default_worker_id() -> u16 {
    0
}

fn default_max_clock_skew_ms() -> u64 {
    1000 // 1 second
}

fn default_grpc_tls_enabled() -> bool {
    true
}

fn default_frontend_base_url() -> String {
    "http://localhost:3000".to_string()
}

fn default_jwt_issuer() -> String {
    "https://api.inferadb.com".to_string()
}

fn default_jwt_audience() -> String {
    "https://api.inferadb.com/evaluate".to_string()
}

impl ManagementConfig {
    /// Load configuration from a file with environment variable overrides
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config = config::Config::builder()
            // Load from YAML file
            .add_source(config::File::from(path.as_ref()))
            // Override with environment variables prefixed with INFERADB_MGMT_
            .add_source(
                config::Environment::with_prefix("INFERADB_MGMT")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()
            .map_err(|e| Error::Config(format!("Failed to build config: {}", e)))?;

        config
            .try_deserialize()
            .map_err(|e| Error::Config(format!("Failed to deserialize config: {}", e)))
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate storage backend
        if self.storage.backend != "memory" && self.storage.backend != "foundationdb" {
            return Err(Error::Config(format!(
                "Invalid storage backend: {}. Must be 'memory' or 'foundationdb'",
                self.storage.backend
            )));
        }

        // Validate FoundationDB config
        if self.storage.backend == "foundationdb" && self.storage.fdb_cluster_file.is_none() {
            return Err(Error::Config(
                "fdb_cluster_file is required when using FoundationDB backend".to_string(),
            ));
        }

        // Validate worker ID range
        if self.id_generation.worker_id > 1023 {
            return Err(Error::Config(format!(
                "Worker ID must be between 0 and 1023, got {}",
                self.id_generation.worker_id
            )));
        }

        // Validate key encryption secret is set
        if self.auth.key_encryption_secret.is_none() {
            tracing::warn!(
                "KEY_ENCRYPTION_SECRET not set - private keys will not be encrypted at rest!"
            );
        }

        // Validate frontend_base_url format
        if !self.frontend_base_url.starts_with("http://")
            && !self.frontend_base_url.starts_with("https://")
        {
            return Err(Error::Config(
                "frontend_base_url must start with http:// or https://".to_string(),
            ));
        }

        if self.frontend_base_url.ends_with('/') {
            return Err(Error::Config(
                "frontend_base_url must not end with trailing slash".to_string(),
            ));
        }

        // Warn about localhost in production-like environments
        if self.frontend_base_url.contains("localhost")
            || self.frontend_base_url.contains("127.0.0.1")
        {
            tracing::warn!(
                "frontend_base_url contains localhost - this should only be used in development. \
                 Production deployments should use a public domain."
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        assert_eq!(default_http_host(), "127.0.0.1");
        assert_eq!(default_http_port(), 3000);
        assert_eq!(default_grpc_port(), 3001);
        assert_eq!(default_storage_backend(), "memory");
        assert_eq!(default_password_min_length(), 12);
        assert_eq!(default_max_sessions_per_user(), 10);
    }

    #[test]
    fn test_worker_id_validation() {
        let mut config = ManagementConfig {
            server: ServerConfig {
                http_host: default_http_host(),
                http_port: default_http_port(),
                grpc_host: default_grpc_host(),
                grpc_port: default_grpc_port(),
                worker_threads: default_worker_threads(),
            },
            storage: StorageConfig {
                backend: "memory".to_string(),
                fdb_cluster_file: None,
            },
            auth: AuthConfig {
                session_ttl_web: default_session_ttl_web(),
                session_ttl_cli: default_session_ttl_cli(),
                session_ttl_sdk: default_session_ttl_sdk(),
                password_min_length: default_password_min_length(),
                max_sessions_per_user: default_max_sessions_per_user(),
                webauthn: WebAuthnConfig {
                    rp_id: "localhost".to_string(),
                    rp_name: default_rp_name(),
                    origin: "http://localhost:3000".to_string(),
                },
                key_encryption_secret: Some("test-secret".to_string()),
                jwt_issuer: default_jwt_issuer(),
                jwt_audience: default_jwt_audience(),
            },
            email: EmailConfig {
                smtp_host: "localhost".to_string(),
                smtp_port: default_smtp_port(),
                smtp_username: None,
                smtp_password: None,
                from_email: "noreply@inferadb.com".to_string(),
                from_name: default_from_name(),
            },
            rate_limiting: RateLimitingConfig {
                login_attempts_per_ip_per_hour: default_login_attempts_per_ip_per_hour(),
                registrations_per_ip_per_day: default_registrations_per_ip_per_day(),
                email_verification_tokens_per_hour: default_email_verification_tokens_per_hour(),
                password_reset_tokens_per_hour: default_password_reset_tokens_per_hour(),
            },
            observability: ObservabilityConfig {
                log_level: default_log_level(),
                metrics_enabled: default_metrics_enabled(),
                tracing_enabled: default_tracing_enabled(),
                otlp_endpoint: None,
            },
            id_generation: IdGenerationConfig {
                worker_id: 0,
                max_clock_skew_ms: default_max_clock_skew_ms(),
            },
            server_api: ServerApiConfig {
                grpc_endpoint: "http://localhost:8080".to_string(),
                tls_enabled: false,
            },
            frontend_base_url: default_frontend_base_url(),
        };

        // Valid worker ID
        assert!(config.validate().is_ok());

        // Invalid worker ID
        config.id_generation.worker_id = 1024;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_storage_backend_validation() {
        let mut config = ManagementConfig {
            server: ServerConfig {
                http_host: default_http_host(),
                http_port: default_http_port(),
                grpc_host: default_grpc_host(),
                grpc_port: default_grpc_port(),
                worker_threads: default_worker_threads(),
            },
            storage: StorageConfig {
                backend: "invalid".to_string(),
                fdb_cluster_file: None,
            },
            auth: AuthConfig {
                session_ttl_web: default_session_ttl_web(),
                session_ttl_cli: default_session_ttl_cli(),
                session_ttl_sdk: default_session_ttl_sdk(),
                password_min_length: default_password_min_length(),
                max_sessions_per_user: default_max_sessions_per_user(),
                webauthn: WebAuthnConfig {
                    rp_id: "localhost".to_string(),
                    rp_name: default_rp_name(),
                    origin: "http://localhost:3000".to_string(),
                },
                key_encryption_secret: Some("test-secret".to_string()),
                jwt_issuer: default_jwt_issuer(),
                jwt_audience: default_jwt_audience(),
            },
            email: EmailConfig {
                smtp_host: "localhost".to_string(),
                smtp_port: default_smtp_port(),
                smtp_username: None,
                smtp_password: None,
                from_email: "noreply@inferadb.com".to_string(),
                from_name: default_from_name(),
            },
            rate_limiting: RateLimitingConfig {
                login_attempts_per_ip_per_hour: default_login_attempts_per_ip_per_hour(),
                registrations_per_ip_per_day: default_registrations_per_ip_per_day(),
                email_verification_tokens_per_hour: default_email_verification_tokens_per_hour(),
                password_reset_tokens_per_hour: default_password_reset_tokens_per_hour(),
            },
            observability: ObservabilityConfig {
                log_level: default_log_level(),
                metrics_enabled: default_metrics_enabled(),
                tracing_enabled: default_tracing_enabled(),
                otlp_endpoint: None,
            },
            id_generation: IdGenerationConfig {
                worker_id: 0,
                max_clock_skew_ms: default_max_clock_skew_ms(),
            },
            server_api: ServerApiConfig {
                grpc_endpoint: "http://localhost:8080".to_string(),
                tls_enabled: false,
            },
            frontend_base_url: default_frontend_base_url(),
        };

        // Invalid storage backend
        assert!(config.validate().is_err());

        // Valid backends
        config.storage.backend = "memory".to_string();
        assert!(config.validate().is_ok());

        config.storage.backend = "foundationdb".to_string();
        config.storage.fdb_cluster_file = Some("/path/to/fdb.cluster".to_string());
        assert!(config.validate().is_ok());
    }
}
