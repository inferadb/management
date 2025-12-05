//! Startup display utilities for InferaDB services
//!
//! Provides consistent, structured startup output across all InferaDB binaries.
//! Includes banner display and configuration summary formatting.

use std::io::IsTerminal;

/// Service information for the startup banner
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// Service name (e.g., "InferaDB Management API")
    pub name: &'static str,
    /// Version string
    pub version: &'static str,
    /// Environment (development, staging, production)
    pub environment: String,
}

/// A single configuration entry for display
#[derive(Debug, Clone)]
pub struct ConfigEntry {
    /// Category/group name
    pub category: &'static str,
    /// Configuration key
    pub key: &'static str,
    /// Configuration value (already formatted as string)
    pub value: String,
    /// Whether this is a sensitive value that should be masked
    pub sensitive: bool,
}

impl ConfigEntry {
    /// Create a new configuration entry
    pub fn new(category: &'static str, key: &'static str, value: impl ToString) -> Self {
        Self { category, key, value: value.to_string(), sensitive: false }
    }

    /// Create a sensitive configuration entry (value will be masked)
    pub fn sensitive(category: &'static str, key: &'static str, value: impl ToString) -> Self {
        Self { category, key, value: value.to_string(), sensitive: true }
    }

    /// Mark an entry as sensitive
    pub fn as_sensitive(mut self) -> Self {
        self.sensitive = true;
        self
    }
}

/// Builder for creating a structured startup display
pub struct StartupDisplay {
    service: ServiceInfo,
    entries: Vec<ConfigEntry>,
    use_ansi: bool,
}

impl StartupDisplay {
    /// Create a new startup display builder
    pub fn new(service: ServiceInfo) -> Self {
        Self { service, entries: Vec::new(), use_ansi: std::io::stdout().is_terminal() }
    }

    /// Set whether to use ANSI colors
    pub fn with_ansi(mut self, use_ansi: bool) -> Self {
        self.use_ansi = use_ansi;
        self
    }

    /// Add a configuration entry
    pub fn entry(mut self, entry: ConfigEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Add multiple configuration entries
    pub fn entries(mut self, entries: impl IntoIterator<Item = ConfigEntry>) -> Self {
        self.entries.extend(entries);
        self
    }

    /// Display the startup banner and configuration summary
    pub fn display(&self) {
        self.print_banner();
        self.print_config_summary();
    }

    fn print_banner(&self) {
        let (dim, reset, bold, cyan) = if self.use_ansi {
            ("\x1b[2m", "\x1b[0m", "\x1b[1m", "\x1b[36m")
        } else {
            ("", "", "", "")
        };

        // Simple, clean banner
        println!();
        println!("{dim}┌─────────────────────────────────────────────────────────────┐{reset}");
        println!(
            "{dim}│{reset}  {bold}{cyan}{name:^55}{reset}  {dim}│{reset}",
            name = self.service.name
        );
        println!(
            "{dim}│{reset}  {version:^55}  {dim}│{reset}",
            version = format!("v{}", self.service.version)
        );
        println!("{dim}└─────────────────────────────────────────────────────────────┘{reset}");
        println!();
    }

    fn print_config_summary(&self) {
        if self.entries.is_empty() {
            return;
        }

        let (dim, reset, bold, green, yellow) = if self.use_ansi {
            ("\x1b[2m", "\x1b[0m", "\x1b[1m", "\x1b[32m", "\x1b[33m")
        } else {
            ("", "", "", "", "")
        };

        // Group entries by category
        let mut categories: Vec<(&str, Vec<&ConfigEntry>)> = Vec::new();
        for entry in &self.entries {
            if let Some((_, entries)) =
                categories.iter_mut().find(|(cat, _)| *cat == entry.category)
            {
                entries.push(entry);
            } else {
                categories.push((entry.category, vec![entry]));
            }
        }

        // Calculate column width for alignment
        let max_key_len = self.entries.iter().map(|e| e.key.len()).max().unwrap_or(20).max(20);

        println!("{bold}Configuration:{reset}");
        println!();

        for (category, entries) in categories {
            println!("  {dim}[{category}]{reset}");
            for entry in entries {
                let display_value = if entry.sensitive {
                    format!("{yellow}********{reset}")
                } else {
                    format!("{green}{}{reset}", entry.value)
                };
                println!(
                    "    {key:<width$}  {value}",
                    key = entry.key,
                    width = max_key_len,
                    value = display_value
                );
            }
            println!();
        }
    }
}

/// Log a startup phase header
///
/// Use this to clearly delineate initialization phases in the logs.
pub fn log_phase(phase: &str) {
    tracing::info!("");
    tracing::info!("━━━ {} ━━━", phase);
}

/// Log a successful initialization step
pub fn log_initialized(component: &str) {
    tracing::info!("✓ {} initialized", component);
}

/// Log a skipped initialization step
pub fn log_skipped(component: &str, reason: &str) {
    tracing::info!("○ {} skipped: {}", component, reason);
}

/// Log that the service is ready to accept connections
pub fn log_ready(service: &str, addresses: &[(&str, &str)]) {
    tracing::info!("");
    tracing::info!("━━━ {} Ready ━━━", service);
    for (name, addr) in addresses {
        tracing::info!("  {} → {}", name, addr);
    }
    tracing::info!("");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_entry_creation() {
        let entry = ConfigEntry::new("Server", "port", 8080);
        assert_eq!(entry.category, "Server");
        assert_eq!(entry.key, "port");
        assert_eq!(entry.value, "8080");
        assert!(!entry.sensitive);
    }

    #[test]
    fn test_sensitive_entry() {
        let entry = ConfigEntry::sensitive("Auth", "secret", "my-secret");
        assert!(entry.sensitive);

        let entry2 = ConfigEntry::new("Auth", "key", "value").as_sensitive();
        assert!(entry2.sensitive);
    }

    #[test]
    fn test_startup_display_builder() {
        let service =
            ServiceInfo { name: "Test Service", version: "0.1.0", environment: "test".to_string() };

        let display = StartupDisplay::new(service)
            .with_ansi(false)
            .entry(ConfigEntry::new("Server", "host", "0.0.0.0"))
            .entry(ConfigEntry::new("Server", "port", 8080));

        assert_eq!(display.entries.len(), 2);
        assert!(!display.use_ansi);
    }

    #[test]
    fn test_startup_display_entries_batch() {
        let service =
            ServiceInfo { name: "Test Service", version: "0.1.0", environment: "test".to_string() };

        let entries = vec![
            ConfigEntry::new("Server", "host", "0.0.0.0"),
            ConfigEntry::new("Server", "port", 8080),
            ConfigEntry::new("Storage", "backend", "memory"),
        ];

        let display = StartupDisplay::new(service).entries(entries);

        assert_eq!(display.entries.len(), 3);
    }
}
