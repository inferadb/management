use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "inferadb-management")]
#[command(about = "InferaDB Management API - Control Plane for InferaDB", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, env = "LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(&args.log_level)
        .init();

    tracing::info!("Starting InferaDB Management API");
    tracing::info!("Configuration file: {}", args.config);

    // TODO: Load configuration
    // TODO: Initialize storage
    // TODO: Start HTTP server
    // TODO: Start gRPC server

    tracing::info!("Management API started successfully");

    // Keep running until interrupted
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down gracefully");

    Ok(())
}
