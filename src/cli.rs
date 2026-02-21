use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "permitd")]
#[command(about = "OIDC Authorization Gateway Powered by Cedar")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the gateway server
    Serve {
        /// Path to config.toml
        #[arg(long, default_value = "/etc/permitd/config.toml")]
        config: String,
    },
    /// Validate Cedar schema and policies without starting
    Validate {
        /// Path to Cedar schema file
        #[arg(long)]
        schema: String,
        /// Path to policies directory
        #[arg(long)]
        policies: String,
        /// Path to routes mapping file
        #[arg(long)]
        routes: Option<String>,
    },
    /// Dry-run an authorization check against loaded policies
    Check {
        /// Path to config.toml
        #[arg(long, default_value = "/etc/permitd/config.toml")]
        config: String,
        /// Principal identifier (e.g., "myorg/payments-service")
        #[arg(long)]
        principal: String,
        /// Cedar action (e.g., "containers:create")
        #[arg(long)]
        action: String,
        /// Resource identifier (e.g., "payments-api")
        #[arg(long)]
        resource: String,
        /// Resource type (e.g., "Container")
        #[arg(long, default_value = "Container")]
        resource_type: String,
        /// Git ref
        #[arg(long, default_value = "refs/heads/main")]
        git_ref: String,
        /// Repository owner (extracted from principal if not provided)
        #[arg(long)]
        owner: Option<String>,
    },
    /// List all configured route mappings
    Routes {
        /// Path to routes.toml
        #[arg(long)]
        mapping: String,
        /// Output format: "table" or "json"
        #[arg(long, default_value = "table")]
        format: String,
    },
}
