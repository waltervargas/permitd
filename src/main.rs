mod cli;
mod config;
mod error;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Serve { config } => {
            eprintln!("serve: config={}", config);
            todo!("serve command")
        }
        Commands::Validate { schema, policies, routes } => {
            eprintln!("validate: schema={} policies={} routes={:?}", schema, policies, routes);
            todo!("validate command")
        }
        Commands::Check { config, principal, action, resource, .. } => {
            eprintln!("check: principal={} action={} resource={}", principal, action, resource);
            todo!("check command")
        }
        Commands::Routes { mapping, format } => {
            eprintln!("routes: mapping={} format={}", mapping, format);
            todo!("routes command")
        }
    }
}
