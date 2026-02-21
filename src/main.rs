mod cedar;
mod cli;
mod config;
mod error;
mod jwt;
mod proxy;
mod routing;
mod server;

use axum::{routing::get, Router};
use clap::Parser;
use cli::{Cli, Commands};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Serve { config: config_path } => {
            if let Err(e) = serve(&config_path).await {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Validate {
            schema,
            policies,
            routes,
        } => {
            if let Err(e) = validate(&schema, &policies, routes.as_deref()) {
                eprintln!("Validation failed: {}", e);
                std::process::exit(1);
            }
            println!("Validation passed.");
        }
        Commands::Check {
            config: config_path,
            principal,
            action,
            resource,
            resource_type,
            git_ref,
            owner,
        } => {
            if let Err(e) = check(
                &config_path,
                &principal,
                &action,
                &resource,
                &resource_type,
                &git_ref,
                owner.as_deref(),
            ) {
                eprintln!("Check failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Routes { mapping, format } => {
            if let Err(e) = list_routes(&mapping, &format) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

async fn serve(config_path: &str) -> Result<(), error::AppError> {
    let config = config::AppConfig::load(config_path)?;
    init_logging(&config.logging);

    tracing::info!("Loading Cedar schema and policies...");
    let cedar_engine =
        cedar::engine::CedarEngine::load(&config.cedar.schema_path, &config.cedar.policy_dir)?;

    tracing::info!("Loading route mappings...");
    let route_mapping = routing::mapping::RouteMapping::load(&config.routes.mapping_file)?;
    let route_matcher = routing::matcher::RouteMatcher::new(route_mapping.routes);

    tracing::info!("Initializing JWKS cache...");
    let jwks_cache =
        jwt::jwks::JwksCache::new(&config.oidc.issuer, config.oidc.jwks_cache_ttl_secs);
    let jwt_validator = jwt::validation::JwtValidator::new(
        jwks_cache,
        config.oidc.issuer.clone(),
        config.oidc.audience.clone(),
    );

    let proxy = proxy::upstream::UnixSocketProxy::new(config.upstream.socket_path.clone());

    let state = Arc::new(server::handler::AppState {
        jwt_validator,
        cedar_engine,
        route_matcher,
        proxy,
        log_authorized: config.logging.log_authorized,
        log_denied: config.logging.log_denied,
    });

    let app = Router::new()
        .route("/healthz", get(server::handler::health_check))
        .route("/readyz", get(server::handler::health_check))
        .fallback(server::handler::handle_request)
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&config.server.listen_addr)
        .await
        .map_err(|e| {
            error::AppError::Config(format!(
                "Failed to bind {}: {}",
                config.server.listen_addr, e
            ))
        })?;

    tracing::info!("permitd listening on {}", config.server.listen_addr);
    axum::serve(listener, app).await.map_err(error::AppError::Io)
}

fn validate(
    schema_path: &str,
    policy_dir: &str,
    routes_path: Option<&str>,
) -> Result<(), error::AppError> {
    cedar::engine::CedarEngine::load(schema_path, policy_dir)?;
    println!("Cedar schema and policies: OK");
    if let Some(routes) = routes_path {
        routing::mapping::RouteMapping::load(routes)?;
        println!("Route mapping: OK");
    }
    Ok(())
}

fn check(
    config_path: &str,
    principal: &str,
    action: &str,
    resource: &str,
    resource_type: &str,
    git_ref: &str,
    owner: Option<&str>,
) -> Result<(), error::AppError> {
    let config = config::AppConfig::load(config_path)?;
    let engine =
        cedar::engine::CedarEngine::load(&config.cedar.schema_path, &config.cedar.policy_dir)?;
    let owner = owner.unwrap_or_else(|| principal.split('/').next().unwrap_or(principal));
    let claims = jwt::claims::GitHubClaims {
        sub: format!("repo:{}:ref:{}", principal, git_ref),
        repository: principal.to_string(),
        repository_owner: owner.to_string(),
        repository_owner_id: "0".to_string(),
        git_ref: git_ref.to_string(),
        workflow: "check".to_string(),
        job_workflow_ref: format!(
            "{}/.github/workflows/check.yml@{}",
            principal, git_ref
        ),
        actor: "permitd-check".to_string(),
        environment: None,
        runner_environment: "self-hosted".to_string(),
        iss: String::new(),
        aud: String::new(),
        exp: 0,
        nbf: 0,
        iat: 0,
    };
    match cedar::eval::evaluate(&engine, &claims, action, resource_type, resource) {
        Ok(()) => {
            println!(
                "ALLOW: {} -> {} on {}::{}",
                principal, action, resource_type, resource
            );
            Ok(())
        }
        Err(error::AppError::Forbidden) => {
            println!(
                "DENY: {} -> {} on {}::{}",
                principal, action, resource_type, resource
            );
            std::process::exit(1);
        }
        Err(e) => Err(e),
    }
}

fn list_routes(mapping_path: &str, format: &str) -> Result<(), error::AppError> {
    let mapping = routing::mapping::RouteMapping::load(mapping_path)?;
    match format {
        "json" => println!(
            "{}",
            serde_json::to_string_pretty(&mapping.routes)
                .map_err(|e| error::AppError::Config(e.to_string()))?
        ),
        _ => {
            println!(
                "{:<8} {:<50} {:<25} {:<12} {}",
                "METHOD", "PATTERN", "ACTION", "RESOURCE", "EXTRACT"
            );
            println!("{}", "-".repeat(110));
            for r in &mapping.routes {
                println!(
                    "{:<8} {:<50} {:<25} {:<12} {}",
                    r.method, r.path_pattern, r.action, r.resource_type, r.resource_from
                );
            }
        }
    }
    Ok(())
}

fn init_logging(config: &config::LoggingConfig) {
    use tracing_subscriber::EnvFilter;
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));
    match config.format.as_str() {
        "json" => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
        _ => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }
}
