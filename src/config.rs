use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub oidc: OidcConfig,
    pub cedar: CedarConfig,
    pub routes: RoutesConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
}

fn default_listen_addr() -> String { "0.0.0.0:8080".to_string() }

#[derive(Debug, Deserialize)]
pub struct UpstreamConfig {
    pub socket_path: String,
}

#[derive(Debug, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    #[serde(default = "default_audience")]
    pub audience: String,
    #[serde(default = "default_jwks_ttl")]
    pub jwks_cache_ttl_secs: u64,
}

fn default_audience() -> String { "permitd".to_string() }
fn default_jwks_ttl() -> u64 { 3600 }

#[derive(Debug, Deserialize)]
pub struct CedarConfig {
    pub schema_path: String,
    pub policy_dir: String,
}

#[derive(Debug, Deserialize)]
pub struct RoutesConfig {
    pub mapping_file: String,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_true")]
    pub log_authorized: bool,
    #[serde(default = "default_true")]
    pub log_denied: bool,
    #[serde(default)]
    pub log_jwt_claims: bool,
}

fn default_log_format() -> String { "json".to_string() }
fn default_log_level() -> String { "info".to_string() }
fn default_true() -> bool { true }

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: default_log_format(),
            level: default_log_level(),
            log_authorized: true,
            log_denied: true,
            log_jwt_claims: false,
        }
    }
}

impl AppConfig {
    pub fn load(path: &str) -> Result<Self, crate::error::AppError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::AppError::Config(format!("Failed to read {}: {}", path, e)))?;
        toml::from_str(&content)
            .map_err(|e| crate::error::AppError::Config(format!("Failed to parse config: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let toml_str = r#"
[server]
listen_addr = "0.0.0.0:8080"

[upstream]
socket_path = "/run/podman/podman.sock"

[oidc]
issuer = "https://token.actions.githubusercontent.com"
audience = "permitd"
jwks_cache_ttl_secs = 3600

[cedar]
schema_path = "/etc/permitd/schema.cedarschema"
policy_dir = "/etc/permitd/policies/"

[routes]
mapping_file = "/etc/permitd/routes.toml"

[logging]
format = "json"
level = "info"
log_authorized = true
log_denied = true
log_jwt_claims = false
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.listen_addr, "0.0.0.0:8080");
        assert_eq!(config.upstream.socket_path, "/run/podman/podman.sock");
        assert_eq!(config.oidc.issuer, "https://token.actions.githubusercontent.com");
        assert_eq!(config.oidc.audience, "permitd");
        assert_eq!(config.cedar.schema_path, "/etc/permitd/schema.cedarschema");
        assert_eq!(config.routes.mapping_file, "/etc/permitd/routes.toml");
        assert_eq!(config.logging.format, "json");
    }
}
