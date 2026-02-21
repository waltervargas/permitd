use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Debug, Deserialize)]
pub struct RouteMapping {
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RouteConfig {
    pub method: String,
    pub path_pattern: String,
    pub action: String,
    pub resource_type: String,
    pub resource_from: String,
}

impl RouteMapping {
    pub fn load(path: &str) -> Result<Self, AppError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AppError::RouteMapping(format!("Failed to read {}: {}", path, e)))?;
        toml::from_str(&content)
            .map_err(|e| AppError::RouteMapping(format!("Failed to parse routes: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_routes_toml() {
        let toml_str = r#"
[[routes]]
method = "POST"
path_pattern = "/v{version}/libpod/containers/create"
action = "containers:create"
resource_type = "Container"
resource_from = "wildcard"

[[routes]]
method = "POST"
path_pattern = "/v{version}/libpod/containers/{id}/start"
action = "containers:start"
resource_type = "Container"
resource_from = "path:id"
"#;
        let mapping: RouteMapping = toml::from_str(toml_str).unwrap();
        assert_eq!(mapping.routes.len(), 2);
        assert_eq!(mapping.routes[0].action, "containers:create");
        assert_eq!(mapping.routes[1].resource_from, "path:id");
    }
}
