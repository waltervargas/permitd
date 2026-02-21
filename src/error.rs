use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("JWKS fetch error: {0}")]
    JwksFetch(String),

    #[error("Cedar schema error: {0}")]
    CedarSchema(String),

    #[error("Cedar policy error: {0}")]
    CedarPolicy(String),

    #[error("Authorization denied")]
    Forbidden,

    #[error("Missing or invalid Authorization header")]
    Unauthorized,

    #[error("No matching route for request")]
    NoRouteMatch,

    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("Route mapping error: {0}")]
    RouteMapping(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden | AppError::NoRouteMatch => StatusCode::FORBIDDEN,
            AppError::Proxy(_) => StatusCode::BAD_GATEWAY,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = serde_json::json!({
            "error": status.as_str(),
            "message": match &self {
                AppError::Forbidden | AppError::NoRouteMatch => "Access denied".to_string(),
                AppError::Unauthorized => "Missing or invalid authorization".to_string(),
                other => other.to_string(),
            }
        });

        (status, axum::Json(body)).into_response()
    }
}
