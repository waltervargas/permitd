use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use std::sync::Arc;

use crate::cedar::eval;
use crate::error::AppError;
use crate::jwt::validation::JwtValidator;
use crate::proxy::upstream::UnixSocketProxy;
use crate::routing::matcher::RouteMatcher;
use crate::routing::resource::extract_resource;

pub struct AppState {
    pub jwt_validator: JwtValidator,
    pub cedar_engine: crate::cedar::engine::CedarEngine,
    pub route_matcher: RouteMatcher,
    pub proxy: UnixSocketProxy,
    pub log_authorized: bool,
    pub log_denied: bool,
}

pub async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub async fn handle_request(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response<Body>, AppError> {
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;
    let claims = state.jwt_validator.validate(token).await?;

    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    let route_match = state
        .route_matcher
        .match_request(&method, &path)
        .ok_or(AppError::NoRouteMatch)?;
    let resource_id = extract_resource(&route_match.resource_from, &route_match.params, &query, "");

    eval::evaluate(
        &state.cedar_engine,
        &claims,
        &route_match.action,
        &route_match.resource_type,
        &resource_id,
    )?;

    if state.log_authorized {
        tracing::info!(
            principal = %claims.repository,
            action = %route_match.action,
            resource_type = %route_match.resource_type,
            resource_id = %resource_id,
            "Request authorized"
        );
    }

    let (mut parts, body) = req.into_parts();
    parts.headers.remove("authorization");

    let body_bytes = body
        .collect()
        .await
        .map_err(|e| AppError::Proxy(format!("Failed to read body: {}", e)))?
        .to_bytes();
    let upstream_body: BoxBody<Bytes, hyper::Error> =
        BoxBody::new(http_body_util::Full::new(body_bytes).map_err(|never| match never {}));
    let upstream_req = hyper::Request::from_parts(parts, upstream_body);
    let resp = state.proxy.forward(upstream_req).await?;
    let (parts, body) = resp.into_parts();
    Ok(Response::from_parts(parts, Body::new(body)))
}
