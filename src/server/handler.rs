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
    pub log_jwt_claims: bool,
}

pub async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub async fn handle_request(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response<Body>, AppError> {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let headers: Vec<String> = req
        .headers()
        .iter()
        .filter(|(name, _)| *name != "authorization")
        .map(|(name, value)| {
            format!("{}: {}", name, value.to_str().unwrap_or("<non-utf8>"))
        })
        .collect();
    let has_auth = req.headers().contains_key("authorization");

    tracing::debug!(
        method = %method,
        path = %path,
        query = %query,
        headers = ?headers,
        has_authorization = has_auth,
        "Incoming request"
    );

    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let token = match token {
        Some(t) => t,
        None => {
            tracing::warn!(
                method = %method,
                path = %path,
                headers = ?headers,
                has_authorization = has_auth,
                "Unauthorized: missing or malformed Authorization header"
            );
            return Err(AppError::Unauthorized);
        }
    };
    let claims = match state.jwt_validator.validate(token).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                method = %method,
                path = %path,
                headers = ?headers,
                error = %e,
                "Unauthorized: JWT validation failed"
            );
            return Err(AppError::Unauthorized);
        }
    };

    if state.log_jwt_claims {
        tracing::debug!(claims = ?claims, "JWT claims");
    }

    let route_match = match state.route_matcher.match_request(&method, &path) {
        Some(m) => m,
        None => {
            tracing::warn!(
                method = %method,
                path = %path,
                principal = %claims.repository,
                actor = %claims.actor,
                "No matching route for request"
            );
            return Err(AppError::NoRouteMatch);
        }
    };
    let resource_id = extract_resource(&route_match.resource_from, &route_match.params, &query, "");

    eval::evaluate(
        &state.cedar_engine,
        &claims,
        &route_match.action,
        &route_match.resource_type,
        &resource_id,
        state.log_denied,
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
    let (resp_parts, body) = resp.into_parts();

    let upstream_status = resp_parts.status;
    if upstream_status.is_server_error() || upstream_status.is_client_error() {
        tracing::warn!(
            method = %method,
            path = %path,
            principal = %claims.repository,
            actor = %claims.actor,
            action = %route_match.action,
            upstream_status = %upstream_status,
            "Upstream returned error"
        );
    } else {
        tracing::debug!(
            method = %method,
            path = %path,
            action = %route_match.action,
            upstream_status = %upstream_status,
            "Upstream response"
        );
    }

    Ok(Response::from_parts(resp_parts, Body::new(body)))
}
