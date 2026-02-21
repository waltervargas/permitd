use std::collections::HashMap;

use crate::routing::mapping::RouteConfig;

pub struct RouteMatcher {
    routes: Vec<RouteConfig>,
}

pub struct RouteMatch {
    pub action: String,
    pub resource_type: String,
    pub resource_from: String,
    pub params: HashMap<String, String>,
}

impl RouteMatcher {
    pub fn new(routes: Vec<RouteConfig>) -> Self {
        Self { routes }
    }

    pub fn match_request(&self, method: &str, path: &str) -> Option<RouteMatch> {
        for route in &self.routes {
            if !route.method.eq_ignore_ascii_case(method) {
                continue;
            }
            if let Some(params) = Self::match_pattern(&route.path_pattern, path) {
                return Some(RouteMatch {
                    action: route.action.clone(),
                    resource_type: route.resource_type.clone(),
                    resource_from: route.resource_from.clone(),
                    params,
                });
            }
        }
        None
    }

    fn match_pattern(pattern: &str, path: &str) -> Option<HashMap<String, String>> {
        let pat_segs: Vec<&str> = pattern.trim_matches('/').split('/').collect();
        let path_segs: Vec<&str> = path.trim_matches('/').split('/').collect();
        if pat_segs.len() != path_segs.len() {
            return None;
        }
        let mut params = HashMap::new();
        for (pat, seg) in pat_segs.iter().zip(path_segs.iter()) {
            if pat.starts_with('{') && pat.ends_with('}') {
                params.insert(pat[1..pat.len() - 1].to_string(), seg.to_string());
            } else if pat.contains('{') && pat.contains('}') {
                let prefix_end = pat.find('{')?;
                let prefix = &pat[..prefix_end];
                let param_name = &pat[prefix_end + 1..pat.find('}')?];
                if !seg.starts_with(prefix) {
                    return None;
                }
                params.insert(param_name.to_string(), seg[prefix.len()..].to_string());
            } else if pat != seg {
                return None;
            }
        }
        Some(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::mapping::RouteConfig;

    fn route(method: &str, pattern: &str, action: &str) -> RouteConfig {
        RouteConfig {
            method: method.into(),
            path_pattern: pattern.into(),
            action: action.into(),
            resource_type: "Container".into(),
            resource_from: "path:id".into(),
        }
    }

    #[test]
    fn test_match_version_and_id() {
        let m = RouteMatcher::new(vec![route(
            "POST",
            "/v{version}/libpod/containers/{id}/start",
            "containers:start",
        )]);
        let r = m
            .match_request("POST", "/v4.0.0/libpod/containers/mycontainer/start")
            .unwrap();
        assert_eq!(r.action, "containers:start");
        assert_eq!(r.params["id"], "mycontainer");
    }

    #[test]
    fn test_no_match_wrong_method() {
        let m = RouteMatcher::new(vec![route(
            "POST",
            "/v{version}/libpod/containers/{id}/start",
            "containers:start",
        )]);
        assert!(m
            .match_request("GET", "/v4.0.0/libpod/containers/mycontainer/start")
            .is_none());
    }

    #[test]
    fn test_version_formats() {
        let m = RouteMatcher::new(vec![route("GET", "/v{version}/test", "test")]);
        assert!(m.match_request("GET", "/v1/test").is_some());
        assert!(m.match_request("GET", "/v4.0.0/test").is_some());
    }
}
