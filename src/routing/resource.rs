use std::collections::HashMap;

pub fn extract_resource(
    resource_from: &str,
    path_params: &HashMap<String, String>,
    query_string: &str,
    _body: &str,
) -> String {
    if resource_from == "wildcard" {
        return "*".to_string();
    }
    if let Some(param) = resource_from.strip_prefix("path:") {
        return path_params
            .get(param)
            .cloned()
            .unwrap_or_else(|| "*".to_string());
    }
    if let Some(param) = resource_from.strip_prefix("query:") {
        for pair in query_string.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if key == param {
                    return value.to_string();
                }
            }
        }
        return "*".to_string();
    }
    if let Some(value) = resource_from.strip_prefix("static:") {
        return value.to_string();
    }
    "*".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_path() {
        let mut p = HashMap::new();
        p.insert("id".to_string(), "my-container".to_string());
        assert_eq!(extract_resource("path:id", &p, "", ""), "my-container");
    }

    #[test]
    fn test_extract_query() {
        assert_eq!(
            extract_resource(
                "query:reference",
                &HashMap::new(),
                "reference=ghcr.io/myorg/app:latest&other=val",
                ""
            ),
            "ghcr.io/myorg/app:latest"
        );
    }

    #[test]
    fn test_extract_wildcard() {
        assert_eq!(extract_resource("wildcard", &HashMap::new(), "", ""), "*");
    }

    #[test]
    fn test_extract_static() {
        assert_eq!(
            extract_resource("static:system", &HashMap::new(), "", ""),
            "system"
        );
    }
}
