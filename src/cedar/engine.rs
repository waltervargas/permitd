use cedar_policy::{Authorizer, PolicySet, Schema};

use crate::error::AppError;

pub struct CedarEngine {
    pub authorizer: Authorizer,
    pub policy_set: PolicySet,
    pub schema: Option<Schema>,
}

impl CedarEngine {
    pub fn from_str(schema_str: &str, policies_str: &str) -> Result<Self, AppError> {
        let (schema, _warnings) = Schema::from_cedarschema_str(schema_str)
            .map_err(|e| AppError::CedarSchema(format!("{}", e)))?;
        let policy_set: PolicySet = policies_str
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| AppError::CedarPolicy(format!("{}", e)))?;
        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set,
            schema: Some(schema),
        })
    }

    pub fn load(schema_path: &str, policy_dir: &str) -> Result<Self, AppError> {
        let schema_str = std::fs::read_to_string(schema_path)
            .map_err(|e| AppError::CedarSchema(format!("Failed to read schema: {}", e)))?;
        let mut all_policies = String::new();
        for entry in std::fs::read_dir(policy_dir)
            .map_err(|e| AppError::CedarPolicy(format!("Failed to read policy dir: {}", e)))?
        {
            let entry = entry.map_err(|e| AppError::CedarPolicy(e.to_string()))?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "cedar") {
                let content = std::fs::read_to_string(&path).map_err(|e| {
                    AppError::CedarPolicy(format!("Failed to read {}: {}", path.display(), e))
                })?;
                all_policies.push_str(&content);
                all_policies.push('\n');
            }
        }
        Self::from_str(&schema_str, &all_policies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_schema() {
        let schema_str = include_str!("../../schema.cedarschema");
        let engine = CedarEngine::from_str(schema_str, "").unwrap();
        assert!(engine.schema.is_some());
    }

    #[test]
    fn test_load_policy() {
        let schema_str = include_str!("../../schema.cedarschema");
        let policy_str = r#"permit(principal is Permitd::Workflow, action == Permitd::Action::"containers:list", resource) when { principal.repository_owner == "myorg" };"#;
        let engine = CedarEngine::from_str(schema_str, policy_str).unwrap();
        assert!(engine.policy_set.policies().count() > 0);
    }
}
