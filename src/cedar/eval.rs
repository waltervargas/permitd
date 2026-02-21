use cedar_policy::{Context, Decision, EntityId, EntityTypeName, EntityUid, Request};
use std::str::FromStr;

use crate::cedar::engine::CedarEngine;
use crate::cedar::entities::build_entities;
use crate::error::AppError;
use crate::jwt::claims::GitHubClaims;

pub fn evaluate(
    engine: &CedarEngine,
    claims: &GitHubClaims,
    action: &str,
    resource_type: &str,
    resource_id: &str,
) -> Result<(), AppError> {
    let (principal_uid, entities) = build_entities(claims, resource_type, resource_id)?;

    let action_type: EntityTypeName = EntityTypeName::from_str("Permitd::Action")
        .map_err(|e| AppError::CedarPolicy(format!("Invalid action type: {}", e)))?;
    let action_eid = EntityId::from_str(action)
        .map_err(|e| AppError::CedarPolicy(format!("Invalid action id: {}", e)))?;
    let action_uid = EntityUid::from_type_name_and_id(action_type, action_eid);

    let resource_type_name: EntityTypeName =
        EntityTypeName::from_str(&format!("Permitd::{}", resource_type))
            .map_err(|e| AppError::CedarPolicy(format!("Invalid resource type: {}", e)))?;
    let resource_eid = EntityId::from_str(resource_id)
        .map_err(|e| AppError::CedarPolicy(format!("Invalid resource id: {}", e)))?;
    let resource_uid = EntityUid::from_type_name_and_id(resource_type_name, resource_eid);

    let context = Context::empty();
    let request = Request::new(
        principal_uid,
        action_uid,
        resource_uid,
        context,
        engine.schema.as_ref(),
    )
    .map_err(|e| AppError::CedarPolicy(format!("Invalid request: {}", e)))?;

    let response = engine
        .authorizer
        .is_authorized(&request, &engine.policy_set, &entities);
    match response.decision() {
        Decision::Allow => Ok(()),
        Decision::Deny => {
            tracing::warn!(
                principal = %claims.repository,
                action = %action,
                resource_type = %resource_type,
                resource_id = %resource_id,
                "Authorization denied"
            );
            Err(AppError::Forbidden)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cedar::engine::CedarEngine;

    fn sample_claims(repo: &str, git_ref: &str) -> GitHubClaims {
        serde_json::from_value(serde_json::json!({
            "sub": format!("repo:{}:ref:{}", repo, git_ref),
            "repository": repo,
            "repository_owner": repo.split('/').next().unwrap(),
            "repository_owner_id": "12345",
            "ref": git_ref,
            "workflow": "deploy.yml",
            "job_workflow_ref": format!("{}/.github/workflows/deploy.yml@{}", repo, git_ref),
            "actor": "username",
            "runner_environment": "github-hosted",
            "iss": "https://token.actions.githubusercontent.com",
            "aud": "permitd",
            "exp": 1700000000u64,
            "nbf": 1699999000u64,
            "iat": 1699999000u64
        }))
        .unwrap()
    }

    #[test]
    fn test_permit_matching_policy() {
        let schema = include_str!("../../schema.cedarschema");
        let policy = r#"permit(principal is Permitd::Workflow, action == Permitd::Action::"containers:list", resource) when { principal.repository_owner == "myorg" };"#;
        let engine = CedarEngine::from_str(schema, policy).unwrap();
        let result = evaluate(
            &engine,
            &sample_claims("myorg/app", "refs/heads/main"),
            "containers:list",
            "Container",
            "*",
        );
        assert!(result.is_ok(), "Expected permit, got: {:?}", result);
    }

    #[test]
    fn test_deny_no_matching_policy() {
        let schema = include_str!("../../schema.cedarschema");
        let policy = r#"permit(principal is Permitd::Workflow, action == Permitd::Action::"containers:list", resource) when { principal.repository_owner == "myorg" };"#;
        let engine = CedarEngine::from_str(schema, policy).unwrap();
        let result = evaluate(
            &engine,
            &sample_claims("otherorg/app", "refs/heads/main"),
            "containers:list",
            "Container",
            "*",
        );
        assert!(result.is_err());
    }
}
