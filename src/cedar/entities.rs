use cedar_policy::{
    Entities, Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use crate::error::AppError;
use crate::jwt::claims::GitHubClaims;

pub fn build_entities(
    claims: &GitHubClaims,
    resource_type: &str,
    resource_id: &str,
) -> Result<(EntityUid, Entities), AppError> {
    let principal_type: EntityTypeName = EntityTypeName::from_str("Permitd::Workflow")
        .map_err(|e| AppError::CedarPolicy(format!("Invalid principal type: {}", e)))?;
    let principal_eid = EntityId::from_str(&claims.repository)
        .map_err(|e| AppError::CedarPolicy(format!("Invalid principal id: {}", e)))?;
    let principal_uid = EntityUid::from_type_name_and_id(principal_type, principal_eid);

    let mut attrs = HashMap::new();
    attrs.insert(
        "repository".to_string(),
        RestrictedExpression::new_string(claims.repository.clone()),
    );
    attrs.insert(
        "repository_owner".to_string(),
        RestrictedExpression::new_string(claims.repository_owner.clone()),
    );
    attrs.insert(
        "ref".to_string(),
        RestrictedExpression::new_string(claims.git_ref.clone()),
    );
    attrs.insert(
        "workflow_ref".to_string(),
        RestrictedExpression::new_string(claims.job_workflow_ref.clone()),
    );
    attrs.insert(
        "actor".to_string(),
        RestrictedExpression::new_string(claims.actor.clone()),
    );
    attrs.insert(
        "environment".to_string(),
        RestrictedExpression::new_string(claims.environment.clone().unwrap_or_default()),
    );
    attrs.insert(
        "runner_environment".to_string(),
        RestrictedExpression::new_string(claims.runner_environment.clone()),
    );

    let principal_entity = Entity::new(principal_uid.clone(), attrs, HashSet::new())
        .map_err(|e| AppError::CedarPolicy(format!("Failed to create entity: {}", e)))?;

    let resource_type_name: EntityTypeName =
        EntityTypeName::from_str(&format!("Permitd::{}", resource_type))
            .map_err(|e| AppError::CedarPolicy(format!("Invalid resource type: {}", e)))?;
    let resource_eid = EntityId::from_str(resource_id)
        .map_err(|e| AppError::CedarPolicy(format!("Invalid resource id: {}", e)))?;
    let resource_uid = EntityUid::from_type_name_and_id(resource_type_name, resource_eid);

    let mut resource_attrs = HashMap::new();
    resource_attrs.insert(
        "name".to_string(),
        RestrictedExpression::new_string(resource_id.to_string()),
    );
    let resource_entity = Entity::new(resource_uid, resource_attrs, HashSet::new())
        .map_err(|e| AppError::CedarPolicy(format!("Failed to create entity: {}", e)))?;

    let entities = Entities::from_entities([principal_entity, resource_entity], None)
        .map_err(|e| AppError::CedarPolicy(format!("Failed to create entities: {}", e)))?;
    Ok((principal_uid, entities))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims() -> GitHubClaims {
        serde_json::from_value(serde_json::json!({
            "sub": "repo:myorg/app:ref:refs/heads/main",
            "repository": "myorg/app",
            "repository_owner": "myorg",
            "repository_owner_id": "12345",
            "ref": "refs/heads/main",
            "workflow": "deploy.yml",
            "job_workflow_ref": "myorg/app/.github/workflows/deploy.yml@refs/heads/main",
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
    fn test_build_entities() {
        let claims = sample_claims();
        let (uid, _entities) = build_entities(&claims, "Container", "test").unwrap();
        assert!(uid.to_string().contains("myorg/app"));
    }
}
