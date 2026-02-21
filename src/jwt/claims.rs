use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct GitHubClaims {
    pub sub: String,
    pub repository: String,
    pub repository_owner: String,
    pub repository_owner_id: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub workflow: String,
    pub job_workflow_ref: String,
    pub actor: String,
    #[serde(default)]
    pub environment: Option<String>,
    pub runner_environment: String,
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub nbf: u64,
    pub iat: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_github_claims() {
        let json = r#"{
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
            "exp": 1700000000,
            "nbf": 1699999000,
            "iat": 1699999000
        }"#;
        let claims: GitHubClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.repository, "myorg/app");
        assert_eq!(claims.repository_owner, "myorg");
        assert_eq!(claims.git_ref, "refs/heads/main");
        assert!(claims.environment.is_none());
    }
}
