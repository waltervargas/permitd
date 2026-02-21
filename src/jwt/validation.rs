use jsonwebtoken::{decode, Algorithm, Validation};

use crate::error::AppError;
use crate::jwt::claims::GitHubClaims;
use crate::jwt::jwks::JwksCache;

pub struct JwtValidator {
    jwks_cache: JwksCache,
    issuer: String,
    audience: String,
}

impl JwtValidator {
    pub fn new(jwks_cache: JwksCache, issuer: String, audience: String) -> Self {
        Self {
            jwks_cache,
            issuer,
            audience,
        }
    }

    pub async fn validate(&self, token: &str) -> Result<GitHubClaims, AppError> {
        let header = jsonwebtoken::decode_header(token)?;
        let kid = header.kid.ok_or(AppError::Unauthorized)?;
        let key = self
            .jwks_cache
            .get_key(&kid)
            .await
            .ok_or(AppError::Unauthorized)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        let token_data = decode::<GitHubClaims>(token, &key, &validation)?;
        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    fn make_test_token(claims: serde_json::Value, key_pem: &[u8]) -> String {
        let key = EncodingKey::from_rsa_pem(key_pem).unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());
        encode(&header, &claims, &key).unwrap()
    }

    fn valid_claims() -> serde_json::Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        json!({
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
            "exp": now + 3600,
            "nbf": now - 60,
            "iat": now
        })
    }

    #[tokio::test]
    async fn test_valid_jwt_accepted() {
        let private_pem = include_bytes!("../../tests/fixtures/test_private_key.pem");
        let public_pem = include_bytes!("../../tests/fixtures/test_public_key.pem");

        let token = make_test_token(valid_claims(), private_pem);

        // Decode and validate manually (bypassing JWKS cache for unit test)
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(public_pem).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["https://token.actions.githubusercontent.com"]);
        validation.set_audience(&["permitd"]);

        let result =
            decode::<crate::jwt::claims::GitHubClaims>(&token, &decoding_key, &validation);
        assert!(result.is_ok());
        let claims = result.unwrap().claims;
        assert_eq!(claims.repository, "myorg/app");
    }

    #[tokio::test]
    async fn test_expired_jwt_rejected() {
        let private_pem = include_bytes!("../../tests/fixtures/test_private_key.pem");
        let public_pem = include_bytes!("../../tests/fixtures/test_public_key.pem");

        let mut claims = valid_claims();
        claims["exp"] = json!(1000000000u64);
        claims["nbf"] = json!(999999000u64);
        claims["iat"] = json!(999999000u64);

        let token = make_test_token(claims, private_pem);
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(public_pem).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["https://token.actions.githubusercontent.com"]);
        validation.set_audience(&["permitd"]);

        let result =
            decode::<crate::jwt::claims::GitHubClaims>(&token, &decoding_key, &validation);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wrong_audience_rejected() {
        let private_pem = include_bytes!("../../tests/fixtures/test_private_key.pem");
        let public_pem = include_bytes!("../../tests/fixtures/test_public_key.pem");

        let mut claims = valid_claims();
        claims["aud"] = json!("wrong-audience");

        let token = make_test_token(claims, private_pem);
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(public_pem).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["https://token.actions.githubusercontent.com"]);
        validation.set_audience(&["permitd"]);

        let result =
            decode::<crate::jwt::claims::GitHubClaims>(&token, &decoding_key, &validation);
        assert!(result.is_err());
    }
}
