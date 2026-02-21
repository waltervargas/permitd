use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::error::AppError;

pub struct JwksCache {
    jwks: Arc<RwLock<CachedJwks>>,
    client: Client,
    jwks_url: String,
    ttl: Duration,
}

struct CachedJwks {
    keys: JwkSet,
    fetched_at: Instant,
}

impl JwksCache {
    pub fn new(issuer: &str, ttl_secs: u64) -> Self {
        let jwks_url = format!("{}/.well-known/jwks", issuer.trim_end_matches('/'));
        Self {
            jwks: Arc::new(RwLock::new(CachedJwks {
                keys: JwkSet { keys: vec![] },
                fetched_at: Instant::now() - Duration::from_secs(ttl_secs + 1),
            })),
            client: Client::new(),
            jwks_url,
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    #[cfg(test)]
    pub fn new_with_keys(keys: JwkSet) -> Self {
        Self {
            jwks: Arc::new(RwLock::new(CachedJwks {
                keys,
                fetched_at: Instant::now(),
            })),
            client: Client::new(),
            jwks_url: String::new(),
            ttl: Duration::from_secs(3600),
        }
    }

    pub async fn get_key(&self, kid: &str) -> Option<jsonwebtoken::DecodingKey> {
        {
            let cached = self.jwks.read().await;
            if cached.fetched_at.elapsed() < self.ttl {
                return Self::find_key(&cached.keys, kid);
            }
        }
        if let Ok(new_keys) = self.fetch_jwks().await {
            let mut cached = self.jwks.write().await;
            cached.keys = new_keys;
            cached.fetched_at = Instant::now();
            return Self::find_key(&cached.keys, kid);
        }
        let cached = self.jwks.read().await;
        Self::find_key(&cached.keys, kid)
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, AppError> {
        let resp = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| AppError::JwksFetch(e.to_string()))?;
        resp.json::<JwkSet>()
            .await
            .map_err(|e| AppError::JwksFetch(e.to_string()))
    }

    fn find_key(jwks: &JwkSet, kid: &str) -> Option<jsonwebtoken::DecodingKey> {
        jwks.keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid))
            .and_then(|jwk| jsonwebtoken::DecodingKey::from_jwk(jwk).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jwks_cache_returns_cached_keys() {
        let test_jwks = r#"{"keys":[{"kty":"RSA","kid":"test-key-1","use":"sig","alg":"RS256","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}]}"#;
        let cache = JwksCache::new_with_keys(serde_json::from_str(test_jwks).unwrap());
        assert!(cache.get_key("test-key-1").await.is_some());
        assert!(cache.get_key("nonexistent").await.is_none());
    }
}
