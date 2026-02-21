# permitd v0.1 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a working OIDC authorization gateway that validates GitHub Actions JWTs, evaluates Cedar policies, and proxies authorized requests to a local Podman Unix socket.

**Architecture:** Plain HTTP server (axum) behind Cloudflare. Incoming requests are authenticated via OIDC JWT, matched to Cedar actions via route mapping, evaluated against Cedar policies, and proxied to Podman via Unix socket using hyper.

**Tech Stack:** Rust, axum, cedar-policy 4, hyper 1, jsonwebtoken 9, reqwest, clap 4, tokio, serde/toml, tracing

---

## Phase 0: Environment Setup

### Task 0: Install Rust Toolchain

**Step 1: Install rustup and stable toolchain**

Run:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"
```

**Step 2: Verify installation**

Run: `rustc --version && cargo --version`
Expected: version output for both

**Step 3: Commit nothing** — toolchain is system-level.

---

## Phase 1: Project Scaffolding

### Task 1: Initialize Cargo project and dependencies

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`

**Step 1: Initialize the project**

Run:
```bash
cd /home/walter/workspace/permitd
cargo init .
```

**Step 2: Replace Cargo.toml with full dependencies**

Write `Cargo.toml`:
```toml
[package]
name = "permitd"
version = "0.1.0"
edition = "2024"
description = "OIDC Authorization Gateway Powered by Cedar"
license = "Apache-2.0"

[dependencies]
axum = { version = "0.8", features = ["macros"] }
cedar-policy = "4"
clap = { version = "4", features = ["derive"] }
hyper = { version = "1", features = ["full"] }
hyper-util = { version = "0.1", features = ["full"] }
http-body-util = "0.1"
jsonwebtoken = "9"
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
toml = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
thiserror = "2"
tower = "0.5"
tower-http = { version = "0.6", features = ["trace"] }
bytes = "1"

[dev-dependencies]
wiremock = "0.6"
tempfile = "3"
```

**Step 3: Replace src/main.rs with minimal placeholder**

```rust
fn main() {
    println!("permitd");
}
```

**Step 4: Build to verify dependencies resolve**

Run: `cargo build`
Expected: Successful compilation (first build will download and compile all deps)

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/main.rs
git commit -m "feat: initialize cargo project with dependencies"
```

---

### Task 2: Error types (`src/error.rs`)

**Files:**
- Create: `src/error.rs`
- Modify: `src/main.rs` (add mod declaration)

**Step 1: Write error.rs**

```rust
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("JWKS fetch error: {0}")]
    JwksFetch(String),

    #[error("Cedar schema error: {0}")]
    CedarSchema(String),

    #[error("Cedar policy error: {0}")]
    CedarPolicy(String),

    #[error("Authorization denied")]
    Forbidden,

    #[error("Missing or invalid Authorization header")]
    Unauthorized,

    #[error("No matching route for request")]
    NoRouteMatch,

    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("Route mapping error: {0}")]
    RouteMapping(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden | AppError::NoRouteMatch => StatusCode::FORBIDDEN,
            AppError::Proxy(_) => StatusCode::BAD_GATEWAY,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = serde_json::json!({
            "error": status.as_str(),
            "message": match &self {
                // Don't leak internal details for auth errors
                AppError::Forbidden | AppError::NoRouteMatch => "Access denied".to_string(),
                AppError::Unauthorized => "Missing or invalid authorization".to_string(),
                other => other.to_string(),
            }
        });

        (status, axum::Json(body)).into_response()
    }
}
```

**Step 2: Add mod declaration to main.rs**

```rust
mod error;

fn main() {
    println!("permitd");
}
```

**Step 3: Build**

Run: `cargo build`
Expected: Success

**Step 4: Commit**

```bash
git add src/error.rs src/main.rs
git commit -m "feat: add AppError types with axum IntoResponse"
```

---

### Task 3: Configuration (`src/config.rs`)

**Files:**
- Create: `src/config.rs`
- Modify: `src/main.rs` (add mod)

**Step 1: Write the test first**

At the bottom of `src/config.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let toml_str = r#"
[server]
listen_addr = "0.0.0.0:8080"

[upstream]
socket_path = "/run/podman/podman.sock"

[oidc]
issuer = "https://token.actions.githubusercontent.com"
audience = "permitd"
jwks_cache_ttl_secs = 3600

[cedar]
schema_path = "/etc/permitd/schema.cedarschema"
policy_dir = "/etc/permitd/policies/"

[routes]
mapping_file = "/etc/permitd/routes.toml"

[logging]
format = "json"
level = "info"
log_authorized = true
log_denied = true
log_jwt_claims = false
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.listen_addr, "0.0.0.0:8080");
        assert_eq!(config.upstream.socket_path, "/run/podman/podman.sock");
        assert_eq!(config.oidc.issuer, "https://token.actions.githubusercontent.com");
        assert_eq!(config.oidc.audience, "permitd");
        assert_eq!(config.cedar.schema_path, "/etc/permitd/schema.cedarschema");
        assert_eq!(config.routes.mapping_file, "/etc/permitd/routes.toml");
        assert_eq!(config.logging.format, "json");
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib config::tests::test_parse_config`
Expected: FAIL — structs don't exist yet

**Step 3: Write the config structs**

```rust
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub oidc: OidcConfig,
    pub cedar: CedarConfig,
    pub routes: RoutesConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
}

fn default_listen_addr() -> String {
    "0.0.0.0:8080".to_string()
}

#[derive(Debug, Deserialize)]
pub struct UpstreamConfig {
    pub socket_path: String,
}

#[derive(Debug, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    #[serde(default = "default_audience")]
    pub audience: String,
    #[serde(default = "default_jwks_ttl")]
    pub jwks_cache_ttl_secs: u64,
}

fn default_audience() -> String {
    "permitd".to_string()
}

fn default_jwks_ttl() -> u64 {
    3600
}

#[derive(Debug, Deserialize)]
pub struct CedarConfig {
    pub schema_path: String,
    pub policy_dir: String,
}

#[derive(Debug, Deserialize)]
pub struct RoutesConfig {
    pub mapping_file: String,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_true")]
    pub log_authorized: bool,
    #[serde(default = "default_true")]
    pub log_denied: bool,
    #[serde(default)]
    pub log_jwt_claims: bool,
}

fn default_log_format() -> String { "json".to_string() }
fn default_log_level() -> String { "info".to_string() }
fn default_true() -> bool { true }

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: default_log_format(),
            level: default_log_level(),
            log_authorized: true,
            log_denied: true,
            log_jwt_claims: false,
        }
    }
}

impl AppConfig {
    pub fn load(path: &str) -> Result<Self, crate::error::AppError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::AppError::Config(format!("Failed to read {}: {}", path, e)))?;
        toml::from_str(&content)
            .map_err(|e| crate::error::AppError::Config(format!("Failed to parse config: {}", e)))
    }
}
```

**Step 4: Run test**

Run: `cargo test --lib config::tests::test_parse_config`
Expected: PASS

**Step 5: Commit**

```bash
git add src/config.rs src/main.rs
git commit -m "feat: add TOML config parsing with defaults"
```

---

### Task 4: CLI definition (`src/cli.rs`) and main.rs wiring

**Files:**
- Create: `src/cli.rs`
- Modify: `src/main.rs`

**Step 1: Write cli.rs**

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "permitd")]
#[command(about = "OIDC Authorization Gateway Powered by Cedar")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the gateway server
    Serve {
        /// Path to config.toml
        #[arg(long, default_value = "/etc/permitd/config.toml")]
        config: String,
    },
    /// Validate Cedar schema and policies without starting
    Validate {
        /// Path to Cedar schema file
        #[arg(long)]
        schema: String,
        /// Path to policies directory
        #[arg(long)]
        policies: String,
        /// Path to routes mapping file
        #[arg(long)]
        routes: Option<String>,
    },
    /// Dry-run an authorization check against loaded policies
    Check {
        /// Path to config.toml
        #[arg(long, default_value = "/etc/permitd/config.toml")]
        config: String,
        /// Principal identifier (e.g., "myorg/payments-service")
        #[arg(long)]
        principal: String,
        /// Cedar action (e.g., "containers:create")
        #[arg(long)]
        action: String,
        /// Resource identifier (e.g., "payments-api")
        #[arg(long)]
        resource: String,
        /// Resource type (e.g., "Container")
        #[arg(long, default_value = "Container")]
        resource_type: String,
        /// Git ref
        #[arg(long, default_value = "refs/heads/main")]
        git_ref: String,
        /// Repository owner (extracted from principal if not provided)
        #[arg(long)]
        owner: Option<String>,
    },
    /// List all configured route mappings
    Routes {
        /// Path to routes.toml
        #[arg(long)]
        mapping: String,
        /// Output format: "table" or "json"
        #[arg(long, default_value = "table")]
        format: String,
    },
}
```

**Step 2: Wire main.rs**

```rust
mod cli;
mod config;
mod error;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { config } => {
            eprintln!("serve: config={}", config);
            todo!("serve command")
        }
        Commands::Validate { schema, policies, routes } => {
            eprintln!("validate: schema={} policies={} routes={:?}", schema, policies, routes);
            todo!("validate command")
        }
        Commands::Check { config, principal, action, resource, .. } => {
            eprintln!("check: principal={} action={} resource={}", principal, action, resource);
            todo!("check command")
        }
        Commands::Routes { mapping, format } => {
            eprintln!("routes: mapping={} format={}", mapping, format);
            todo!("routes command")
        }
    }
}
```

**Step 3: Build and test CLI help**

Run: `cargo run -- --help`
Expected: Help text with serve, validate, check, routes subcommands

Run: `cargo run -- serve --help`
Expected: Help text for serve subcommand

**Step 4: Commit**

```bash
git add src/cli.rs src/main.rs
git commit -m "feat: add CLI with serve, validate, check, routes subcommands"
```

---

## Phase 2: JWT Module (can be parallel with Phase 3 and 4)

### Task 5: GitHub OIDC claims struct (`src/jwt/claims.rs`)

**Files:**
- Create: `src/jwt/mod.rs`
- Create: `src/jwt/claims.rs`
- Modify: `src/main.rs` (add `mod jwt;`)

**Step 1: Write the test**

In `src/jwt/claims.rs`:
```rust
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
        assert_eq!(claims.actor, "username");
        assert!(claims.environment.is_none());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib jwt::claims::tests::test_deserialize_github_claims`
Expected: FAIL

**Step 3: Implement claims struct**

```rust
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

    // Standard JWT claims
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub nbf: u64,
    pub iat: u64,
}
```

`src/jwt/mod.rs`:
```rust
pub mod claims;
```

Add to `src/main.rs`: `mod jwt;`

**Step 4: Run test**

Run: `cargo test --lib jwt::claims::tests::test_deserialize_github_claims`
Expected: PASS

**Step 5: Commit**

```bash
git add src/jwt/ src/main.rs
git commit -m "feat: add GitHub OIDC claims struct"
```

---

### Task 6: JWKS fetching and caching (`src/jwt/jwks.rs`)

**Files:**
- Create: `src/jwt/jwks.rs`
- Modify: `src/jwt/mod.rs`

**Step 1: Write the test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jwks_cache_returns_cached_keys() {
        // Create a JwksCache with a test JWKS JSON
        let test_jwks = r#"{
            "keys": [{
                "kty": "RSA",
                "kid": "test-key-1",
                "use": "sig",
                "alg": "RS256",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB"
            }]
        }"#;

        let cache = JwksCache::new_with_keys(
            serde_json::from_str(test_jwks).unwrap(),
        );

        let key = cache.get_key("test-key-1").await;
        assert!(key.is_some());

        let key = cache.get_key("nonexistent").await;
        assert!(key.is_none());
    }
}
```

**Step 2: Run test — expect fail**

Run: `cargo test --lib jwt::jwks::tests::test_jwks_cache_returns_cached_keys`

**Step 3: Implement JWKS cache**

```rust
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

    /// Test helper: create a cache pre-loaded with keys
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
        // Try cache first
        {
            let cached = self.jwks.read().await;
            if cached.fetched_at.elapsed() < self.ttl {
                return Self::find_key(&cached.keys, kid);
            }
        }

        // Cache expired, refresh
        if let Ok(new_keys) = self.fetch_jwks().await {
            let mut cached = self.jwks.write().await;
            cached.keys = new_keys;
            cached.fetched_at = Instant::now();
            return Self::find_key(&cached.keys, kid);
        }

        // Fetch failed, try stale cache
        let cached = self.jwks.read().await;
        Self::find_key(&cached.keys, kid)
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, AppError> {
        let resp = self.client
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
```

Add to `src/jwt/mod.rs`: `pub mod jwks;`

**Step 4: Run test**

Run: `cargo test --lib jwt::jwks::tests`
Expected: PASS

**Step 5: Commit**

```bash
git add src/jwt/jwks.rs src/jwt/mod.rs
git commit -m "feat: add JWKS fetching with TTL-based caching"
```

---

### Task 7: JWT validation (`src/jwt/validation.rs`)

**Files:**
- Create: `src/jwt/validation.rs`
- Modify: `src/jwt/mod.rs`

**Step 1: Write the test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    fn generate_rsa_keypair() -> (EncodingKey, jsonwebtoken::DecodingKey, jsonwebtoken::jwk::Jwk) {
        use jsonwebtoken::Algorithm;
        // Use a pre-generated test RSA key (2048-bit)
        let private_key_pem = include_str!("../../tests/fixtures/test_private_key.pem");
        let public_key_pem = include_str!("../../tests/fixtures/test_public_key.pem");

        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap();
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).unwrap();

        // Build a JWK from the public key for the JWKS cache
        let n_b64 = base64_url_encode_from_pem(public_key_pem);

        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(json!({
            "kty": "RSA",
            "kid": "test-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": n_b64,
            "e": "AQAB"
        })).unwrap();

        (encoding_key, decoding_key, jwk)
    }

    #[tokio::test]
    async fn test_validate_valid_jwt() {
        // This test requires test RSA key fixtures — see Task 7 Step 2
        // Test validates that a properly signed JWT with correct claims passes validation
    }

    #[tokio::test]
    async fn test_reject_expired_jwt() {
        // Test validates that expired JWTs are rejected
    }
}
```

> **Note:** This task requires generating test RSA key fixtures first. The implementing agent should generate a 2048-bit RSA key pair and save them to `tests/fixtures/test_private_key.pem` and `tests/fixtures/test_public_key.pem`.

**Step 2: Generate test RSA key fixtures**

Run:
```bash
mkdir -p tests/fixtures
openssl genrsa -out tests/fixtures/test_private_key.pem 2048
openssl rsa -in tests/fixtures/test_private_key.pem -pubout -out tests/fixtures/test_public_key.pem
```

**Step 3: Implement JWT validator**

```rust
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
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
        Self { jwks_cache, issuer, audience }
    }

    pub async fn validate(&self, token: &str) -> Result<GitHubClaims, AppError> {
        // Decode header to get kid
        let header = jsonwebtoken::decode_header(token)?;
        let kid = header.kid.ok_or(AppError::Unauthorized)?;

        // Get key from JWKS cache
        let key = self.jwks_cache
            .get_key(&kid)
            .await
            .ok_or(AppError::Unauthorized)?;

        // Validate token
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);

        let token_data = decode::<GitHubClaims>(token, &key, &validation)?;
        Ok(token_data.claims)
    }
}
```

Add to `src/jwt/mod.rs`: `pub mod validation;`

**Step 4: Write full test with real RSA signing**

The implementing agent should write a test that:
1. Creates a JWT signed with the test private key
2. Sets up a JwksCache with the corresponding public key
3. Validates the JWT succeeds
4. Tests that expired JWTs fail
5. Tests that wrong-audience JWTs fail

**Step 5: Run tests**

Run: `cargo test --lib jwt::validation::tests`
Expected: PASS

**Step 6: Commit**

```bash
git add src/jwt/validation.rs src/jwt/mod.rs tests/fixtures/
git commit -m "feat: add JWT validation with RS256 and claims extraction"
```

---

## Phase 3: Cedar Module (can be parallel with Phase 2 and 4)

### Task 8: Cedar schema and policy loading (`src/cedar/engine.rs`)

**Files:**
- Create: `src/cedar/mod.rs`
- Create: `src/cedar/engine.rs`
- Create: `schema.cedarschema` (default schema from PRD)
- Modify: `src/main.rs` (add `mod cedar;`)

**Step 1: Create the Cedar schema file**

Write `schema.cedarschema` (at project root):
```
namespace Permitd {
    entity Workflow {
        repository: String,
        repository_owner: String,
        ref: String,
        workflow_ref: String,
        actor: String,
        environment: String,
        runner_environment: String,
    };

    entity Container {
        name: String,
    };

    entity Image {
        name: String,
    };

    entity Volume {
        name: String,
    };

    entity Network {
        name: String,
    };

    action "containers:create" appliesTo {
        principal: [Workflow],
        resource: [Container]
    };
    action "containers:start" appliesTo {
        principal: [Workflow],
        resource: [Container]
    };
    action "containers:stop" appliesTo {
        principal: [Workflow],
        resource: [Container]
    };
    action "containers:remove" appliesTo {
        principal: [Workflow],
        resource: [Container]
    };
    action "containers:list" appliesTo {
        principal: [Workflow],
        resource: [Container]
    };
    action "containers:inspect" appliesTo {
        principal: [Workflow],
        resource: [Container]
    };
    action "containers:logs" appliesTo {
        principal: [Workflow],
        resource: [Container]
    };
    action "containers:exec" appliesTo {
        principal: [Workflow],
        resource: [Container]
    };
    action "images:pull" appliesTo {
        principal: [Workflow],
        resource: [Image]
    };
    action "images:list" appliesTo {
        principal: [Workflow],
        resource: [Image]
    };
    action "images:remove" appliesTo {
        principal: [Workflow],
        resource: [Image]
    };
    action "images:build" appliesTo {
        principal: [Workflow],
        resource: [Image]
    };
    action "volumes:create" appliesTo {
        principal: [Workflow],
        resource: [Volume]
    };
    action "volumes:remove" appliesTo {
        principal: [Workflow],
        resource: [Volume]
    };
    action "volumes:list" appliesTo {
        principal: [Workflow],
        resource: [Volume]
    };
    action "networks:create" appliesTo {
        principal: [Workflow],
        resource: [Network]
    };
    action "networks:remove" appliesTo {
        principal: [Workflow],
        resource: [Network]
    };
    action "networks:list" appliesTo {
        principal: [Workflow],
        resource: [Network]
    };
}
```

**Step 2: Write the test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_schema() {
        let schema_str = include_str!("../../schema.cedarschema");
        let engine = CedarEngine::from_str(schema_str, "").unwrap();
        // Schema loaded without errors
        assert!(engine.schema.is_some());
    }

    #[test]
    fn test_load_policy() {
        let schema_str = include_str!("../../schema.cedarschema");
        let policy_str = r#"
permit (
    principal is Permitd::Workflow,
    action == Permitd::Action::"containers:list",
    resource
)
when {
    principal.repository_owner == "myorg"
};
"#;
        let engine = CedarEngine::from_str(schema_str, policy_str).unwrap();
        assert!(engine.policy_set.policy_ids().count() > 0);
    }
}
```

**Step 3: Implement CedarEngine**

```rust
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

        let policy_set: PolicySet = policies_str.parse()
            .map_err(|e: cedar_policy::PolicySetError| AppError::CedarPolicy(format!("{}", e)))?;

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
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| AppError::CedarPolicy(format!("Failed to read {}: {}", path.display(), e)))?;
                all_policies.push_str(&content);
                all_policies.push('\n');
            }
        }

        Self::from_str(&schema_str, &all_policies)
    }
}
```

`src/cedar/mod.rs`:
```rust
pub mod engine;
```

**Step 4: Run tests**

Run: `cargo test --lib cedar::engine::tests`
Expected: PASS

**Step 5: Commit**

```bash
git add src/cedar/ src/main.rs schema.cedarschema
git commit -m "feat: add Cedar engine with schema and policy loading"
```

---

### Task 9: Cedar entity mapping (`src/cedar/entities.rs`)

**Files:**
- Create: `src/cedar/entities.rs`
- Modify: `src/cedar/mod.rs`

**Step 1: Write the test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::claims::GitHubClaims;

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
            "exp": 1700000000,
            "nbf": 1699999000,
            "iat": 1699999000
        })).unwrap()
    }

    #[test]
    fn test_build_principal_entity() {
        let claims = sample_claims();
        let (uid, entities) = build_entities(&claims, "Container", "test-container").unwrap();
        assert!(uid.to_string().contains("myorg/app"));
    }
}
```

**Step 2: Run test — expect fail**

**Step 3: Implement entity builder**

```rust
use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, Entities, RestrictedExpression};
use std::collections::{HashMap, HashSet};
use crate::error::AppError;
use crate::jwt::claims::GitHubClaims;

pub fn build_entities(
    claims: &GitHubClaims,
    resource_type: &str,
    resource_id: &str,
) -> Result<(EntityUid, Entities), AppError> {
    // Build principal entity: Permitd::Workflow
    let principal_type: EntityTypeName = "Permitd::Workflow".parse()
        .map_err(|e| AppError::CedarPolicy(format!("Invalid principal type: {}", e)))?;
    let principal_id: EntityId = claims.repository.clone().into();
    let principal_uid = EntityUid::from_type_name_and_id(principal_type, principal_id);

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
        RestrictedExpression::new_string(
            claims.environment.clone().unwrap_or_default(),
        ),
    );
    attrs.insert(
        "runner_environment".to_string(),
        RestrictedExpression::new_string(claims.runner_environment.clone()),
    );

    let principal_entity = Entity::new(principal_uid.clone(), attrs, HashSet::new())
        .map_err(|e| AppError::CedarPolicy(format!("Failed to create principal entity: {}", e)))?;

    // Build resource entity
    let resource_type_name: EntityTypeName = format!("Permitd::{}", resource_type).parse()
        .map_err(|e| AppError::CedarPolicy(format!("Invalid resource type: {}", e)))?;
    let resource_entity_id: EntityId = resource_id.to_string().into();
    let resource_uid = EntityUid::from_type_name_and_id(resource_type_name, resource_entity_id);

    let mut resource_attrs = HashMap::new();
    resource_attrs.insert(
        "name".to_string(),
        RestrictedExpression::new_string(resource_id.to_string()),
    );
    let resource_entity = Entity::new(resource_uid, resource_attrs, HashSet::new())
        .map_err(|e| AppError::CedarPolicy(format!("Failed to create resource entity: {}", e)))?;

    let entities = Entities::from_entities([principal_entity, resource_entity], None)
        .map_err(|e| AppError::CedarPolicy(format!("Failed to create entities: {}", e)))?;

    Ok((principal_uid, entities))
}
```

Add to `src/cedar/mod.rs`: `pub mod entities;`

**Step 4: Run tests**

Run: `cargo test --lib cedar::entities::tests`
Expected: PASS

**Step 5: Commit**

```bash
git add src/cedar/entities.rs src/cedar/mod.rs
git commit -m "feat: add Cedar entity builder from JWT claims"
```

---

### Task 10: Cedar authorization evaluation (`src/cedar/eval.rs`)

**Files:**
- Create: `src/cedar/eval.rs`
- Modify: `src/cedar/mod.rs`

**Step 1: Write the test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cedar::engine::CedarEngine;
    use crate::jwt::claims::GitHubClaims;

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
            "exp": 1700000000,
            "nbf": 1699999000,
            "iat": 1699999000
        })).unwrap()
    }

    #[test]
    fn test_permit_matching_policy() {
        let schema_str = include_str!("../../schema.cedarschema");
        let policy_str = r#"
permit (
    principal is Permitd::Workflow,
    action == Permitd::Action::"containers:list",
    resource
)
when {
    principal.repository_owner == "myorg"
};
"#;
        let engine = CedarEngine::from_str(schema_str, policy_str).unwrap();
        let claims = sample_claims("myorg/app", "refs/heads/main");
        let result = evaluate(&engine, &claims, "containers:list", "Container", "*");
        assert!(result.is_ok(), "Expected permit, got: {:?}", result);
    }

    #[test]
    fn test_deny_no_matching_policy() {
        let schema_str = include_str!("../../schema.cedarschema");
        let policy_str = r#"
permit (
    principal is Permitd::Workflow,
    action == Permitd::Action::"containers:list",
    resource
)
when {
    principal.repository_owner == "myorg"
};
"#;
        let engine = CedarEngine::from_str(schema_str, policy_str).unwrap();
        let claims = sample_claims("otherorg/app", "refs/heads/main");
        let result = evaluate(&engine, &claims, "containers:list", "Container", "*");
        assert!(matches!(result, Err(AppError::Forbidden)));
    }
}
```

**Step 2: Implement evaluation**

```rust
use cedar_policy::{Context, Decision, EntityTypeName, EntityId, EntityUid, Request};
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

    let action_type: EntityTypeName = "Permitd::Action".parse()
        .map_err(|e| AppError::CedarPolicy(format!("Invalid action type: {}", e)))?;
    let action_id: EntityId = action.to_string().into();
    let action_uid = EntityUid::from_type_name_and_id(action_type, action_id);

    let resource_type_name: EntityTypeName = format!("Permitd::{}", resource_type).parse()
        .map_err(|e| AppError::CedarPolicy(format!("Invalid resource type: {}", e)))?;
    let resource_entity_id: EntityId = resource_id.to_string().into();
    let resource_uid = EntityUid::from_type_name_and_id(resource_type_name, resource_entity_id);

    let context = Context::empty();

    let request = Request::new(
        principal_uid,
        action_uid,
        resource_uid,
        context,
        engine.schema.as_ref(),
    ).map_err(|e| AppError::CedarPolicy(format!("Invalid request: {}", e)))?;

    let response = engine.authorizer.is_authorized(&request, &engine.policy_set, &entities);

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
```

Add to `src/cedar/mod.rs`: `pub mod eval;`

**Step 4: Run tests**

Run: `cargo test --lib cedar::eval::tests`
Expected: PASS

**Step 5: Commit**

```bash
git add src/cedar/eval.rs src/cedar/mod.rs
git commit -m "feat: add Cedar authorization evaluation"
```

---

## Phase 4: Routing Module (can be parallel with Phase 2 and 3)

### Task 11: Route mapping parser (`src/routing/mapping.rs`)

**Files:**
- Create: `src/routing/mod.rs`
- Create: `src/routing/mapping.rs`
- Modify: `src/main.rs` (add `mod routing;`)

**Step 1: Write the test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_routes_toml() {
        let toml_str = r#"
[[routes]]
method = "POST"
path_pattern = "/v{version}/libpod/containers/create"
action = "containers:create"
resource_type = "Container"
resource_from = "wildcard"

[[routes]]
method = "POST"
path_pattern = "/v{version}/libpod/containers/{id}/start"
action = "containers:start"
resource_type = "Container"
resource_from = "path:id"

[[routes]]
method = "GET"
path_pattern = "/v{version}/libpod/containers/json"
action = "containers:list"
resource_type = "Container"
resource_from = "wildcard"
"#;
        let mapping: RouteMapping = toml::from_str(toml_str).unwrap();
        assert_eq!(mapping.routes.len(), 3);
        assert_eq!(mapping.routes[0].action, "containers:create");
        assert_eq!(mapping.routes[0].resource_from, "wildcard");
        assert_eq!(mapping.routes[1].resource_from, "path:id");
    }
}
```

**Step 2: Implement**

```rust
use serde::Deserialize;
use crate::error::AppError;

#[derive(Debug, Deserialize, Clone)]
pub struct RouteMapping {
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    pub method: String,
    pub path_pattern: String,
    pub action: String,
    pub resource_type: String,
    pub resource_from: String,
}

impl RouteMapping {
    pub fn load(path: &str) -> Result<Self, AppError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AppError::RouteMapping(format!("Failed to read {}: {}", path, e)))?;
        toml::from_str(&content)
            .map_err(|e| AppError::RouteMapping(format!("Failed to parse routes: {}", e)))
    }
}
```

`src/routing/mod.rs`:
```rust
pub mod mapping;
```

**Step 3: Run tests, commit**

```bash
git add src/routing/ src/main.rs
git commit -m "feat: add route mapping TOML parser"
```

---

### Task 12: Path pattern matcher (`src/routing/matcher.rs`)

**Files:**
- Create: `src/routing/matcher.rs`
- Modify: `src/routing/mod.rs`

**Step 1: Write comprehensive tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::mapping::RouteConfig;

    fn route(method: &str, pattern: &str, action: &str, res_type: &str, res_from: &str) -> RouteConfig {
        RouteConfig {
            method: method.to_string(),
            path_pattern: pattern.to_string(),
            action: action.to_string(),
            resource_type: res_type.to_string(),
            resource_from: res_from.to_string(),
        }
    }

    #[test]
    fn test_match_version_and_id() {
        let routes = vec![
            route("POST", "/v{version}/libpod/containers/{id}/start", "containers:start", "Container", "path:id"),
        ];
        let matcher = RouteMatcher::new(routes);
        let m = matcher.match_request("POST", "/v4.0.0/libpod/containers/mycontainer/start");
        assert!(m.is_some());
        let m = m.unwrap();
        assert_eq!(m.action, "containers:start");
        assert_eq!(m.params.get("id"), Some(&"mycontainer".to_string()));
    }

    #[test]
    fn test_no_match_wrong_method() {
        let routes = vec![
            route("POST", "/v{version}/libpod/containers/{id}/start", "containers:start", "Container", "path:id"),
        ];
        let matcher = RouteMatcher::new(routes);
        let m = matcher.match_request("GET", "/v4.0.0/libpod/containers/mycontainer/start");
        assert!(m.is_none());
    }

    #[test]
    fn test_match_no_id() {
        let routes = vec![
            route("GET", "/v{version}/libpod/containers/json", "containers:list", "Container", "wildcard"),
        ];
        let matcher = RouteMatcher::new(routes);
        let m = matcher.match_request("GET", "/v4.0.0/libpod/containers/json");
        assert!(m.is_some());
        assert_eq!(m.unwrap().action, "containers:list");
    }

    #[test]
    fn test_first_match_wins() {
        let routes = vec![
            route("GET", "/v{version}/libpod/containers/json", "containers:list", "Container", "wildcard"),
            route("GET", "/v{version}/libpod/containers/{id}", "containers:other", "Container", "path:id"),
        ];
        let matcher = RouteMatcher::new(routes);
        let m = matcher.match_request("GET", "/v4.0.0/libpod/containers/json");
        assert_eq!(m.unwrap().action, "containers:list");
    }

    #[test]
    fn test_version_formats() {
        let routes = vec![
            route("GET", "/v{version}/test", "test:action", "Container", "wildcard"),
        ];
        let matcher = RouteMatcher::new(routes);
        // Various version formats
        assert!(matcher.match_request("GET", "/v1/test").is_some());
        assert!(matcher.match_request("GET", "/v4.0.0/test").is_some());
        assert!(matcher.match_request("GET", "/v2.1/test").is_some());
    }

    #[test]
    fn test_delete_with_id() {
        let routes = vec![
            route("DELETE", "/v{version}/libpod/containers/{id}", "containers:remove", "Container", "path:id"),
        ];
        let matcher = RouteMatcher::new(routes);
        let m = matcher.match_request("DELETE", "/v4.0.0/libpod/containers/my-app");
        assert!(m.is_some());
        let m = m.unwrap();
        assert_eq!(m.params.get("id"), Some(&"my-app".to_string()));
    }
}
```

**Step 2: Implement**

```rust
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
        let pattern_segments: Vec<&str> = pattern.trim_matches('/').split('/').collect();
        let path_segments: Vec<&str> = path.trim_matches('/').split('/').collect();

        if pattern_segments.len() != path_segments.len() {
            return None;
        }

        let mut params = HashMap::new();

        for (pat, seg) in pattern_segments.iter().zip(path_segments.iter()) {
            if pat.starts_with('{') && pat.ends_with('}') {
                let param_name = &pat[1..pat.len() - 1];
                if param_name == "version" {
                    // Version must start with 'v' prefix (already consumed by first segment)
                    // Actually the pattern segment is like "v{version}" so we need special handling
                }
                params.insert(param_name.to_string(), seg.to_string());
            } else if pat.contains('{') && pat.contains('}') {
                // Handle prefix patterns like "v{version}"
                let prefix_end = pat.find('{').unwrap();
                let prefix = &pat[..prefix_end];
                let param_start = pat.find('{').unwrap() + 1;
                let param_end = pat.find('}').unwrap();
                let param_name = &pat[param_start..param_end];

                if !seg.starts_with(prefix) {
                    return None;
                }
                let value = &seg[prefix.len()..];
                params.insert(param_name.to_string(), value.to_string());
            } else if pat != seg {
                return None;
            }
        }

        Some(params)
    }
}
```

Add to `src/routing/mod.rs`: `pub mod matcher;`

**Step 3: Run tests, commit**

```bash
git add src/routing/matcher.rs src/routing/mod.rs
git commit -m "feat: add path pattern matcher with parameter extraction"
```

---

### Task 13: Resource extraction (`src/routing/resource.rs`)

**Files:**
- Create: `src/routing/resource.rs`
- Modify: `src/routing/mod.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_extract_from_path() {
        let mut params = HashMap::new();
        params.insert("id".to_string(), "my-container".to_string());
        let result = extract_resource("path:id", &params, "", "");
        assert_eq!(result, "my-container");
    }

    #[test]
    fn test_extract_from_query() {
        let result = extract_resource("query:reference", &HashMap::new(), "reference=ghcr.io/myorg/app:latest&other=val", "");
        assert_eq!(result, "ghcr.io/myorg/app:latest");
    }

    #[test]
    fn test_extract_wildcard() {
        let result = extract_resource("wildcard", &HashMap::new(), "", "");
        assert_eq!(result, "*");
    }

    #[test]
    fn test_extract_static() {
        let result = extract_resource("static:system", &HashMap::new(), "", "");
        assert_eq!(result, "system");
    }

    #[test]
    fn test_extract_missing_query_param() {
        let result = extract_resource("query:reference", &HashMap::new(), "other=val", "");
        assert_eq!(result, "*");
    }

    #[test]
    fn test_extract_missing_path_param() {
        let result = extract_resource("path:id", &HashMap::new(), "", "");
        assert_eq!(result, "*");
    }
}
```

**Step 2: Implement**

```rust
use std::collections::HashMap;

/// Extract resource ID based on the resource_from configuration.
/// Returns the extracted resource ID or "*" as fallback.
pub fn extract_resource(
    resource_from: &str,
    path_params: &HashMap<String, String>,
    query_string: &str,
    _body: &str, // Reserved for future body extraction
) -> String {
    if resource_from == "wildcard" {
        return "*".to_string();
    }

    if let Some(param) = resource_from.strip_prefix("path:") {
        return path_params.get(param).cloned().unwrap_or_else(|| "*".to_string());
    }

    if let Some(param) = resource_from.strip_prefix("query:") {
        // Parse query string manually
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

    // Unknown extraction mode, fall back to wildcard
    "*".to_string()
}
```

Add to `src/routing/mod.rs`: `pub mod resource;`

**Step 3: Run tests, commit**

```bash
git add src/routing/resource.rs src/routing/mod.rs
git commit -m "feat: add resource extraction from path, query, wildcard, static"
```

---

## Phase 5: Proxy (depends on nothing except Phase 1)

### Task 14: Unix socket proxy (`src/proxy/upstream.rs`)

**Files:**
- Create: `src/proxy/mod.rs`
- Create: `src/proxy/upstream.rs`
- Modify: `src/main.rs` (add `mod proxy;`)

**Step 1: Implement Unix socket connector and proxy**

```rust
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

use crate::error::AppError;

pub struct UnixSocketProxy {
    socket_path: String,
}

impl UnixSocketProxy {
    pub fn new(socket_path: String) -> Self {
        Self { socket_path }
    }

    pub async fn forward(
        &self,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> Result<hyper::Response<Incoming>, AppError> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| AppError::Proxy(format!("Failed to connect to {}: {}", self.socket_path, e)))?;

        let io = TokioIo::new(stream);

        let (mut sender, conn) = http1::handshake(io)
            .await
            .map_err(|e| AppError::Proxy(format!("Handshake failed: {}", e)))?;

        // Spawn connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::error!("Connection error: {}", e);
            }
        });

        let resp = sender.send_request(req)
            .await
            .map_err(|e| AppError::Proxy(format!("Request failed: {}", e)))?;

        Ok(resp)
    }
}
```

`src/proxy/mod.rs`:
```rust
pub mod upstream;
```

**Step 2: Build to verify compilation**

Run: `cargo build`
Expected: Success

**Step 3: Commit**

```bash
git add src/proxy/ src/main.rs
git commit -m "feat: add Unix socket reverse proxy via hyper"
```

---

## Phase 6: Server (depends on all previous phases)

### Task 15: Auth middleware and request handler (`src/server/`)

**Files:**
- Create: `src/server/mod.rs`
- Create: `src/server/handler.rs`
- Modify: `src/main.rs` (add `mod server;`)

**Step 1: Implement the server module**

`src/server/handler.rs`:
```rust
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
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
    // 1. Extract JWT from Authorization header
    let token = req.headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;

    // 2. Validate JWT
    let claims = state.jwt_validator.validate(token).await?;

    // 3. Match route
    let method = req.method().as_str();
    let path = req.uri().path();
    let query = req.uri().query().unwrap_or("");

    let route_match = state.route_matcher
        .match_request(method, path)
        .ok_or(AppError::NoRouteMatch)?;

    // 4. Extract resource
    let resource_id = extract_resource(
        &route_match.resource_from,
        &route_match.params,
        query,
        "", // No body extraction in v0.1
    );

    // 5. Cedar evaluation
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

    // 6. Proxy to upstream
    // Rebuild request for upstream (strip Authorization header, keep everything else)
    let (mut parts, body) = req.into_parts();
    parts.headers.remove("authorization");

    // Convert axum body to hyper body
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| AppError::Proxy(format!("Failed to read request body: {}", e)))?
        .to_bytes();

    let upstream_body: BoxBody<Bytes, hyper::Error> = BoxBody::new(
        http_body_util::Full::new(body_bytes)
            .map_err(|never| match never {})
    );

    let upstream_req = hyper::Request::from_parts(parts, upstream_body);

    let resp = state.proxy.forward(upstream_req).await?;

    // Stream response back
    let (parts, body) = resp.into_parts();
    let body = Body::new(body);
    Ok(Response::from_parts(parts, body))
}
```

`src/server/mod.rs`:
```rust
pub mod handler;
```

**Step 2: Build**

Run: `cargo build`
Expected: Success

**Step 3: Commit**

```bash
git add src/server/ src/main.rs
git commit -m "feat: add request handler with JWT, route matching, Cedar eval, proxy"
```

---

### Task 16: Wire main.rs serve command

**Files:**
- Modify: `src/main.rs`

**Step 1: Implement the serve command**

```rust
mod cedar;
mod cli;
mod config;
mod error;
mod jwt;
mod proxy;
mod routing;
mod server;

use axum::{Router, routing::get};
use clap::Parser;
use cli::{Cli, Commands};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { config: config_path } => {
            if let Err(e) = serve(&config_path).await {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Validate { schema, policies, routes } => {
            if let Err(e) = validate(&schema, &policies, routes.as_deref()) {
                eprintln!("Validation failed: {}", e);
                std::process::exit(1);
            }
            println!("Validation passed.");
        }
        Commands::Check {
            config: config_path, principal, action, resource,
            resource_type, git_ref, owner,
        } => {
            if let Err(e) = check(&config_path, &principal, &action, &resource, &resource_type, &git_ref, owner.as_deref()) {
                eprintln!("Check failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Routes { mapping, format } => {
            if let Err(e) = list_routes(&mapping, &format) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

async fn serve(config_path: &str) -> Result<(), error::AppError> {
    let config = config::AppConfig::load(config_path)?;

    // Init logging
    init_logging(&config.logging);

    tracing::info!("Loading Cedar schema and policies...");
    let cedar_engine = cedar::engine::CedarEngine::load(
        &config.cedar.schema_path,
        &config.cedar.policy_dir,
    )?;

    tracing::info!("Loading route mappings...");
    let route_mapping = routing::mapping::RouteMapping::load(&config.routes.mapping_file)?;
    let route_matcher = routing::matcher::RouteMatcher::new(route_mapping.routes);

    tracing::info!("Initializing JWKS cache...");
    let jwks_cache = jwt::jwks::JwksCache::new(
        &config.oidc.issuer,
        config.oidc.jwks_cache_ttl_secs,
    );
    let jwt_validator = jwt::validation::JwtValidator::new(
        jwks_cache,
        config.oidc.issuer.clone(),
        config.oidc.audience.clone(),
    );

    let proxy = proxy::upstream::UnixSocketProxy::new(config.upstream.socket_path.clone());

    let state = Arc::new(server::handler::AppState {
        jwt_validator,
        cedar_engine,
        route_matcher,
        proxy,
        log_authorized: config.logging.log_authorized,
        log_denied: config.logging.log_denied,
    });

    let app = Router::new()
        .route("/healthz", get(server::handler::health_check))
        .route("/readyz", get(server::handler::health_check))
        .fallback(server::handler::handle_request)
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&config.server.listen_addr)
        .await
        .map_err(|e| error::AppError::Config(format!("Failed to bind {}: {}", config.server.listen_addr, e)))?;

    tracing::info!("permitd listening on {}", config.server.listen_addr);

    axum::serve(listener, app)
        .await
        .map_err(|e| error::AppError::Io(e))?;

    Ok(())
}

fn validate(schema_path: &str, policy_dir: &str, routes_path: Option<&str>) -> Result<(), error::AppError> {
    cedar::engine::CedarEngine::load(schema_path, policy_dir)?;
    println!("Cedar schema and policies: OK");

    if let Some(routes) = routes_path {
        routing::mapping::RouteMapping::load(routes)?;
        println!("Route mapping: OK");
    }

    Ok(())
}

fn check(
    config_path: &str,
    principal: &str,
    action: &str,
    resource: &str,
    resource_type: &str,
    git_ref: &str,
    owner: Option<&str>,
) -> Result<(), error::AppError> {
    let config = config::AppConfig::load(config_path)?;
    let engine = cedar::engine::CedarEngine::load(
        &config.cedar.schema_path,
        &config.cedar.policy_dir,
    )?;

    let owner = owner.unwrap_or_else(|| {
        principal.split('/').next().unwrap_or(principal)
    });

    // Build synthetic claims for dry-run
    let claims = jwt::claims::GitHubClaims {
        sub: format!("repo:{}:ref:{}", principal, git_ref),
        repository: principal.to_string(),
        repository_owner: owner.to_string(),
        repository_owner_id: "0".to_string(),
        git_ref: git_ref.to_string(),
        workflow: "check".to_string(),
        job_workflow_ref: format!("{}/.github/workflows/check.yml@{}", principal, git_ref),
        actor: "permitd-check".to_string(),
        environment: None,
        runner_environment: "self-hosted".to_string(),
        iss: String::new(),
        aud: String::new(),
        exp: 0,
        nbf: 0,
        iat: 0,
    };

    match cedar::eval::evaluate(&engine, &claims, action, resource_type, resource) {
        Ok(()) => {
            println!("ALLOW: {} -> {} on {}::{}", principal, action, resource_type, resource);
            Ok(())
        }
        Err(error::AppError::Forbidden) => {
            println!("DENY: {} -> {} on {}::{}", principal, action, resource_type, resource);
            std::process::exit(1);
        }
        Err(e) => Err(e),
    }
}

fn list_routes(mapping_path: &str, format: &str) -> Result<(), error::AppError> {
    let mapping = routing::mapping::RouteMapping::load(mapping_path)?;

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&mapping.routes)
                .map_err(|e| error::AppError::Config(e.to_string()))?);
        }
        _ => {
            println!("{:<8} {:<50} {:<25} {:<12} {}", "METHOD", "PATTERN", "ACTION", "RESOURCE", "EXTRACT");
            println!("{}", "-".repeat(110));
            for route in &mapping.routes {
                println!("{:<8} {:<50} {:<25} {:<12} {}",
                    route.method, route.path_pattern, route.action, route.resource_type, route.resource_from);
            }
        }
    }

    Ok(())
}

fn init_logging(config: &config::LoggingConfig) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.level));

    match config.format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .init();
        }
    }
}
```

**Step 2: Build**

Run: `cargo build`
Expected: Success

**Step 3: Test CLI**

Run: `cargo run -- --help`
Expected: Full help text

**Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat: wire serve, validate, check, routes commands in main"
```

---

## Phase 7: Example Files and Integration

### Task 17: Example configuration files

**Files:**
- Create: `examples/config.toml`
- Create: `examples/routes.podman.toml`
- Create: `examples/policies/deploy.cedar`
- Create: `examples/policies/readonly.cedar`

**Step 1: Write example config.toml**

```toml
[server]
listen_addr = "0.0.0.0:8080"

[upstream]
socket_path = "/run/podman/podman.sock"

[oidc]
issuer = "https://token.actions.githubusercontent.com"
audience = "permitd"
jwks_cache_ttl_secs = 3600

[cedar]
schema_path = "/etc/permitd/schema.cedarschema"
policy_dir = "/etc/permitd/policies/"

[routes]
mapping_file = "/etc/permitd/routes.toml"

[logging]
format = "json"
level = "info"
log_authorized = true
log_denied = true
log_jwt_claims = false
```

**Step 2: Write example routes.podman.toml** (from PRD)

**Step 3: Write example policies** (from PRD)

**Step 4: Commit**

```bash
git add examples/ schema.cedarschema
git commit -m "feat: add example config, routes, and Cedar policies"
```

---

### Task 18: Replace LICENSE with Apache-2.0

**Files:**
- Modify: `LICENSE`

**Step 1: Replace LICENSE file with Apache-2.0 text**

**Step 2: Commit**

```bash
git add LICENSE
git commit -m "chore: replace MIT license with Apache-2.0"
```

---

### Task 19: Systemd unit file

**Files:**
- Create: `systemd/permitd.service`

Use the unit file from the PRD section 12.1.

**Step 1: Write the file, commit**

```bash
git add systemd/
git commit -m "feat: add systemd service unit file"
```

---

### Task 20: Dockerfile

**Files:**
- Create: `Dockerfile`

Multi-stage build: `rust:bookworm` builder → `debian:trixie-slim` runtime, targeting `aarch64-unknown-linux-gnu`.

**Step 1: Write Dockerfile, commit**

```bash
git add Dockerfile
git commit -m "feat: add multi-stage Dockerfile for aarch64"
```

---

### Task 21: Serialize RouteConfig for JSON output

**Files:**
- Modify: `src/routing/mapping.rs` (add `Serialize` derive)

The `list_routes` function needs `serde::Serialize` on `RouteConfig` for JSON output.

**Step 1: Add `Serialize` derive to `RouteConfig` and `RouteMapping`**

**Step 2: Build, commit**

---

### Task 22: Push branch and create PR

**Step 1: Push**

```bash
git push -u origin feat/v0.1-proof-of-value
```

**Step 2: Create PR**

```bash
gh pr create --title "feat: permitd v0.1 proof of value" --body "..."
```

---

## Parallelization Guide

These task groups can be executed concurrently by separate agents:

| Agent | Tasks | Description |
|-------|-------|-------------|
| Agent A | 5, 6, 7 | JWT module (claims, JWKS, validation) |
| Agent B | 8, 9, 10 | Cedar module (engine, entities, eval) |
| Agent C | 11, 12, 13 | Routing module (mapping, matcher, resource) |

**Sequential dependencies:**
- Tasks 0-4 must complete before agents A/B/C start
- Task 14 (proxy) can run in parallel with A/B/C
- Tasks 15-16 (server, main wiring) depend on all of A/B/C + 14
- Tasks 17-22 (examples, license, systemd, Docker, PR) depend on 16
