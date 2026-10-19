//! Conformance test mode: the SUT (system under test) interface of the
//! `ianlintner/oauth2-conformance` contract (v0.1, `contract/sut-interface.md`).
//!
//! The mode is **off by default**. It is switched on only by
//! `OAUTH2_CONFORMANCE_MODE=1` together with `OAUTH2_CONFORMANCE_SEED=<file>`,
//! and every failure while it is on aborts startup (fail closed): an invalid
//! seed, an unsupported signing algorithm, or a configuration that looks like
//! production. There is no partial seed and no warn-and-continue path.
//!
//! What the mode does:
//!
//! * loads and validates the seed file (YAML or JSON; mirrors
//!   `schemas/seed.schema.json` including `additionalProperties: false`),
//! * checks the process is not in a production profile ([`check_not_production`]),
//! * seeds clients and users into the (process-local, in-memory) store, so the
//!   ordinary `/auth/login` form + `/oauth/authorize` drive the flow
//!   non-interactively,
//! * provisions the seeded signing key IDs, and
//! * lets `/ready` report that the seed was applied.
//!
//! Nothing here changes protocol behavior: redirect validation, PKCE, `iss`,
//! and error handling are the normal code paths.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use oauth2_core::models::key_set::{Algorithm as KeyAlgorithm, SigningKey};
use oauth2_core::{Client, User};
use oauth2_storage_factory::DynStorage;
use serde::Deserialize;

/// Env var that switches conformance mode on (`1`/`true`) or leaves it off.
pub const MODE_ENV: &str = "OAUTH2_CONFORMANCE_MODE";
/// Env var holding the path of the seed file.
pub const SEED_ENV: &str = "OAUTH2_CONFORMANCE_SEED";

/// Environment-name variables inspected by the production guard.
const PROFILE_ENV_VARS: &[&str] = &[
    "OAUTH2_ENV",
    "OAUTH2_ENVIRONMENT",
    "OAUTH2_PROFILE",
    "APP_ENV",
    "ENVIRONMENT",
    "RUST_ENV",
];

/// Environment names under which conformance mode may run. Any other value of
/// a profile variable (production, staging, a typo, ...) aborts startup:
/// the guard is an allowlist so an unknown name fails closed.
const NON_PRODUCTION_ENV_NAMES: &[&str] = &[
    "test",
    "testing",
    "conformance",
    "dev",
    "development",
    "local",
    "ci",
];

const DEFAULT_CLIENT_SCOPE: &str = "openid read";
const DEFAULT_GRANT_TYPES: &[&str] = &["authorization_code"];
const GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
];

// ── Seed file model (schemas/seed.schema.json) ──────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    pub issuer: String,
    #[serde(default, rename = "signingKeys")]
    pub signing_keys: Vec<SeedSigningKey>,
    pub clients: Vec<SeedClient>,
    pub users: Vec<SeedUser>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedSigningKey {
    pub kid: String,
    pub alg: String,
    #[serde(default, rename = "use")]
    pub key_use: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedClient {
    pub client_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub public: Option<bool>,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedUser {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub email: Option<String>,
    /// Accepted for schema compatibility; not enforced by the v0.1 contract.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// This server grants consent to every authenticated authorization
    /// request (there is no consent screen), so the list is validated
    /// (each entry must be a seeded client) but needs no further handling.
    #[serde(default)]
    pub auto_approve_clients: Option<Vec<String>>,
}

impl SeedClient {
    fn is_public(&self) -> bool {
        self.public == Some(true) || self.token_endpoint_auth_method.as_deref() == Some("none")
    }
}

/// Result of a successful [`apply`]; `/ready` reports it.
#[derive(Debug, Clone)]
pub struct Applied {
    pub clients: usize,
    pub users: usize,
    pub signing_keys: Vec<SigningKey>,
}

impl Applied {
    /// Public readiness detail (counts only, never credentials or key bytes).
    pub fn readiness(&self) -> oauth2_actix::handlers::admin::ConformanceReadiness {
        oauth2_actix::handlers::admin::ConformanceReadiness {
            seed_applied: true,
            clients: self.clients,
            users: self.users,
            signing_key_ids: self.signing_keys.iter().map(|k| k.kid.clone()).collect(),
        }
    }
}

// ── Mode switch ─────────────────────────────────────────────────────────────

/// Decide whether conformance mode is on, from an env lookup.
///
/// Returns the seed path when on. An ambiguous `OAUTH2_CONFORMANCE_MODE`
/// value or a missing seed path is an error (fail closed). A seed path
/// without the mode switch is ignored: with the mode off nothing is exposed.
pub fn mode_from_env(get: impl Fn(&str) -> Option<String>) -> Result<Option<PathBuf>, String> {
    let mode = get(MODE_ENV).map(|v| v.trim().to_ascii_lowercase());
    let enabled = match mode.as_deref() {
        None | Some("") | Some("0") | Some("false") => false,
        Some("1") | Some("true") => true,
        Some(other) => {
            return Err(format!(
                "{MODE_ENV}={other:?} is not a recognized value; use 1 to enable or unset it"
            ))
        }
    };
    if !enabled {
        if get(SEED_ENV).is_some_and(|v| !v.trim().is_empty()) {
            tracing::warn!("{SEED_ENV} is set but {MODE_ENV} is off; the seed is ignored");
        }
        return Ok(None);
    }
    match get(SEED_ENV).map(|v| v.trim().to_string()) {
        Some(path) if !path.is_empty() => Ok(Some(PathBuf::from(path))),
        _ => Err(format!(
            "{MODE_ENV}=1 requires {SEED_ENV} to point at a seed file"
        )),
    }
}

// ── Production guard ────────────────────────────────────────────────────────

/// True when `database_url` is a process-local in-memory SQLite database.
fn is_in_memory_sqlite(database_url: &str) -> bool {
    let rest = match database_url.strip_prefix("sqlite:") {
        Some(rest) => rest,
        None => return false,
    };
    let rest = rest.trim_start_matches('/');
    let path = rest.split('?').next().unwrap_or(rest);
    path == ":memory:" || (path.starts_with("file:") && rest.contains("mode=memory"))
}

/// Abort-worthy reasons conformance mode must not run with this configuration.
///
/// Conformance mode refuses to start when
/// * a profile variable (`OAUTH2_ENV`, `APP_ENV`, ...) names anything other
///   than a known non-production environment, or
/// * the database is not process-local in-memory SQLite (seed data must never
///   reach a shared or production store), or a read replica is configured.
pub fn check_not_production(
    get: impl Fn(&str) -> Option<String>,
    database_url: &str,
    read_url: Option<&str>,
) -> Result<(), String> {
    for var in PROFILE_ENV_VARS {
        if let Some(value) = get(var) {
            let name = value.trim().to_ascii_lowercase();
            if !name.is_empty() && !NON_PRODUCTION_ENV_NAMES.contains(&name.as_str()) {
                return Err(format!(
                    "conformance mode refused: {var}={value:?} is not a known non-production \
                     environment (allowed: {})",
                    NON_PRODUCTION_ENV_NAMES.join(", ")
                ));
            }
        }
    }
    if !is_in_memory_sqlite(database_url) {
        return Err(
            "conformance mode refused: it requires OAUTH2_DATABASE_URL=sqlite::memory: so seeded \
             test credentials are never persisted to a shared or production store"
                .to_string(),
        );
    }
    if read_url.is_some_and(|u| !u.trim().is_empty()) {
        return Err(
            "conformance mode refused: a read-replica database URL is configured".to_string(),
        );
    }
    Ok(())
}

// ── Parsing and validation ──────────────────────────────────────────────────

fn yaml_to_json(node: &yaml_rust2::Yaml) -> Result<serde_json::Value, String> {
    use serde_json::Value;
    use yaml_rust2::Yaml;
    Ok(match node {
        Yaml::Null => Value::Null,
        Yaml::Boolean(b) => Value::Bool(*b),
        Yaml::Integer(i) => Value::from(*i),
        Yaml::Real(r) => r
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .ok_or_else(|| format!("invalid number {r:?}"))?,
        Yaml::String(s) => Value::String(s.clone()),
        Yaml::Array(items) => Value::Array(
            items
                .iter()
                .map(yaml_to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Yaml::Hash(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    Yaml::String(s) => s.clone(),
                    other => return Err(format!("non-string mapping key {other:?}")),
                };
                if out.insert(key.clone(), yaml_to_json(v)?).is_some() {
                    return Err(format!("duplicate key {key:?}"));
                }
            }
            Value::Object(out)
        }
        Yaml::Alias(_) | Yaml::BadValue => return Err("unsupported YAML node".to_string()),
    })
}

fn nonempty(what: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        Err(format!("{what} must not be empty"))
    } else {
        Ok(())
    }
}

impl Seed {
    /// Parse and validate seed text (JSON first, then YAML).
    pub fn parse(text: &str) -> Result<Seed, String> {
        let value: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => {
                let docs = yaml_rust2::YamlLoader::load_from_str(text)
                    .map_err(|e| format!("seed is neither valid JSON nor YAML: {e}"))?;
                match docs.as_slice() {
                    [doc] => yaml_to_json(doc)?,
                    [] => return Err("seed file is empty".to_string()),
                    _ => return Err("seed file must contain exactly one document".to_string()),
                }
            }
        };
        let seed: Seed =
            serde_json::from_value(value).map_err(|e| format!("seed schema violation: {e}"))?;
        seed.validate()?;
        Ok(seed)
    }

    /// Read and parse the seed at `path`. Any failure is an error; there is
    /// no default seed.
    pub fn load(path: &Path) -> Result<Seed, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read seed file {}: {e}", path.display()))?;
        Seed::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn validate(&self) -> Result<(), String> {
        let issuer = url::Url::parse(&self.issuer)
            .map_err(|e| format!("issuer {:?} is not a valid URL: {e}", self.issuer))?;
        if !matches!(issuer.scheme(), "http" | "https") {
            return Err("issuer must be an http(s) URL".to_string());
        }
        if self.issuer.ends_with('/') {
            // The server normalizes a trailing slash away; the contract forbids
            // that normalization, so an issuer it cannot honor verbatim is refused.
            return Err("issuer must not end with '/'".to_string());
        }

        if self.clients.is_empty() {
            return Err("clients must contain at least one client".to_string());
        }
        if self.users.is_empty() {
            return Err("users must contain at least one user".to_string());
        }

        let mut kids = HashSet::new();
        for key in &self.signing_keys {
            nonempty("signingKeys[].kid", &key.kid)?;
            if !kids.insert(key.kid.as_str()) {
                return Err(format!("duplicate signing key kid {:?}", key.kid));
            }
            if key.key_use.as_deref().is_some_and(|u| u != "sig") {
                return Err(format!("signing key {:?}: use must be \"sig\"", key.kid));
            }
            let well_formed = key.alg.len() == 5
                && key.alg.is_ascii()
                && matches!(&key.alg[..2], "RS" | "ES" | "PS" | "HS")
                && key.alg[2..].bytes().all(|b| b.is_ascii_digit());
            if !well_formed {
                return Err(format!(
                    "signing key {:?}: alg {:?} is not RS/ES/PS/HS + 3 digits",
                    key.kid, key.alg
                ));
            }
            if key.alg.parse::<KeyAlgorithm>().is_err() {
                return Err(format!(
                    "signing key {:?}: alg {} is not supported by this server (HS256, RS256)",
                    key.kid, key.alg
                ));
            }
        }

        let mut client_ids = HashSet::new();
        for client in &self.clients {
            nonempty("clients[].client_id", &client.client_id)?;
            if !client_ids.insert(client.client_id.as_str()) {
                return Err(format!("duplicate client_id {:?}", client.client_id));
            }
            self.validate_client(client)?;
        }

        let mut usernames = HashSet::new();
        for user in &self.users {
            nonempty("users[].username", &user.username)?;
            nonempty(
                &format!("user {:?} password", user.username),
                &user.password,
            )?;
            if !usernames.insert(user.username.as_str()) {
                return Err(format!("duplicate username {:?}", user.username));
            }
            if user.email.as_deref().is_some_and(|e| e.len() < 3) {
                return Err(format!("user {:?}: email is too short", user.username));
            }
            for approved in user.auto_approve_clients.iter().flatten() {
                if !client_ids.contains(approved.as_str()) {
                    return Err(format!(
                        "user {:?}: auto_approve_clients names unknown client {approved:?}",
                        user.username
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_client(&self, client: &SeedClient) -> Result<(), String> {
        let id = &client.client_id;
        if client.name.as_deref().is_some_and(str::is_empty) {
            return Err(format!("client {id:?}: name must not be empty"));
        }
        if let Some(method) = client.token_endpoint_auth_method.as_deref() {
            if !matches!(
                method,
                "none" | "client_secret_basic" | "client_secret_post"
            ) {
                return Err(format!(
                    "client {id:?}: token_endpoint_auth_method {method:?} is not supported"
                ));
            }
        }
        if client.client_secret.as_deref().is_some_and(str::is_empty) {
            return Err(format!("client {id:?}: client_secret must not be empty"));
        }
        if client.is_public() {
            if client.client_secret.is_some() {
                return Err(format!(
                    "client {id:?}: a public client must not carry a secret"
                ));
            }
            if client
                .token_endpoint_auth_method
                .as_deref()
                .is_some_and(|m| m != "none")
            {
                return Err(format!(
                    "client {id:?}: a public client must use method none"
                ));
            }
        } else if client.client_secret.is_none() {
            return Err(format!(
                "client {id:?}: a confidential client needs client_secret (or set public: true)"
            ));
        }
        if client.redirect_uris.is_empty() {
            return Err(format!("client {id:?}: redirect_uris must not be empty"));
        }
        for uri in &client.redirect_uris {
            let parsed = url::Url::parse(uri)
                .map_err(|e| format!("client {id:?}: redirect_uri {uri:?} is invalid: {e}"))?;
            if parsed.fragment().is_some() {
                return Err(format!(
                    "client {id:?}: redirect_uri {uri:?} has a fragment"
                ));
            }
        }
        for scope in client.scopes.iter().flatten() {
            if scope.is_empty() || scope.contains(char::is_whitespace) {
                return Err(format!("client {id:?}: invalid scope {scope:?}"));
            }
        }
        for grant in client.grant_types.iter().flatten() {
            if !GRANT_TYPES.contains(&grant.as_str()) {
                return Err(format!("client {id:?}: unsupported grant type {grant:?}"));
            }
        }
        Ok(())
    }
}

// ── Applying the seed ───────────────────────────────────────────────────────

fn generate_signing_key(key: &SeedSigningKey) -> Result<SigningKey, String> {
    let algorithm: KeyAlgorithm = key.alg.parse()?;
    let key_material = match algorithm {
        KeyAlgorithm::HS256 => {
            use rsa::rand_core::RngCore;
            let mut secret = vec![0u8; 48];
            rsa::rand_core::OsRng.fill_bytes(&mut secret);
            secret
        }
        KeyAlgorithm::RS256 => {
            use rsa::pkcs1::EncodeRsaPrivateKey;
            let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
                .map_err(|e| format!("RSA key generation failed for {:?}: {e}", key.kid))?;
            // `oauth2-core` decodes/signs RS256 keys with jsonwebtoken's
            // `(En|De)codingKey::from_rsa_pem`, which expects PKCS#1 ("BEGIN
            // RSA PRIVATE KEY") — not PKCS#8. Emit PKCS#1 so the same key
            // material round-trips through both the signer and every verifier.
            private
                .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                .map_err(|e| format!("PEM encoding failed for {:?}: {e}", key.kid))?
                .as_bytes()
                .to_vec()
        }
    };
    Ok(SigningKey {
        kid: key.kid.clone(),
        algorithm,
        key_material,
        is_current: true,
        created_at: Utc::now(),
        expires_at: None,
    })
}

/// Insert the seeded signing keys into `keyset`, each becoming the current key
/// for its algorithm. Previously current keys of that algorithm stop being
/// active immediately so the seeded `kid` is what gets published and used.
pub fn install_signing_keys(
    keyset: &mut oauth2_core::models::key_set::KeySet,
    keys: &[SigningKey],
) {
    for key in keys {
        keyset.rotate(key.clone(), Duration::ZERO);
    }
}

/// Kid of the implicitly generated RS256 key. RFC 9068 §2.1 makes RS256 a MUST
/// for JWT access tokens; the v0.2 contract seed carries no `signingKeys`, so
/// the SUT generates its own and publishes the public side (RFC 7517 §5 wants
/// a non-empty `keys` array). Without this the SUT falls back to HS256 and
/// serves `{"keys":[]}`, which the token-lifecycle JWT scenarios flag.
const DEFAULT_RS256_KID: &str = "seed-rs256";

/// Apply the seed to `storage`: clients, users, and generated signing keys.
///
/// The first failure aborts (the caller must not start serving). Key material
/// is generated here and never read from or written back to the seed.
pub async fn apply(seed: &Seed, storage: &DynStorage) -> Result<Applied, String> {
    let mut signing_keys = seed
        .signing_keys
        .iter()
        .map(generate_signing_key)
        .collect::<Result<Vec<_>, _>>()?;

    // The seed carries no private key material (see sut-interface.md); the SUT
    // generates its own. Ensure an RS256 key always exists so JWT access tokens
    // are signed with an asymmetric key and the JWKS endpoint is non-empty.
    if !signing_keys
        .iter()
        .any(|k| k.algorithm == KeyAlgorithm::RS256)
    {
        signing_keys.push(generate_signing_key(&SeedSigningKey {
            kid: DEFAULT_RS256_KID.to_string(),
            alg: "RS256".to_string(),
            key_use: Some("sig".to_string()),
        })?);
    }

    for seeded in &seed.clients {
        let public = seeded.is_public();
        let scope = match seeded.scopes.as_deref() {
            Some(scopes) if !scopes.is_empty() => scopes.join(" "),
            _ => DEFAULT_CLIENT_SCOPE.to_string(),
        };
        let grant_types = match seeded.grant_types.as_deref() {
            Some(grants) if !grants.is_empty() => grants.to_vec(),
            _ => DEFAULT_GRANT_TYPES.iter().map(|g| g.to_string()).collect(),
        };
        let mut client = Client::new(
            seeded.client_id.clone(),
            seeded.client_secret.clone().unwrap_or_default(),
            seeded.redirect_uris.clone(),
            grant_types,
            scope,
            seeded
                .name
                .clone()
                .unwrap_or_else(|| seeded.client_id.clone()),
        );
        client.token_endpoint_auth_method = if public {
            "none".to_string()
        } else {
            seeded
                .token_endpoint_auth_method
                .clone()
                .unwrap_or_else(|| "client_secret_basic".to_string())
        };
        storage
            .save_client(&client)
            .await
            .map_err(|e| format!("seeding client {:?} failed: {e}", seeded.client_id))?;
    }

    for seeded in &seed.users {
        let hash = oauth2_actix::handlers::login::hash_password(&seeded.password)
            .map_err(|e| format!("hashing password for {:?} failed: {e}", seeded.username))?;
        let email = seeded
            .email
            .clone()
            .unwrap_or_else(|| format!("{}@conformance.invalid", seeded.username));
        let user = User::new(seeded.username.clone(), hash, email);
        storage
            .save_user(&user)
            .await
            .map_err(|e| format!("seeding user {:?} failed: {e}", seeded.username))?;
    }

    Ok(Applied {
        clients: seed.clients.len(),
        users: seed.users.len(),
        signing_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    const VALID: &str = "
issuer: http://localhost:8080
clients:
  - client_id: client-a
    client_secret: test-only-secret
    token_endpoint_auth_method: client_secret_basic
    redirect_uris: [https://client.example/callback]
    grant_types: [authorization_code, refresh_token]
  - client_id: pub
    public: true
    token_endpoint_auth_method: none
    redirect_uris: [http://127.0.0.1/cb]
users:
  - username: alice
    password: test-only-password
    auto_approve_clients: [client-a]
";

    #[test]
    fn mode_is_off_by_default_and_for_explicit_zero() {
        assert_eq!(mode_from_env(env(&[])).unwrap(), None);
        assert_eq!(mode_from_env(env(&[(MODE_ENV, "0")])).unwrap(), None);
        assert_eq!(mode_from_env(env(&[(MODE_ENV, "")])).unwrap(), None);
        // A seed path alone never turns the mode on.
        assert_eq!(mode_from_env(env(&[(SEED_ENV, "/x.yaml")])).unwrap(), None);
    }

    #[test]
    fn mode_on_requires_a_seed_path() {
        assert_eq!(
            mode_from_env(env(&[(MODE_ENV, "1"), (SEED_ENV, "/s.yaml")])).unwrap(),
            Some(PathBuf::from("/s.yaml"))
        );
        assert!(mode_from_env(env(&[(MODE_ENV, "1")])).is_err());
        assert!(mode_from_env(env(&[(MODE_ENV, "1"), (SEED_ENV, "  ")])).is_err());
    }

    #[test]
    fn mode_rejects_ambiguous_values() {
        assert!(mode_from_env(env(&[(MODE_ENV, "yes"), (SEED_ENV, "/s")])).is_err());
    }

    #[test]
    fn guard_allows_unset_and_known_test_environments_on_memory_db() {
        assert!(check_not_production(env(&[]), "sqlite::memory:", None).is_ok());
        for name in ["test", "CI", "conformance", " Dev "] {
            assert!(
                check_not_production(env(&[("OAUTH2_ENV", name)]), "sqlite::memory:", None).is_ok(),
                "{name} should be allowed"
            );
        }
        assert!(check_not_production(env(&[]), "sqlite://:memory:", None).is_ok());
    }

    #[test]
    fn guard_rejects_production_and_unknown_environment_names() {
        for var in PROFILE_ENV_VARS {
            for name in ["production", "prod", "staging", "live", "typo-env"] {
                let err = check_not_production(env(&[(var, name)]), "sqlite::memory:", None)
                    .expect_err("must refuse");
                assert!(err.contains(var), "{err}");
            }
        }
    }

    #[test]
    fn guard_rejects_persistent_or_shared_databases() {
        for url in [
            "sqlite:oauth2.db?mode=rwc",
            "sqlite:///var/lib/oauth2.db",
            "postgres://u:p@db/oauth2",
            "mongodb://localhost/oauth2",
            "",
        ] {
            assert!(
                check_not_production(env(&[]), url, None).is_err(),
                "{url:?} must be refused"
            );
        }
        assert!(check_not_production(env(&[]), "sqlite::memory:", Some("postgres://r/x")).is_err());
    }

    #[test]
    fn parses_the_contract_example_shape() {
        let seed = Seed::parse(VALID).expect("valid seed");
        assert_eq!(seed.issuer, "http://localhost:8080");
        assert_eq!(seed.clients.len(), 2);
        assert!(seed.clients[1].is_public());
        assert_eq!(seed.users[0].username, "alice");
    }

    #[test]
    fn parses_json_seeds() {
        let json = r#"{"issuer":"http://localhost:8080",
            "clients":[{"client_id":"c","client_secret":"s","redirect_uris":["https://c.example/cb"]}],
            "users":[{"username":"u","password":"p"}]}"#;
        assert!(Seed::parse(json).is_ok());
    }

    fn rejects(text: &str, needle: &str) {
        let err = Seed::parse(text).expect_err("seed must be rejected");
        assert!(err.contains(needle), "expected {needle:?} in {err:?}");
    }

    #[test]
    fn rejects_schema_violations() {
        rejects("", "empty");
        rejects("a: [", "neither valid JSON nor YAML");
        rejects(
            "issuer: http://x\nclients: []\nusers: []\n",
            "at least one client",
        );
        // additionalProperties: false at every level.
        rejects(&format!("{VALID}extra: 1\n"), "unknown field");
        rejects(
            &VALID.replace("client_id: client-a", "client_id: client-a\n    bogus: 1"),
            "unknown field",
        );
        // required keys
        rejects("clients: []\nusers: []\n", "issuer");
        // issuer
        rejects(
            &VALID.replace("http://localhost:8080", "ftp://x"),
            "http(s)",
        );
        rejects(
            &VALID.replace("http://localhost:8080", "http://x/"),
            "end with '/'",
        );
        rejects(
            &VALID.replace("http://localhost:8080", "not a url"),
            "valid URL",
        );
    }

    #[test]
    fn non_ascii_signing_alg_is_rejected_without_panicking() {
        // "RéS2" is 5 bytes with a char boundary-straddling byte 2.
        let text = format!("{VALID}signingKeys:\n  - kid: k1\n    alg: \"RéS2\"\n");
        rejects(&text, "is not RS/ES/PS/HS + 3 digits");
    }

    #[test]
    fn rejects_inconsistent_clients() {
        // confidential without secret
        rejects(
            "issuer: http://x\nclients:\n  - client_id: c\n    redirect_uris: [https://c/cb]\nusers:\n  - {username: u, password: p}\n",
            "needs client_secret",
        );
        // public with secret
        rejects(
            &VALID.replace("public: true", "public: true\n    client_secret: nope"),
            "must not carry a secret",
        );
        // public with a secret-based method
        rejects(
            &VALID.replace(
                "token_endpoint_auth_method: none",
                "token_endpoint_auth_method: client_secret_post",
            ),
            "must use method none",
        );
        rejects(
            &VALID.replace("client_secret_basic", "private_key_jwt"),
            "not supported",
        );
        rejects(
            &VALID.replace(
                "grant_types: [authorization_code, refresh_token]",
                "grant_types: [implicit]",
            ),
            "unsupported grant type",
        );
        rejects(
            &VALID.replace("https://client.example/callback", "https://c/cb#frag"),
            "fragment",
        );
        rejects(
            &VALID.replace("https://client.example/callback", "not-a-uri"),
            "invalid",
        );
    }

    #[test]
    fn rejects_duplicates_and_dangling_references() {
        rejects(
            &VALID.replace("client_id: pub", "client_id: client-a"),
            "duplicate client_id",
        );
        rejects(
            &format!("{VALID}  - username: alice\n    password: x\n"),
            "duplicate username",
        );
        rejects(
            &VALID.replace(
                "auto_approve_clients: [client-a]",
                "auto_approve_clients: [ghost]",
            ),
            "unknown client",
        );
        rejects(
            &VALID.replace("password: test-only-password", "password: \"\""),
            "must not be empty",
        );
    }

    #[test]
    fn validates_signing_keys() {
        let with_keys = |keys: &str| format!("{VALID}signingKeys:\n{keys}");
        assert!(Seed::parse(&with_keys(
            "  - {kid: k1, alg: RS256, use: sig}\n  - {kid: k2, alg: HS256}\n"
        ))
        .is_ok());
        rejects(
            &with_keys("  - {kid: k1, alg: RS256}\n  - {kid: k1, alg: HS256}\n"),
            "duplicate signing key",
        );
        rejects(&with_keys("  - {kid: k1, alg: bogus}\n"), "not RS/ES/PS/HS");
        // well-formed per schema but not implemented here: must refuse, not skip
        rejects(
            &with_keys("  - {kid: k1, alg: ES256}\n"),
            "not supported by this server",
        );
        rejects(
            &with_keys("  - {kid: k1, alg: RS256, use: enc}\n"),
            "use must be",
        );
    }

    #[test]
    fn load_fails_for_missing_file() {
        let err = Seed::load(Path::new("/nonexistent/seed.yaml")).unwrap_err();
        assert!(err.contains("cannot read seed file"), "{err}");
    }

    #[tokio::test]
    async fn apply_seeds_clients_users_and_keys() {
        let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
            .await
            .unwrap();
        storage.init().await.unwrap();
        let seed = Seed::parse(&format!(
            "{VALID}signingKeys:\n  - {{kid: seed-rs, alg: RS256}}\n  - {{kid: seed-hs, alg: HS256}}\n"
        ))
        .unwrap();
        let applied = apply(&seed, &storage).await.unwrap();
        assert_eq!((applied.clients, applied.users), (2, 1));

        let confidential = storage.get_client("client-a").await.unwrap().unwrap();
        assert_eq!(confidential.client_secret, "test-only-secret");
        assert_eq!(
            confidential.token_endpoint_auth_method,
            "client_secret_basic"
        );
        assert_eq!(confidential.scope, DEFAULT_CLIENT_SCOPE);
        assert_eq!(
            confidential.get_grant_types(),
            ["authorization_code", "refresh_token"]
        );
        let public = storage.get_client("pub").await.unwrap().unwrap();
        assert!(public.is_public());
        assert!(public.client_secret.is_empty());

        let user = storage
            .get_user_by_username("alice")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            user.password_hash, "test-only-password",
            "password must be hashed"
        );
        assert!(user.password_hash.starts_with("$argon2"));
        // Only seeded identities exist: no default admin.
        assert!(storage
            .get_user_by_username("admin")
            .await
            .unwrap()
            .is_none());

        let kids: Vec<_> = applied
            .signing_keys
            .iter()
            .map(|k| k.kid.as_str())
            .collect();
        assert_eq!(kids, ["seed-rs", "seed-hs"]);
        let pem = std::str::from_utf8(&applied.signing_keys[0].key_material).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[tokio::test]
    async fn apply_aborts_on_conflicting_existing_state() {
        let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
            .await
            .unwrap();
        storage.init().await.unwrap();
        let seed = Seed::parse(VALID).unwrap();
        apply(&seed, &storage).await.unwrap();
        // Re-applying onto a non-fresh store must fail, never merge silently.
        assert!(apply(&seed, &storage).await.is_err());
    }

    #[test]
    fn install_signing_keys_makes_seeded_kid_current() {
        use oauth2_core::models::key_set::KeySet;
        let mut ks = KeySet::new();
        ks.add(SigningKey {
            kid: "hs256-initial".into(),
            algorithm: KeyAlgorithm::HS256,
            key_material: b"x".to_vec(),
            is_current: true,
            created_at: Utc::now(),
            expires_at: None,
        });
        let seed = Seed::parse(&format!(
            "{VALID}signingKeys:\n  - {{kid: seed-hs, alg: HS256}}\n"
        ))
        .unwrap();
        let key = generate_signing_key(&seed.signing_keys[0]).unwrap();
        install_signing_keys(&mut ks, &[key]);
        assert_eq!(
            ks.current_for_alg(KeyAlgorithm::HS256).unwrap().kid,
            "seed-hs"
        );
        assert!(ks.find("hs256-initial").is_none());
    }
}
