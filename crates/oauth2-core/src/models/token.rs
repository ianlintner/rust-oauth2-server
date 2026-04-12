#![allow(dead_code)]

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::key_set::{Algorithm as KeyAlgorithm, KeySet, SigningKey};

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,   // Subject (user ID)
    pub iss: String,   // Issuer
    pub aud: String,   // Audience (client ID)
    pub exp: i64,      // Expiration time
    pub iat: i64,      // Issued at
    pub scope: String, // Scopes
    pub jti: String,   // JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

/// OIDC ID Token claims (returned when `openid` scope is requested).
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String, // Issuer
    pub sub: String, // Subject (user ID)
    pub aud: String, // Audience (client ID)
    pub exp: i64,    // Expiration time
    pub iat: i64,    // Issued at
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>, // Nonce from authorize request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>, // Access token hash (OIDC Core §3.3.2.11)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_hash: Option<String>, // Authorization code hash (OIDC Core §3.3.2.11)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
}

impl IdTokenClaims {
    pub fn new(
        issuer: &str,
        subject: String,
        client_id: String,
        duration_seconds: i64,
        access_token: Option<&str>,
    ) -> Self {
        let now = Utc::now();
        let exp = now + Duration::seconds(duration_seconds);

        // Compute at_hash: left half of SHA-256 of the access_token, base64url-encoded
        let at_hash = access_token.map(|at| {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(at.as_bytes());
            let left_half = &hash[..16]; // left 128 bits
            base64_url_encode(left_half)
        });

        Self {
            iss: issuer.to_string(),
            sub: subject,
            aud: client_id,
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nonce: None,
            at_hash,
            c_hash: None,
            email: None,
            preferred_username: None,
        }
    }

    pub fn encode(&self, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
        jsonwebtoken::encode(
            &Header::default(),
            self,
            &EncodingKey::from_secret(secret.as_ref()),
        )
    }

    pub fn encode_rs256(
        &self,
        private_key_pem: &str,
        kid: Option<&str>,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = kid.map(|s| s.to_string());
        let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;
        jsonwebtoken::encode(&header, self, &key)
    }

    /// Encode ID token claims using a SigningKey (unified HS256/RS256 path).
    pub fn encode_with_key(&self, key: &SigningKey) -> Result<String, jsonwebtoken::errors::Error> {
        let mut header = match key.algorithm {
            KeyAlgorithm::HS256 => Header::default(),
            KeyAlgorithm::RS256 => Header::new(jsonwebtoken::Algorithm::RS256),
        };
        header.kid = Some(key.kid.clone());

        let encoding_key = match key.algorithm {
            KeyAlgorithm::HS256 => EncodingKey::from_secret(&key.key_material),
            KeyAlgorithm::RS256 => EncodingKey::from_rsa_pem(&key.key_material)?,
        };

        jsonwebtoken::encode(&header, self, &encoding_key)
    }
}

/// Base64url encode without padding (per RFC 7515).
fn base64_url_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(data)
}

impl Claims {
    pub fn new(
        subject: String,
        client_id: String,
        scope: String,
        duration_seconds: i64,
        issuer: &str,
    ) -> Self {
        let now = Utc::now();
        let exp = now + Duration::seconds(duration_seconds);

        Self {
            sub: subject,
            iss: issuer.to_string(),
            aud: client_id.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            scope,
            jti: Uuid::new_v4().to_string(),
            client_id: Some(client_id),
        }
    }

    pub fn encode(&self, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let header = Header {
            typ: Some("at+JWT".to_string()),
            ..Header::default()
        };
        jsonwebtoken::encode(&header, self, &EncodingKey::from_secret(secret.as_ref()))
    }

    /// Encode as a refresh token JWT (no `typ: at+JWT` header per RFC 9068).
    pub fn encode_refresh(&self, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
        jsonwebtoken::encode(
            &Header::default(),
            self,
            &EncodingKey::from_secret(secret.as_ref()),
        )
    }

    pub fn decode(token: &str, secret: &str) -> Result<Self, jsonwebtoken::errors::Error> {
        let token_data = jsonwebtoken::decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::default(),
        )?;
        Ok(token_data.claims)
    }

    /// Encode claims using a SigningKey (supports HS256 and RS256 with kid).
    pub fn encode_with_key(&self, key: &SigningKey) -> Result<String, jsonwebtoken::errors::Error> {
        let mut header = match key.algorithm {
            KeyAlgorithm::HS256 => Header::default(),
            KeyAlgorithm::RS256 => Header::new(jsonwebtoken::Algorithm::RS256),
        };
        header.kid = Some(key.kid.clone());
        header.typ = Some("at+JWT".to_string());

        let encoding_key = match key.algorithm {
            KeyAlgorithm::HS256 => EncodingKey::from_secret(&key.key_material),
            KeyAlgorithm::RS256 => EncodingKey::from_rsa_pem(&key.key_material)?,
        };

        jsonwebtoken::encode(&header, self, &encoding_key)
    }

    /// Encode as a refresh token JWT using a SigningKey (no `typ: at+JWT`).
    pub fn encode_refresh_with_key(
        &self,
        key: &SigningKey,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let mut header = match key.algorithm {
            KeyAlgorithm::HS256 => Header::default(),
            KeyAlgorithm::RS256 => Header::new(jsonwebtoken::Algorithm::RS256),
        };
        header.kid = Some(key.kid.clone());

        let encoding_key = match key.algorithm {
            KeyAlgorithm::HS256 => EncodingKey::from_secret(&key.key_material),
            KeyAlgorithm::RS256 => EncodingKey::from_rsa_pem(&key.key_material)?,
        };

        jsonwebtoken::encode(&header, self, &encoding_key)
    }

    /// Decode and validate a token against a KeySet.
    ///
    /// If the token has a `kid` header, the matching key is used.
    /// If no `kid`, tries all active HS256 keys (backward compat).
    pub fn decode_with_keyset(
        token: &str,
        keyset: &KeySet,
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        // Read the unverified header to get kid
        let header = jsonwebtoken::decode_header(token)?;

        if let Some(ref kid) = header.kid {
            // Find the key by kid
            if let Some(key) = keyset.find(kid) {
                let decoding_key = match key.algorithm {
                    KeyAlgorithm::HS256 => DecodingKey::from_secret(&key.key_material),
                    KeyAlgorithm::RS256 => DecodingKey::from_rsa_pem(&key.key_material)?,
                };
                let validation = match key.algorithm {
                    KeyAlgorithm::HS256 => Validation::default(),
                    KeyAlgorithm::RS256 => Validation::new(jsonwebtoken::Algorithm::RS256),
                };
                let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)?;
                return Ok(token_data.claims);
            }
        }

        // No kid or kid not found — try all active HS256 keys (backward compat)
        let mut last_err = None;
        for key in keyset.active_keys() {
            if key.algorithm != KeyAlgorithm::HS256 {
                continue;
            }
            let decoding_key = DecodingKey::from_secret(&key.key_material);
            match jsonwebtoken::decode::<Claims>(token, &decoding_key, &Validation::default()) {
                Ok(data) => return Ok(data.claims),
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
        }))
    }
}

#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: String,
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: i32,
    pub scope: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    /// Lineage UUID shared by all tokens issued from the same authorization grant.
    /// Used for replay detection: if a revoked refresh token is presented, every
    /// token in the family is revoked (OAuth 2.0 Security BCP §4.13.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_family: Option<String>,
}

impl Token {
    pub fn new(
        access_token: String,
        refresh_token: Option<String>,
        client_id: String,
        user_id: Option<String>,
        scope: String,
        expires_in: i32,
        token_family: Option<String>,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(i64::from(expires_in));

        Self {
            id: Uuid::new_v4().to_string(),
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in,
            scope,
            client_id,
            user_id,
            created_at: now,
            expires_at,
            revoked: false,
            token_family,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_valid(&self) -> bool {
        !self.revoked && !self.is_expired()
    }
}

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// OIDC id_token – present when the `openid` scope was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

impl TokenResponse {
    /// Attach an OIDC id_token to an existing response.
    pub fn with_id_token(mut self, id_token: String) -> Self {
        self.id_token = Some(id_token);
        self
    }
}

impl From<Token> for TokenResponse {
    fn from(token: Token) -> Self {
        Self {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            token_type: token.token_type,
            expires_in: token.expires_in,
            scope: Some(token.scope),
            id_token: None,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// RFC 7662 §2.2: not-before time (seconds since epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// RFC 7662 §2.2: audience the token was issued for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// RFC 7662 §2.2: unique identifier for the token (JWT ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// RFC 7662 §2.2: issuer of the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
}
