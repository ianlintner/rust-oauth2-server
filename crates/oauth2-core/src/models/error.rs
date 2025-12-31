#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[cfg(feature = "actix")]
use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuth2Error {
    pub error: String,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
}

impl OAuth2Error {
    pub fn new(error: &str, description: Option<&str>) -> Self {
        Self {
            error: error.to_string(),
            error_description: description.map(|s| s.to_string()),
            error_uri: None,
        }
    }

    pub fn invalid_request(description: &str) -> Self {
        Self::new("invalid_request", Some(description))
    }

    pub fn invalid_client(description: &str) -> Self {
        Self::new("invalid_client", Some(description))
    }

    pub fn invalid_grant(description: &str) -> Self {
        Self::new("invalid_grant", Some(description))
    }

    pub fn unauthorized_client(description: &str) -> Self {
        Self::new("unauthorized_client", Some(description))
    }

    pub fn unsupported_grant_type(description: &str) -> Self {
        Self::new("unsupported_grant_type", Some(description))
    }

    pub fn invalid_scope(description: &str) -> Self {
        Self::new("invalid_scope", Some(description))
    }

    pub fn access_denied(description: &str) -> Self {
        Self::new("access_denied", Some(description))
    }
}

impl fmt::Display for OAuth2Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {:?}", self.error, self.error_description)
    }
}

#[cfg(feature = "actix")]
impl ResponseError for OAuth2Error {
    fn status_code(&self) -> StatusCode {
        match self.error.as_str() {
            "invalid_client" => StatusCode::UNAUTHORIZED,
            "access_denied" => StatusCode::FORBIDDEN,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(self)
    }
}

#[cfg(feature = "sqlx")]
impl From<sqlx::Error> for OAuth2Error {
    fn from(err: sqlx::Error) -> Self {
        // Provide a stable, non-leaky mapping for common constraint violations.
        if let sqlx::Error::Database(db_err) = &err {
            let code = db_err.code().unwrap_or_default();
            let msg = db_err.message();

            // Postgres unique violation: 23505
            // SQLite constraint error codes vary by extended code; also match by message.
            let is_unique = code == "23505"
                || code == "2067"
                || code == "1555"
                || msg.contains("UNIQUE constraint failed")
                || msg.contains("duplicate key");

            if is_unique {
                return Self::invalid_request("duplicate key");
            }
        }

        Self::new("server_error", Some(&err.to_string()))
    }
}
