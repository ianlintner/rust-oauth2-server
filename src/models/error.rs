#![allow(dead_code)]

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use serde::{Deserialize, Serialize};
use std::fmt;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
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

impl From<sqlx::Error> for OAuth2Error {
    fn from(err: sqlx::Error) -> Self {
        Self::new("server_error", Some(&err.to_string()))
    }
}
