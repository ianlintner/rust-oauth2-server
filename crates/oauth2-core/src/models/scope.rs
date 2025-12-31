#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl Scope {
    pub fn new(name: String, description: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description,
        }
    }
}

pub fn validate_scopes(requested: &str, available: &str) -> bool {
    let requested_scopes: Vec<&str> = requested.split_whitespace().collect();
    let available_scopes: Vec<&str> = available.split_whitespace().collect();

    requested_scopes
        .iter()
        .all(|s| available_scopes.contains(s))
}

pub fn intersect_scopes(requested: &str, available: &str) -> String {
    let requested_scopes: Vec<&str> = requested.split_whitespace().collect();
    let available_scopes: Vec<&str> = available.split_whitespace().collect();

    requested_scopes
        .iter()
        .filter(|s| available_scopes.contains(s))
        .map(|s| s.to_string())
        .collect::<Vec<String>>()
        .join(" ")
}
