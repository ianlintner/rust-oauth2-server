//! Token type and grant type URNs used by RFC 8693 token exchange and the
//! agent/A2A profiles built on top of it.

/// RFC 8693 §3 token type identifiers.
pub const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
pub const REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
pub const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
pub const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
pub const SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";
/// Identity Assertion Authorization Grant (ID-JAG) token type.
pub const ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
/// Transaction Token (Txn-Token) type.
pub const TXN_TOKEN: &str = "urn:ietf:params:oauth:token-type:txn_token";

/// Grant type URNs.
pub const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const GRANT_TRANSACTION_AUTHORIZATION: &str =
    "urn:ietf:params:oauth:grant-type:transaction-authorization";
