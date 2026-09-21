//! Identity Assertion Authorization Grant (ID-JAG) issuance.
//!
//! Reached from the RFC 8693 token-exchange arm when
//! `requested_token_type = urn:ietf:params:oauth:token-type:id-jag`.
//! The issuance itself is not implemented yet; until it is, the arm refuses
//! the request rather than silently issuing a plain access token.

use actix_web::HttpResponse;

use oauth2_core::OAuth2Error;

use crate::handlers::token_exchange::ExchangeContext;

pub(crate) async fn issue(ctx: &ExchangeContext) -> Result<HttpResponse, OAuth2Error> {
    let _ = ctx;
    Err(OAuth2Error::invalid_request(
        "requested_token_type not enabled",
    ))
}
