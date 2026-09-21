//! Single entry point for turning a `client_id` into a [`Client`].
//!
//! Two kinds of `client_id` reach the OAuth endpoints:
//!
//! * an opaque identifier issued at registration, resolved through
//!   [`ClientActor`], and
//! * an HTTPS URL naming a Client ID Metadata Document
//!   (draft-ietf-oauth-client-id-metadata-document-02), dereferenced through
//!   [`CimdFetcher`].
//!
//! Routing that choice in one place keeps every endpoint — authorize, PAR and
//! each token grant — agreeing on which clients exist and on the validation a
//! CIMD-derived client must still pass.

use actix::Addr;

use oauth2_config::AgentConfig;
use oauth2_core::{Client, OAuth2Error};

use crate::actors::{ClientActor, GetClient, MaterializeCimdClient};
use crate::handlers::cimd::{is_client_id_url, CimdFetcher};

/// Returned whenever a URL `client_id` arrives but CIMD is switched off.
const CIMD_DISABLED: &str = "client_id metadata documents are not enabled";

/// Resolve `client_id` to a [`Client`].
///
/// A URL `client_id` is dereferenced as a metadata document when CIMD is
/// enabled and a fetcher is available, and rejected with `invalid_client`
/// otherwise — never silently looked up in storage, which would let a URL
/// collide with a registered identifier.
pub(crate) async fn resolve_client(
    client_id: &str,
    client_actor: &Addr<ClientActor>,
    cimd: Option<&CimdFetcher>,
    agent: &AgentConfig,
) -> Result<Client, OAuth2Error> {
    let fetcher: Option<&CimdFetcher> = cimd.filter(|_| agent.cimd_enabled);

    // A fetcher built for tests accepts loopback `http` URLs that the plain
    // shape check rejects, so ask it when there is one.
    let is_url: bool = match fetcher {
        Some(f) => f.accepts_client_id(client_id),
        None => is_client_id_url(client_id),
    };

    if is_url {
        let fetcher: &CimdFetcher =
            fetcher.ok_or_else(|| OAuth2Error::invalid_client(CIMD_DISABLED))?;
        let client: Client = fetcher.resolve(client_id).await?;
        validate_metadata_redirect_uris(&client)?;
        // Authorization codes and tokens are stored with a foreign key to
        // `clients(client_id)`, so the document has to exist as a client row
        // before anything can be issued against it.
        client_actor
            .send(MaterializeCimdClient {
                client: client.clone(),
                span: tracing::Span::current(),
            })
            .await
            .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;
        return Ok(client);
    }

    client_actor
        .send(GetClient {
            client_id: client_id.to_string(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
}

/// Apply the registration-time redirect-URI rules to a fetched document.
///
/// The document is attacker-supplied and never passed through
/// `/clients/register`, so without this a CIMD client could declare
/// `javascript:` or `data:` redirect URIs and have them accepted at
/// `/authorize`. One bad entry rejects the whole document, matching what
/// registration does.
fn validate_metadata_redirect_uris(client: &Client) -> Result<(), OAuth2Error> {
    for uri in client.get_redirect_uris() {
        crate::handlers::client::validate_redirect_uri(&uri).map_err(|e| {
            OAuth2Error::invalid_client(&format!(
                "client metadata redirect_uri is not usable: {}",
                e.error_description.as_deref().unwrap_or("invalid")
            ))
        })?;
    }
    Ok(())
}

/// How to name `client` on a login / consent screen.
///
/// A URL `client_id` is shown with the host its metadata came from
/// (`Example MCP Client (app.example.com)`) so the user can tell two agents
/// claiming the same name apart.
pub(crate) fn client_display_name(client: &Client) -> String {
    match metadata_host(&client.client_id) {
        Some(host) => format!("{} ({})", client.name, host),
        None => client.name.clone(),
    }
}

fn metadata_host(client_id: &str) -> Option<String> {
    let url = url::Url::parse(client_id).ok()?;
    if !matches!(url.scheme(), "https" | "http") {
        return None;
    }
    url.host_str().map(|h| h.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(client_id: &str, redirect_uris: Vec<String>) -> Client {
        Client::new(
            client_id.to_string(),
            String::new(),
            redirect_uris,
            vec!["authorization_code".to_string()],
            "read".to_string(),
            "Example MCP Client".to_string(),
        )
    }

    #[test]
    fn display_name_appends_host_for_url_client_ids() {
        let c = client("https://app.example.com/agent", vec![]);
        assert_eq!(
            client_display_name(&c),
            "Example MCP Client (app.example.com)"
        );
    }

    #[test]
    fn display_name_is_bare_for_registered_client_ids() {
        let c = client("registered-client", vec![]);
        assert_eq!(client_display_name(&c), "Example MCP Client");
    }

    #[test]
    fn metadata_redirect_uris_reject_dangerous_schemes() {
        let c = client(
            "https://app.example.com/agent",
            vec!["javascript:alert(1)".to_string()],
        );
        let err = validate_metadata_redirect_uris(&c).expect_err("javascript: must be rejected");
        assert_eq!(err.error, "invalid_client");
    }

    #[test]
    fn metadata_redirect_uris_accept_https() {
        let c = client(
            "https://app.example.com/agent",
            vec!["https://app.example.com/cb".to_string()],
        );
        assert!(validate_metadata_redirect_uris(&c).is_ok());
    }
}
