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
//! CIMD-derived client must still pass. A metadata document is self-asserted,
//! so it is held to the same rules registration applies: no privileged scopes,
//! no unsupported grant types, no dangerous redirect-URI schemes.
//!
//! Resolution never writes. Authorization codes and tokens carry a foreign key
//! to `clients(client_id)`, so a CIMD client has to exist as a row before
//! anything is issued against it — but that write happens later, through
//! [`materialize_cimd_client`], once the request has proven itself (a matching
//! redirect URI and PKCE at `/authorize`, successful client authentication at
//! `/oauth/token`). An unauthenticated caller therefore cannot drive rows into
//! the `clients` table by naming URLs.

use actix::Addr;
use url::Url;

use oauth2_config::AgentConfig;
use oauth2_core::{Client, OAuth2Error};

use crate::actors::{ClientActor, GetClient, MaterializeCimdClient};
use crate::handlers::cimd::{is_client_id_url, CimdFetcher};

/// Returned whenever a URL `client_id` arrives but CIMD is switched off.
const CIMD_DISABLED: &str = "client_id metadata documents are not enabled";

/// Resolve `client_id` to a [`Client`], without writing anything.
///
/// A URL `client_id` is dereferenced as a metadata document when CIMD is
/// enabled and a fetcher is available, and rejected with `invalid_client`
/// otherwise — never silently looked up in storage, which would let a URL
/// collide with a registered identifier.
///
/// A client resolved from a document is returned with `cimd_managed = true`
/// and a normalized `client_id`; pass it to [`materialize_cimd_client`] before
/// issuing anything against it.
pub(crate) async fn resolve_client(
    client_id: &str,
    client_actor: &Addr<ClientActor>,
    cimd: Option<&CimdFetcher>,
    agent: &AgentConfig,
) -> Result<Client, OAuth2Error> {
    let fetcher: Option<&CimdFetcher> = cimd.filter(|_| agent.cimd_enabled);

    if let Some(canonical) = cimd_url_target(client_id, fetcher) {
        let fetcher: &CimdFetcher =
            fetcher.ok_or_else(|| OAuth2Error::invalid_client(CIMD_DISABLED))?;
        let mut client: Client = fetcher.resolve(&canonical).await?;
        validate_metadata_document(&client)?;
        client.cimd_managed = true;

        // An operator who disabled the row must stay in control of it: the
        // document cannot re-enable itself by changing.
        if let Ok(Ok(existing)) = client_actor
            .send(GetClient {
                client_id: canonical.clone(),
                span: tracing::Span::current(),
            })
            .await
        {
            if !existing.enabled {
                return Err(OAuth2Error::invalid_client("client is disabled"));
            }
        }

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

/// Persist the `clients` row for a client resolved from a metadata document.
///
/// A no-op for every other client. Call this once the request has been
/// validated (redirect URI + PKCE, or client authentication) and before
/// storing an authorization code or token, so the foreign key on
/// `clients(client_id)` resolves.
pub(crate) async fn materialize_cimd_client(
    client: &Client,
    client_actor: &Addr<ClientActor>,
    agent: &AgentConfig,
) -> Result<(), OAuth2Error> {
    if !client.cimd_managed {
        return Ok(());
    }

    client_actor
        .send(MaterializeCimdClient {
            client: client.clone(),
            max_clients: agent.cimd_max_clients,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
}

/// The canonical URL to dereference for `client_id`, or `None` when this is
/// not a metadata-document identifier.
///
/// A fetcher built for tests accepts loopback `http` URLs that the plain shape
/// check rejects, so ask it when there is one.
fn cimd_url_target(client_id: &str, fetcher: Option<&CimdFetcher>) -> Option<String> {
    let canonical: String = canonical_client_id(client_id);
    let is_url: bool = match fetcher {
        Some(f) => f.accepts_client_id(&canonical),
        None => is_client_id_url(&canonical),
    };
    is_url.then_some(canonical)
}

/// The spelling of `client_id` every endpoint must key on.
///
/// A metadata-document identifier collapses to its canonical URL, so one
/// document cannot end up with two `clients` rows, two cache entries or an
/// authorization code whose `client_id` does not match the token request's.
/// Every other identifier is returned unchanged.
pub(crate) fn canonical_cimd_client_id(
    client_id: &str,
    cimd: Option<&CimdFetcher>,
    agent: &AgentConfig,
) -> String {
    cimd_url_target(client_id, cimd.filter(|_| agent.cimd_enabled))
        .unwrap_or_else(|| client_id.to_string())
}

/// Canonical spelling of a `client_id` URL.
///
/// `HTTPS://App.Example.COM:443/agent` and `https://app.example.com/agent`
/// name the same document, so both must collapse to one cache key, one fetch
/// target and one `clients` row. Anything that is not an http(s) URL — every
/// registered, opaque `client_id` — is returned unchanged.
pub(crate) fn canonical_client_id(client_id: &str) -> String {
    match Url::parse(client_id) {
        Ok(url) if matches!(url.scheme(), "https" | "http") => url.to_string(),
        _ => client_id.to_string(),
    }
}

/// Hold a fetched metadata document to the rules registration enforces.
///
/// The document is self-asserted by whoever controls the URL, so without this
/// a client could hand itself `admin` scope, a grant type registration
/// forbids, or a `javascript:` redirect URI.
fn validate_metadata_document(client: &Client) -> Result<(), OAuth2Error> {
    if crate::handlers::client::scope_contains_privileged(&client.scope) {
        return Err(OAuth2Error::invalid_client(
            "client metadata requests a privileged scope",
        ));
    }

    let grant_types: Vec<String> = client.get_grant_types();
    crate::handlers::client::validate_grant_types(&grant_types).map_err(|e| {
        OAuth2Error::invalid_client(&format!(
            "client metadata grant_types are not usable: {}",
            e.error_description.as_deref().unwrap_or("invalid")
        ))
    })?;

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

/// Longest client name shown on the login page.
///
/// The name comes from a self-asserted document, so it is bounded — and
/// bounded on its own, before the host is appended, so a padded name cannot
/// push the host (the part that actually identifies the client) out of view.
const MAX_DISPLAY_NAME_CHARS: usize = 40;

/// How to name `client` on a login / consent screen.
///
/// A URL `client_id` is shown with the host its metadata came from
/// (`Example MCP Client (app.example.com)`) so the user can tell two agents
/// claiming the same name apart.
pub(crate) fn client_display_name(client: &Client) -> String {
    let name: String = truncate_chars(&client.name, MAX_DISPLAY_NAME_CHARS);
    match metadata_host(&client.client_id) {
        Some(host) => format!("{name} ({host})"),
        None => name,
    }
}

/// Keep at most `max` characters, marking the cut with an ellipsis.
fn truncate_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let kept: String = value.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

fn metadata_host(client_id: &str) -> Option<String> {
    let url = Url::parse(client_id).ok()?;
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
    fn display_name_truncates_the_name_but_keeps_the_host() {
        let mut c = client("https://app.example.com/agent", vec![]);
        c.name = "A".repeat(200);
        let display = client_display_name(&c);
        assert!(
            display.ends_with(" (app.example.com)"),
            "the host must survive a long name: {display}"
        );
        assert_eq!(
            display.chars().count(),
            40 + " (app.example.com)".chars().count()
        );
    }

    #[test]
    fn display_name_is_bare_for_registered_client_ids() {
        let c = client("registered-client", vec![]);
        assert_eq!(client_display_name(&c), "Example MCP Client");
    }

    #[test]
    fn canonical_client_id_collapses_url_spellings() {
        assert_eq!(
            canonical_client_id("HTTPS://App.Example.COM:443/agent"),
            "https://app.example.com/agent"
        );
        assert_eq!(
            canonical_client_id("https://app.example.com/agent"),
            "https://app.example.com/agent"
        );
    }

    #[test]
    fn canonical_client_id_leaves_registered_identifiers_alone() {
        assert_eq!(canonical_client_id("test-client"), "test-client");
        assert_eq!(canonical_client_id("urn:example:app"), "urn:example:app");
    }

    #[test]
    fn metadata_document_rejects_dangerous_redirect_schemes() {
        let c = client(
            "https://app.example.com/agent",
            vec!["javascript:alert(1)".to_string()],
        );
        let err = validate_metadata_document(&c).expect_err("javascript: must be rejected");
        assert_eq!(err.error, "invalid_client");
    }

    #[test]
    fn metadata_document_rejects_privileged_scopes() {
        let mut c = client(
            "https://app.example.com/agent",
            vec!["https://app.example.com/cb".to_string()],
        );
        c.scope = "openid admin".to_string();
        let err = validate_metadata_document(&c).expect_err("admin scope must be rejected");
        assert_eq!(
            err.error_description.as_deref(),
            Some("client metadata requests a privileged scope")
        );
    }

    #[test]
    fn metadata_document_rejects_unsupported_grant_types() {
        let mut c = client(
            "https://app.example.com/agent",
            vec!["https://app.example.com/cb".to_string()],
        );
        c.grant_types = serde_json::to_string(&["urn:ietf:params:oauth:grant-type:token-exchange"])
            .expect("serialize");
        let err = validate_metadata_document(&c).expect_err("token-exchange must be rejected");
        assert_eq!(err.error, "invalid_client");
    }

    #[test]
    fn metadata_document_accepts_an_ordinary_agent() {
        let c = client(
            "https://app.example.com/agent",
            vec!["https://app.example.com/cb".to_string()],
        );
        assert!(validate_metadata_document(&c).is_ok());
    }
}
