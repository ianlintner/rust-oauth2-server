//! Client ID Metadata Document (CIMD) fetcher
//! (draft-ietf-oauth-client-id-metadata-document-02).
//!
//! A CIMD client identifies itself with an HTTPS URL; the authorization server
//! dereferences that URL to obtain the client's metadata instead of relying on
//! a prior registration. Because the client controls the URL, every fetch is an
//! attacker-influenced outbound request, so this module:
//!
//! * validates the URL shape before touching the network,
//! * applies operator allow/deny host lists,
//! * resolves the host itself and refuses special-use IP ranges, then pins the
//!   connection to those exact addresses so a DNS rebind between the check and
//!   the fetch cannot reach a private address,
//! * refuses redirects, caps the response body, and requires a JSON media type.
//!
//! Successful documents are cached; failures never are.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde_json::Value;
use url::Url;

use oauth2_core::{Client, OAuth2Error};

/// Maximum metadata document size, in bytes.
const MAX_BYTES: usize = 5120;

/// Cache TTL when the server does not advertise `Cache-Control: max-age`.
const DEFAULT_TTL_SECS: u64 = 300; // 5 minutes

/// Upper bound on the cache TTL, regardless of `Cache-Control`.
const MAX_TTL_SECS: u64 = 3600; // 1 hour

/// Per-request timeout for the metadata fetch.
const FETCH_TIMEOUT_SECS: u64 = 5;

/// Default grant types when the document does not list any.
const DEFAULT_GRANT_TYPES: [&str; 2] = ["authorization_code", "refresh_token"];

/// Client authentication methods a CIMD client may declare. A CIMD client has
/// no registration step and therefore no shared secret, so every
/// `client_secret_*` method is rejected.
const ALLOWED_AUTH_METHODS: [&str; 2] = ["none", "private_key_jwt"];

/// Returns `true` when `client_id` is a well-formed client ID URL.
///
/// The URL must use the `https` scheme and carry a non-empty path other than
/// `/`. Userinfo, a fragment, a query string, and `.`/`..` path segments are
/// all rejected — the draft makes the query a SHOULD NOT, which is tightened
/// to a hard rejection here so that the cache key and the `client_id` byte
/// comparison stay unambiguous.
pub fn is_client_id_url(client_id: &str) -> bool {
    validate_client_id_url(client_id, false).is_ok()
}

/// Shared, cloneable CIMD fetcher.
///
/// Register this as Actix `app_data` so all handlers share one cache.
#[derive(Clone, Debug)]
pub struct CimdFetcher {
    /// When non-empty, only these hosts may be dereferenced.
    allowed_hosts: Vec<String>,
    /// Hosts that may never be dereferenced. Takes precedence over the allow list.
    denied_hosts: Vec<String>,
    /// Test-only escape hatch: permit loopback addresses (and `http` on
    /// loopback hosts) so unit tests can serve documents in-process.
    allow_loopback: bool,
    /// `client_id` -> (metadata, expiry).
    cache: Arc<Mutex<HashMap<String, (Client, Instant)>>>,
}

impl CimdFetcher {
    pub fn new(allowed_hosts: Vec<String>, denied_hosts: Vec<String>) -> Self {
        Self {
            allowed_hosts: lowercase_all(allowed_hosts),
            denied_hosts: lowercase_all(denied_hosts),
            allow_loopback: false,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Allow loopback destinations. **Tests only** — this disables the SSRF
    /// guard that keeps client-controlled URLs away from the local host.
    pub fn allow_loopback_for_tests(mut self) -> Self {
        self.allow_loopback = true;
        self
    }

    /// Dereference `client_id` and return the client it describes.
    ///
    /// Returns `invalid_client` for every rejection: a malformed URL, a
    /// disallowed host, a non-200 response, an oversized or non-JSON body, or
    /// metadata that fails validation.
    pub async fn resolve(&self, client_id: &str) -> Result<Client, OAuth2Error> {
        let url: Url = validate_client_id_url(client_id, self.allow_loopback)?;
        let host: String = url
            .host_str()
            .ok_or_else(|| OAuth2Error::invalid_client("client_id URL has no host"))?
            .to_ascii_lowercase();

        self.check_host_lists(&host)?;

        if let Some(cached) = self.cached(client_id)? {
            return Ok(cached);
        }

        let port: u16 = url.port_or_known_default().unwrap_or(443);
        let addrs: Vec<SocketAddr> = self.resolve_host(&host, port).await?;

        let (doc, ttl) = fetch_document(&host, &addrs, client_id).await?;
        let client: Client = document_to_client(&doc, client_id, &host)?;

        self.store(client_id, &client, ttl)?;

        Ok(client)
    }

    fn check_host_lists(&self, host: &str) -> Result<(), OAuth2Error> {
        if self.denied_hosts.iter().any(|h| h == host) {
            return Err(OAuth2Error::invalid_client(&format!(
                "client_id host '{host}' is denied"
            )));
        }
        if !self.allowed_hosts.is_empty() && !self.allowed_hosts.iter().any(|h| h == host) {
            return Err(OAuth2Error::invalid_client(&format!(
                "client_id host '{host}' is not allowed"
            )));
        }
        Ok(())
    }

    /// Resolve `host` and reject the answer if *any* address is special-use.
    ///
    /// Rejecting on any (rather than filtering to the public subset) means a
    /// host that mixes public and private records cannot be used to probe the
    /// internal network.
    async fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, OAuth2Error> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| {
                OAuth2Error::invalid_client(&format!(
                    "client_id host '{host}' did not resolve: {e}"
                ))
            })?
            .collect();

        if addrs.is_empty() {
            return Err(OAuth2Error::invalid_client(&format!(
                "client_id host '{host}' did not resolve"
            )));
        }

        for addr in &addrs {
            if is_special_use(addr.ip(), self.allow_loopback) {
                return Err(OAuth2Error::invalid_client(&format!(
                    "client_id host '{host}' resolves to a non-public address"
                )));
            }
        }

        Ok(addrs)
    }

    fn cached(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error> {
        let guard = self.lock()?;
        Ok(guard.get(client_id).and_then(|(client, expires_at)| {
            (Instant::now() < *expires_at).then(|| client.clone())
        }))
    }

    fn store(&self, client_id: &str, client: &Client, ttl: Duration) -> Result<(), OAuth2Error> {
        let mut guard = self.lock()?;
        guard.insert(
            client_id.to_string(),
            (client.clone(), Instant::now() + ttl),
        );
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, (Client, Instant)>>, OAuth2Error> {
        self.cache
            .lock()
            .map_err(|_| OAuth2Error::new("server_error", Some("CIMD cache lock poisoned")))
    }
}

fn lowercase_all(hosts: Vec<String>) -> Vec<String> {
    hosts.into_iter().map(|h| h.to_ascii_lowercase()).collect()
}

/// Validate the client ID URL shape, returning the parsed URL.
///
/// `allow_loopback` additionally permits `http` for loopback hosts so tests can
/// serve documents from an in-process server without TLS.
fn validate_client_id_url(client_id: &str, allow_loopback: bool) -> Result<Url, OAuth2Error> {
    let url: Url = Url::parse(client_id)
        .map_err(|e| OAuth2Error::invalid_client(&format!("client_id is not a valid URL: {e}")))?;

    let host: String = url
        .host_str()
        .ok_or_else(|| OAuth2Error::invalid_client("client_id URL has no host"))?
        .to_ascii_lowercase();

    let scheme_ok: bool = url.scheme() == "https"
        || (allow_loopback
            && url.scheme() == "http"
            && matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1"));
    if !scheme_ok {
        return Err(OAuth2Error::invalid_client(
            "client_id URL must use the https scheme",
        ));
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(OAuth2Error::invalid_client(
            "client_id URL must not contain userinfo",
        ));
    }

    if url.fragment().is_some() {
        return Err(OAuth2Error::invalid_client(
            "client_id URL must not contain a fragment",
        ));
    }

    if url.query().is_some() {
        return Err(OAuth2Error::invalid_client(
            "client_id URL must not contain a query string",
        ));
    }

    if url.path().is_empty() || url.path() == "/" {
        return Err(OAuth2Error::invalid_client(
            "client_id URL must have a path other than '/'",
        ));
    }

    // `Url::parse` normalizes dot segments away, so inspect the raw input.
    if raw_path(client_id).split('/').any(is_dot_segment) {
        return Err(OAuth2Error::invalid_client(
            "client_id URL must not contain '.' or '..' path segments",
        ));
    }

    Ok(url)
}

/// Extract the raw path substring of `client_id` (everything after the
/// authority, before any query or fragment).
fn raw_path(client_id: &str) -> &str {
    let after_scheme: &str = match client_id.find("://") {
        Some(i) => &client_id[i + 3..],
        None => client_id,
    };
    let path: &str = match after_scheme.find('/') {
        Some(i) => &after_scheme[i..],
        None => return "",
    };
    let end: usize = path.find(['?', '#']).unwrap_or(path.len());
    &path[..end]
}

fn is_dot_segment(segment: &str) -> bool {
    let decoded: String = segment.to_ascii_lowercase().replace("%2e", ".");
    decoded == "." || decoded == ".."
}

/// Special-use address ranges that a client ID URL must never reach.
fn is_special_use(ip: IpAddr, allow_loopback: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            (v4.is_loopback() && !allow_loopback)
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                // 0.0.0.0/8 ("this network")
                || octets[0] == 0
                // 100.64.0.0/10 (carrier-grade NAT)
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(v6) => {
            // An IPv4-mapped address (::ffff:10.0.0.1) reaches the IPv4 host,
            // so evaluate it under the IPv4 rules.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_special_use(IpAddr::V4(mapped), allow_loopback);
            }
            let segments = v6.segments();
            (v6.is_loopback() && !allow_loopback)
                || v6.is_multicast()
                || v6.is_unspecified()
                // fc00::/7 (unique local)
                || (segments[0] & 0xfe00) == 0xfc00
                // fe80::/10 (link-local)
                || (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Fetch and parse the metadata document, returning it with its cache TTL.
async fn fetch_document(
    host: &str,
    addrs: &[SocketAddr],
    client_id: &str,
) -> Result<(Value, Duration), OAuth2Error> {
    // Pinning the already-vetted addresses closes the DNS-rebinding window
    // between the check above and the connection below.
    let http_client: reqwest::Client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .resolve_to_addrs(host, addrs)
        .build()
        .map_err(|e| {
            OAuth2Error::new(
                "server_error",
                Some(&format!("Failed to build HTTP client: {e}")),
            )
        })?;

    let mut response: reqwest::Response = http_client
        .get(client_id)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| {
            OAuth2Error::invalid_client(&format!("Failed to fetch client_id '{client_id}': {e}"))
        })?;

    // Redirects are not followed, so a 3xx lands here and is rejected.
    if response.status() != reqwest::StatusCode::OK {
        return Err(OAuth2Error::invalid_client(&format!(
            "client_id '{client_id}' returned HTTP {}",
            response.status()
        )));
    }

    check_content_type(&response, client_id)?;

    let ttl: Duration = parse_cache_control_max_age(response.headers());

    if response
        .content_length()
        .is_some_and(|n| n > MAX_BYTES as u64)
    {
        return Err(OAuth2Error::invalid_client(&format!(
            "client_id '{client_id}' metadata exceeds {MAX_BYTES} bytes"
        )));
    }

    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| {
        OAuth2Error::invalid_client(&format!(
            "Failed to read client_id '{client_id}' metadata: {e}"
        ))
    })? {
        if body.len() + chunk.len() > MAX_BYTES {
            return Err(OAuth2Error::invalid_client(&format!(
                "client_id '{client_id}' metadata exceeds {MAX_BYTES} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }

    let doc: Value = serde_json::from_slice(&body).map_err(|e| {
        OAuth2Error::invalid_client(&format!(
            "client_id '{client_id}' returned invalid JSON: {e}"
        ))
    })?;

    Ok((doc, ttl))
}

/// Require `application/json` or `application/<subtype>+json`.
fn check_content_type(response: &reqwest::Response, client_id: &str) -> Result<(), OAuth2Error> {
    let raw: &str = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let media_type: String = raw
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if media_type == "application/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
    {
        Ok(())
    } else {
        Err(OAuth2Error::invalid_client(&format!(
            "client_id '{client_id}' returned content-type '{media_type}', expected JSON"
        )))
    }
}

/// Parse `Cache-Control: max-age=N`, capped at [`MAX_TTL_SECS`] and defaulting
/// to [`DEFAULT_TTL_SECS`] when absent or unparseable.
fn parse_cache_control_max_age(headers: &reqwest::header::HeaderMap) -> Duration {
    let secs: u64 = headers
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(',')
                .map(str::trim)
                .find(|d| d.starts_with("max-age="))
                .and_then(|d| d["max-age=".len()..].parse::<u64>().ok())
        })
        .unwrap_or(DEFAULT_TTL_SECS);

    Duration::from_secs(secs.min(MAX_TTL_SECS))
}

/// Validate the metadata document and map it onto [`Client`].
fn document_to_client(doc: &Value, client_id: &str, host: &str) -> Result<Client, OAuth2Error> {
    let obj = doc
        .as_object()
        .ok_or_else(|| OAuth2Error::invalid_client("client metadata is not a JSON object"))?;

    // The document must claim exactly the URL it was fetched from, byte for
    // byte, so one URL cannot vouch for another.
    let declared: &str = obj
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or_else(|| OAuth2Error::invalid_client("client metadata has no 'client_id' string"))?;
    if declared.as_bytes() != client_id.as_bytes() {
        return Err(OAuth2Error::invalid_client(
            "client metadata 'client_id' does not match the requested URL",
        ));
    }

    if obj.contains_key("client_secret") {
        return Err(OAuth2Error::invalid_client(
            "client metadata must not contain 'client_secret'",
        ));
    }

    let redirect_uris: Vec<String> = string_array(obj.get("redirect_uris")).ok_or_else(|| {
        OAuth2Error::invalid_client("client metadata 'redirect_uris' must be an array of strings")
    })?;
    if redirect_uris.is_empty() {
        return Err(OAuth2Error::invalid_client(
            "client metadata 'redirect_uris' must not be empty",
        ));
    }

    let auth_method: &str = obj
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .unwrap_or("none");
    if !ALLOWED_AUTH_METHODS.contains(&auth_method) {
        return Err(OAuth2Error::invalid_client(&format!(
            "client metadata 'token_endpoint_auth_method' '{auth_method}' is not supported for \
             client ID metadata documents"
        )));
    }

    let grant_types: Vec<String> = string_array(obj.get("grant_types"))
        .filter(|g| !g.is_empty())
        .unwrap_or_else(|| DEFAULT_GRANT_TYPES.iter().map(|s| s.to_string()).collect());

    let name: String = obj
        .get("client_name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(host)
        .to_string();

    let scope: String = obj
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let mut client = Client::new(
        client_id.to_string(),
        String::new(),
        redirect_uris,
        grant_types,
        scope,
        name,
    );

    client.token_endpoint_auth_method = auth_method.to_string();
    client.jwks = obj
        .get("jwks")
        .map(|v| v.to_string())
        .unwrap_or_else(String::new);
    client.jwks_uri = optional_string(obj.get("jwks_uri"));
    client.client_uri = optional_string(obj.get("client_uri"));
    client.logo_uri = optional_string(obj.get("logo_uri"));
    if let Some(response_types) = string_array(obj.get("response_types")).filter(|r| !r.is_empty())
    {
        client.response_types =
            serde_json::to_string(&response_types).unwrap_or_else(|_| "[]".to_string());
    }

    Ok(client)
}

/// Interpret `value` as an array of strings; `None` when absent or the wrong shape.
fn string_array(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|v| v.as_str().map(str::to_string))
        .collect()
}

fn optional_string(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
    use serde_json::json;

    /// Single catch-all handler serving every CIMD fixture by path.
    async fn dispatch(req: HttpRequest, hits: web::Data<Arc<AtomicUsize>>) -> HttpResponse {
        hits.fetch_add(1, Ordering::SeqCst);

        let host: String = req.connection_info().host().to_string();
        let path: String = req.path().to_string();
        let client_id: String = format!("http://{host}{path}");

        let base: serde_json::Value = json!({
            "client_id": client_id,
            "redirect_uris": ["https://app.example/cb"],
            "client_name": "Test Agent",
        });

        match path.as_str() {
            "/good" => HttpResponse::Ok().json(json!({
                "client_id": client_id,
                "redirect_uris": ["https://app.example/cb", "https://app.example/cb2"],
                "client_name": "Test Agent",
                "client_uri": "https://app.example/",
                "logo_uri": "https://app.example/logo.png",
                "scope": "openid profile",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "jwks_uri": "https://app.example/jwks.json",
            })),
            "/counted" => HttpResponse::Ok().json(base),
            "/mismatch" => HttpResponse::Ok().json(json!({
                "client_id": "https://other.example/app",
                "redirect_uris": ["https://app.example/cb"],
            })),
            "/big" => HttpResponse::Ok().json(json!({
                "client_id": client_id,
                "redirect_uris": ["https://app.example/cb"],
                "client_name": "x".repeat(6000),
            })),
            "/secret-basic" => HttpResponse::Ok().json(json!({
                "client_id": client_id,
                "redirect_uris": ["https://app.example/cb"],
                "token_endpoint_auth_method": "client_secret_basic",
            })),
            "/has-secret" => HttpResponse::Ok().json(json!({
                "client_id": client_id,
                "redirect_uris": ["https://app.example/cb"],
                "client_secret": "hunter2",
            })),
            "/no-redirects" => HttpResponse::Ok().json(json!({
                "client_id": client_id,
                "redirect_uris": [],
            })),
            "/pkjwt" => HttpResponse::Ok()
                .content_type("application/cimd+json")
                .body(
                    json!({
                        "client_id": client_id,
                        "redirect_uris": ["https://app.example/cb"],
                        "token_endpoint_auth_method": "private_key_jwt",
                        "jwks": {"keys": []},
                    })
                    .to_string(),
                ),
            "/texty" => HttpResponse::Ok()
                .content_type("text/plain")
                .body(base.to_string()),
            "/redirect" => HttpResponse::Found()
                .insert_header(("Location", "/good"))
                .finish(),
            // 404 on the first hit, valid document afterwards: proves failures
            // are not cached.
            "/flaky" => {
                if hits.load(Ordering::SeqCst) <= 1 {
                    HttpResponse::NotFound().finish()
                } else {
                    HttpResponse::Ok().json(base)
                }
            }
            _ => HttpResponse::NotFound().finish(),
        }
    }

    /// Spawn an in-process HTTP server on an ephemeral loopback port.
    ///
    /// Returns `(base_url, request_counter)`.
    fn spawn_server() -> (String, Arc<AtomicUsize>) {
        let hits: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let for_app: Arc<AtomicUsize> = hits.clone();

        let server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(for_app.clone()))
                .default_service(web::to(dispatch))
        })
        .workers(1)
        .disable_signals()
        .bind(("127.0.0.1", 0))
        .expect("bind loopback");

        let port: u16 = server.addrs()[0].port();
        actix_web::rt::spawn(server.run());

        (format!("http://127.0.0.1:{port}"), hits)
    }

    fn fetcher() -> CimdFetcher {
        CimdFetcher::new(vec![], vec![]).allow_loopback_for_tests()
    }

    // ---------------------------------------------------------------
    // URL shape rules (pure)
    // ---------------------------------------------------------------

    #[test]
    fn is_client_id_url_accepts_https_url_with_path() {
        assert!(is_client_id_url("https://example.com/agent"));
        assert!(is_client_id_url("https://example.com:8443/a/b"));
    }

    #[test]
    fn is_client_id_url_rejects_root_or_empty_path() {
        assert!(!is_client_id_url("https://example.com/"));
        assert!(!is_client_id_url("https://example.com"));
    }

    #[test]
    fn is_client_id_url_rejects_userinfo() {
        assert!(!is_client_id_url("https://user@example.com/agent"));
        assert!(!is_client_id_url("https://user:pw@example.com/agent"));
    }

    #[test]
    fn is_client_id_url_rejects_fragment() {
        assert!(!is_client_id_url("https://example.com/agent#frag"));
    }

    #[test]
    fn is_client_id_url_rejects_query() {
        assert!(!is_client_id_url("https://example.com/agent?x=1"));
    }

    #[test]
    fn is_client_id_url_rejects_non_https_scheme() {
        assert!(!is_client_id_url("http://example.com/agent"));
        assert!(!is_client_id_url("ftp://example.com/agent"));
        assert!(!is_client_id_url("not a url"));
    }

    #[test]
    fn is_client_id_url_rejects_dot_segments() {
        assert!(!is_client_id_url("https://example.com/a/./b"));
        assert!(!is_client_id_url("https://example.com/a/../b"));
        assert!(!is_client_id_url("https://example.com/a/%2e%2e/b"));
    }

    // ---------------------------------------------------------------
    // SSRF / host policy
    // ---------------------------------------------------------------

    #[actix_web::test]
    async fn resolve_rejects_loopback_without_test_flag() {
        let f = CimdFetcher::new(vec![], vec![]);
        let err = f
            .resolve("https://127.0.0.1/agent")
            .await
            .expect_err("loopback must be rejected");
        assert_eq!(err.error, "invalid_client");
        assert!(err
            .error_description
            .unwrap()
            .contains("non-public address"));
    }

    #[actix_web::test]
    async fn resolve_rejects_denied_host() {
        let (base, _hits) = spawn_server();
        let f = CimdFetcher::new(vec![], vec!["127.0.0.1".to_string()]).allow_loopback_for_tests();
        let err = f
            .resolve(&format!("{base}/good"))
            .await
            .expect_err("denied host");
        assert_eq!(err.error, "invalid_client");
        assert!(err.error_description.unwrap().contains("is denied"));
    }

    #[actix_web::test]
    async fn resolve_rejects_host_outside_allowlist() {
        let (base, _hits) = spawn_server();
        let f = CimdFetcher::new(vec!["allowed.example".to_string()], vec![])
            .allow_loopback_for_tests();
        let err = f
            .resolve(&format!("{base}/good"))
            .await
            .expect_err("host not allow-listed");
        assert_eq!(err.error, "invalid_client");
        assert!(err.error_description.unwrap().contains("is not allowed"));
    }

    // ---------------------------------------------------------------
    // Fetch + validation
    // ---------------------------------------------------------------

    #[actix_web::test]
    async fn resolve_returns_client_for_valid_document() {
        let (base, _hits) = spawn_server();
        let client_id: String = format!("{base}/good");

        let client = fetcher().resolve(&client_id).await.expect("valid document");

        assert_eq!(client.client_id, client_id);
        assert_eq!(client.client_secret, "");
        assert_eq!(client.token_endpoint_auth_method, "none");
        assert_eq!(client.name, "Test Agent");
        assert_eq!(
            client.get_redirect_uris(),
            vec![
                "https://app.example/cb".to_string(),
                "https://app.example/cb2".to_string()
            ]
        );
        assert_eq!(
            client.get_grant_types(),
            vec!["authorization_code".to_string()]
        );
        assert_eq!(client.get_response_types(), vec!["code".to_string()]);
        assert_eq!(client.scope, "openid profile");
        assert_eq!(client.client_uri, "https://app.example/");
        assert_eq!(client.logo_uri, "https://app.example/logo.png");
        assert_eq!(client.jwks_uri, "https://app.example/jwks.json");
    }

    #[actix_web::test]
    async fn resolve_defaults_grant_types_and_scope() {
        let (base, _hits) = spawn_server();
        let client = fetcher()
            .resolve(&format!("{base}/counted"))
            .await
            .expect("valid document");
        assert_eq!(
            client.get_grant_types(),
            vec![
                "authorization_code".to_string(),
                "refresh_token".to_string()
            ]
        );
        assert_eq!(client.scope, "");
    }

    #[actix_web::test]
    async fn resolve_accepts_private_key_jwt_and_plus_json_content_type() {
        let (base, _hits) = spawn_server();
        let client = fetcher()
            .resolve(&format!("{base}/pkjwt"))
            .await
            .expect("private_key_jwt document");
        assert_eq!(client.token_endpoint_auth_method, "private_key_jwt");
        assert!(client.jwks.contains("keys"));
    }

    #[actix_web::test]
    async fn resolve_rejects_client_id_mismatch() {
        let (base, _hits) = spawn_server();
        let err = fetcher()
            .resolve(&format!("{base}/mismatch"))
            .await
            .expect_err("client_id mismatch");
        assert_eq!(err.error, "invalid_client");
        assert!(err
            .error_description
            .unwrap()
            .contains("does not match the requested URL"));
    }

    #[actix_web::test]
    async fn resolve_rejects_non_200_and_does_not_cache_failures() {
        let (base, hits) = spawn_server();
        let f = fetcher();
        let url: String = format!("{base}/flaky");

        let err = f.resolve(&url).await.expect_err("first hit is 404");
        assert_eq!(err.error, "invalid_client");
        assert!(err.error_description.unwrap().contains("returned HTTP 404"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // A second attempt must re-fetch (the 404 was not cached).
        let client = f.resolve(&url).await.expect("second hit succeeds");
        assert_eq!(client.client_id, url);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[actix_web::test]
    async fn resolve_caches_successful_documents() {
        let (base, hits) = spawn_server();
        let f = fetcher();
        let url: String = format!("{base}/counted");

        let first = f.resolve(&url).await.expect("first resolve");
        let second = f.resolve(&url).await.expect("cached resolve");

        assert_eq!(first.client_id, second.client_id);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "second resolve must hit cache"
        );
    }

    #[actix_web::test]
    async fn resolve_rejects_oversize_body() {
        let (base, _hits) = spawn_server();
        let err = fetcher()
            .resolve(&format!("{base}/big"))
            .await
            .expect_err("oversize body");
        assert_eq!(err.error, "invalid_client");
        assert!(err
            .error_description
            .unwrap()
            .contains("exceeds 5120 bytes"));
    }

    #[actix_web::test]
    async fn resolve_rejects_client_secret_auth_methods() {
        let (base, _hits) = spawn_server();
        let err = fetcher()
            .resolve(&format!("{base}/secret-basic"))
            .await
            .expect_err("client_secret_basic");
        assert_eq!(err.error, "invalid_client");
        assert!(err
            .error_description
            .unwrap()
            .contains("token_endpoint_auth_method"));
    }

    #[actix_web::test]
    async fn resolve_rejects_document_with_client_secret() {
        let (base, _hits) = spawn_server();
        let err = fetcher()
            .resolve(&format!("{base}/has-secret"))
            .await
            .expect_err("client_secret present");
        assert_eq!(err.error, "invalid_client");
        assert!(err
            .error_description
            .unwrap()
            .contains("must not contain 'client_secret'"));
    }

    #[actix_web::test]
    async fn resolve_rejects_empty_redirect_uris() {
        let (base, _hits) = spawn_server();
        let err = fetcher()
            .resolve(&format!("{base}/no-redirects"))
            .await
            .expect_err("empty redirect_uris");
        assert_eq!(err.error, "invalid_client");
        assert!(err.error_description.unwrap().contains("must not be empty"));
    }

    #[actix_web::test]
    async fn resolve_rejects_non_json_content_type() {
        let (base, _hits) = spawn_server();
        let err = fetcher()
            .resolve(&format!("{base}/texty"))
            .await
            .expect_err("text/plain");
        assert_eq!(err.error, "invalid_client");
        assert!(err
            .error_description
            .unwrap()
            .contains("content-type 'text/plain'"));
    }

    #[actix_web::test]
    async fn resolve_rejects_redirect_response() {
        let (base, hits) = spawn_server();
        let err = fetcher()
            .resolve(&format!("{base}/redirect"))
            .await
            .expect_err("redirects must not be followed");
        assert_eq!(err.error, "invalid_client");
        assert!(err.error_description.unwrap().contains("returned HTTP 302"));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "redirect must not be followed"
        );
    }
}
