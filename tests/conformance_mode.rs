//! Black-box tests for conformance test mode (SUT interface of
//! `ianlintner/oauth2-conformance`): spawn the real server binary and drive it
//! over HTTP, because the production guard and the seed run in `run()`.

use std::io::Read;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_rust_oauth2_server");
const JWT_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1tFEmvB6bs";
// S256(VERIFIER)
const CHALLENGE: &str = "6flGpdlD1lnAKqCv6S2yPx8oaGlOgMPdFCrAVB-xI1k";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn seed_file(dir: &tempfile::TempDir, port: u16) -> std::path::PathBuf {
    let path = dir.path().join("seed.yaml");
    std::fs::write(
        &path,
        format!(
            "issuer: http://127.0.0.1:{port}
signingKeys:
  - {{kid: conf-rs256, alg: RS256, use: sig}}
clients:
  - client_id: client-a
    client_secret: test-only-secret
    token_endpoint_auth_method: client_secret_basic
    redirect_uris: [https://client.example/callback]
    grant_types: [authorization_code, refresh_token]
users:
  - username: alice
    password: test-only-password
"
        ),
    )
    .unwrap();
    path
}

fn command(port: u16, env: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("OAUTH2_SERVER_HOST", "127.0.0.1")
        .env("OAUTH2_SERVER_PORT", port.to_string())
        .env("OAUTH2_DATABASE_URL", "sqlite::memory:")
        .env("OAUTH2_JWT_SECRET", JWT_SECRET)
        .env("OAUTH2_ALLOW_INSECURE_DEFAULTS", "1")
        .env("RUST_LOG", "error")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run to completion and return (success, combined output). Fails the test if
/// the process is still running after a generous timeout (it must abort).
fn run_expecting_exit(mut cmd: Command) -> (bool, String) {
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("server did not exit: conformance guard failed open");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    (status.success(), out)
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn wait_ready(base: &str, server: &mut Server) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(status) = server.0.try_wait().unwrap() {
            let mut err = String::new();
            if let Some(mut s) = server.0.stderr.take() {
                let _ = s.read_to_string(&mut err);
            }
            panic!("server exited early ({status}): {err}");
        }
        if let Ok(resp) = http().get(format!("{base}/ready")).send().await {
            if resp.status() == 200 {
                return resp.json().await.unwrap();
            }
        }
        assert!(Instant::now() < deadline, "server never became ready");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn cookie_of(resp: &reqwest::Response) -> Option<String> {
    let cookies: Vec<_> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .map(str::to_string)
        .collect();
    (!cookies.is_empty()).then(|| cookies.join("; "))
}

/// POST an `application/x-www-form-urlencoded` body without depending on the
/// `form` feature of the shared reqwest test dependency.
fn post_form(
    client: &reqwest::Client,
    url: &str,
    fields: &[(&str, &str)],
) -> reqwest::RequestBuilder {
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    let body = fields
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                utf8_percent_encode(k, NON_ALPHANUMERIC),
                utf8_percent_encode(v, NON_ALPHANUMERIC)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    client
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
}

#[tokio::test]
async fn conformance_mode_serves_seeded_flow_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let seed = seed_file(&dir, port);
    let base = format!("http://127.0.0.1:{port}");
    let mut server = Server(
        command(
            port,
            &[
                ("OAUTH2_CONFORMANCE_MODE", "1"),
                ("OAUTH2_CONFORMANCE_SEED", seed.to_str().unwrap()),
                ("OAUTH2_ENV", "test"),
            ],
        )
        .spawn()
        .unwrap(),
    );

    // Readiness reports the applied seed (counts and kids only).
    let ready = wait_ready(&base, &mut server).await;
    assert_eq!(ready["conformance"]["seed_applied"], true);
    assert_eq!(ready["conformance"]["clients"], 1);
    assert_eq!(ready["conformance"]["users"], 1);
    assert_eq!(ready["conformance"]["signing_key_ids"][0], "conf-rs256");
    let ready_text = ready.to_string();
    assert!(
        !ready_text.contains("test-only"),
        "readiness leaked a credential"
    );

    // Seeded issuer and signing key are what the server publishes.
    let disco: serde_json::Value = http()
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(disco["issuer"], base);
    let jwks: serde_json::Value = http()
        .get(format!("{base}/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["kid"] == "conf-rs256"));

    // Non-interactive login with the seeded user, then authorize.
    let query = format!(
        "response_type=code&client_id=client-a&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback\
         &scope=openid&state=xyz&code_challenge={CHALLENGE}&code_challenge_method=S256"
    );
    let authorize_url = format!("{base}/oauth/authorize?{query}");
    let first = http().get(&authorize_url).send().await.unwrap();
    assert_eq!(first.status(), 302);
    let cookie = cookie_of(&first).expect("authorize starts a session");

    let login = post_form(
        &http(),
        &format!("{base}/auth/login"),
        &[("username", "alice"), ("password", "test-only-password")],
    )
    .header("cookie", &cookie)
    .send()
    .await
    .unwrap();
    assert!(login.status().is_redirection());
    let cookie = cookie_of(&login).unwrap_or(cookie);

    let granted = http()
        .get(&authorize_url)
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(granted.status(), 302);
    let location = granted.headers()["location"].to_str().unwrap().to_string();
    let redirect = reqwest::Url::parse(&location).unwrap();
    assert_eq!(redirect.host_str(), Some("client.example"));
    let params: std::collections::HashMap<_, _> = redirect.query_pairs().into_owned().collect();
    assert_eq!(params["state"], "xyz");
    assert_eq!(
        params["iss"], base,
        "RFC 9207 iss must be the seeded issuer"
    );

    // Seeded client secret works at the token endpoint.
    let token = post_form(
        &http(),
        &format!("{base}/oauth/token"),
        &[
            ("grant_type", "authorization_code"),
            ("code", params["code"].as_str()),
            ("code_verifier", VERIFIER),
            ("redirect_uri", "https://client.example/callback"),
        ],
    )
    .basic_auth("client-a", Some("test-only-secret"))
    .send()
    .await
    .unwrap();
    assert_eq!(token.status(), 200);
    assert_eq!(token.headers()["cache-control"], "no-store");

    // The seed replaces the default admin/changeme account: in conformance
    // mode only seeded identities exist, so admin/changeme must be rejected.
    let admin = post_form(
        &http(),
        &format!("{base}/auth/login"),
        &[("username", "admin"), ("password", "changeme")],
    )
    .send()
    .await
    .unwrap();
    // A rejected credential redirects back to the login form with an error.
    let location = admin
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        admin.status().is_redirection() && location.contains("error=invalid_credentials"),
        "default admin must not be seeded into conformance mode (got {location:?})"
    );
}

#[tokio::test]
async fn mode_off_by_default_ignores_seed_and_reports_no_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let seed = seed_file(&dir, port);
    let base = format!("http://127.0.0.1:{port}");
    // Seed path present, mode switch absent: the seed must be ignored.
    let mut server = Server(
        command(
            port,
            &[
                ("OAUTH2_CONFORMANCE_SEED", seed.to_str().unwrap()),
                ("OAUTH2_SEED_PASSWORD", "a-real-seed-password-1"),
            ],
        )
        .spawn()
        .unwrap(),
    );
    let ready = wait_ready(&base, &mut server).await;
    assert!(ready.get("conformance").is_none());
    let jwks: serde_json::Value = http()
        .get(format!("{base}/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!jwks.to_string().contains("conf-rs256"));
}

fn refused(env: &[(&str, &str)], expect: &str) {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let seed = seed_file(&dir, port);
    let mut all = vec![
        ("OAUTH2_CONFORMANCE_MODE", "1"),
        ("OAUTH2_CONFORMANCE_SEED", seed.to_str().unwrap()),
    ];
    all.extend_from_slice(env);
    let (ok, out) = run_expecting_exit(command(port, &all));
    assert!(!ok, "must abort: {out}");
    assert!(out.contains(expect), "expected {expect:?} in: {out}");
    assert!(
        TcpListener::bind(("127.0.0.1", port)).is_ok(),
        "server must not have bound a port"
    );
}

#[test]
fn production_profile_with_conformance_mode_fails_closed() {
    refused(&[("OAUTH2_ENV", "production")], "conformance mode refused");
    refused(&[("APP_ENV", "prod")], "conformance mode refused");
}

#[test]
fn persistent_database_with_conformance_mode_fails_closed() {
    refused(
        &[
            ("OAUTH2_ENV", "test"),
            ("OAUTH2_DATABASE_URL", "postgres://u:p@127.0.0.1:1/db"),
        ],
        "sqlite::memory:",
    );
}

#[test]
fn invalid_or_missing_seed_fails_closed() {
    let port = free_port();
    let (ok, out) = run_expecting_exit(command(
        port,
        &[
            ("OAUTH2_CONFORMANCE_MODE", "1"),
            ("OAUTH2_CONFORMANCE_SEED", "/nonexistent/seed.yaml"),
        ],
    ));
    assert!(!ok);
    assert!(out.contains("cannot read seed file"), "{out}");

    let (ok, out) = run_expecting_exit(command(port, &[("OAUTH2_CONFORMANCE_MODE", "1")]));
    assert!(!ok);
    assert!(out.contains("OAUTH2_CONFORMANCE_SEED"), "{out}");

    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.yaml");
    std::fs::write(&bad, "issuer: http://x\nclients: []\nusers: []\nextra: 1\n").unwrap();
    let (ok, out) = run_expecting_exit(command(
        port,
        &[
            ("OAUTH2_CONFORMANCE_MODE", "1"),
            ("OAUTH2_CONFORMANCE_SEED", bad.to_str().unwrap()),
        ],
    ));
    assert!(!ok);
    assert!(out.contains("seed schema violation"), "{out}");
}
