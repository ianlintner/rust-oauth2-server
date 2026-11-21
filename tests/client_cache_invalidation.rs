//! Ordering guarantees between client lookups and cache invalidation, and the
//! metadata-only storage update used by RFC 7592.

use actix::Actor;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

use oauth2_actix::actors::client_actor::{
    ClientActor, DeleteClient, GetClient, InvalidateClient, UpdateClient, ValidateClient,
};
use oauth2_core::{AuthorizationCode, Client, OAuth2Error, Token, User};
use oauth2_ports::{DynStorage, Storage};

fn span() -> tracing::Span {
    tracing::Span::none()
}

fn make_client() -> Client {
    let client = Client::new(
        "client-cache-order".to_string(),
        "old-secret".to_string(),
        vec!["https://example.com/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "Cache order".to_string(),
    );
    // In-memory fixtures must already be in at-rest form, like rows loaded
    // from a real backend.
    client.for_storage()
}

/// One in-memory client whose first `get_client` call parks after reading the
/// row until the test releases it, so a lookup can be held "in flight".
struct GatedStorage {
    client: Mutex<Option<Client>>,
    gate: Mutex<Option<(Arc<Notify>, Arc<Notify>)>>,
}

impl GatedStorage {
    fn new(client: Client) -> (Arc<Self>, Arc<Notify>, Arc<Notify>) {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let storage = Arc::new(Self {
            client: Mutex::new(Some(client)),
            gate: Mutex::new(Some((entered.clone(), release.clone()))),
        });
        (storage, entered, release)
    }
}

#[async_trait]
impl Storage for GatedStorage {
    async fn init(&self) -> Result<(), OAuth2Error> {
        Ok(())
    }
    async fn save_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        *self.client.lock().unwrap() = Some(client.clone());
        Ok(())
    }
    async fn get_client(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error> {
        let row = self
            .client
            .lock()
            .unwrap()
            .clone()
            .filter(|c| c.client_id == client_id);
        let gate = self.gate.lock().unwrap().take();
        if let Some((entered, release)) = gate {
            entered.notify_one();
            release.notified().await;
        }
        Ok(row)
    }
    async fn update_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        *self.client.lock().unwrap() = Some(client.clone());
        Ok(())
    }
    async fn delete_client(&self, _client_id: &str) -> Result<(), OAuth2Error> {
        *self.client.lock().unwrap() = None;
        Ok(())
    }
    async fn save_user(&self, _user: &User) -> Result<(), OAuth2Error> {
        Ok(())
    }
    async fn get_user_by_username(&self, _username: &str) -> Result<Option<User>, OAuth2Error> {
        Ok(None)
    }
    async fn save_token(&self, _token: &Token) -> Result<(), OAuth2Error> {
        Ok(())
    }
    async fn get_token_by_access_token(&self, _t: &str) -> Result<Option<Token>, OAuth2Error> {
        Ok(None)
    }
    async fn get_token_by_refresh_token(&self, _t: &str) -> Result<Option<Token>, OAuth2Error> {
        Ok(None)
    }
    async fn revoke_token(&self, _token: &str) -> Result<(), OAuth2Error> {
        Ok(())
    }
    async fn save_authorization_code(&self, _c: &AuthorizationCode) -> Result<(), OAuth2Error> {
        Ok(())
    }
    async fn get_authorization_code(
        &self,
        _code: &str,
    ) -> Result<Option<AuthorizationCode>, OAuth2Error> {
        Ok(None)
    }
    async fn mark_authorization_code_used(&self, _code: &str) -> Result<(), OAuth2Error> {
        Ok(())
    }
}

async fn validate(
    actor: &actix::Addr<ClientActor>,
    client_id: &str,
    secret: &str,
) -> Result<bool, OAuth2Error> {
    actor
        .send(ValidateClient {
            client_id: client_id.to_string(),
            client_secret: secret.to_string(),
            span: span(),
        })
        .await
        .unwrap()
}

#[actix_web::test]
async fn lookup_in_flight_during_invalidation_does_not_recache_old_record() {
    let original = make_client();
    let client_id = original.client_id.clone();
    let (storage, entered, release) = GatedStorage::new(original.clone());
    let dyn_storage: DynStorage = storage.clone();
    let actor = ClientActor::new(dyn_storage).start();

    // Lookup A reads the pre-rotation row and parks inside storage.
    let lookup = {
        let actor = actor.clone();
        let client_id = client_id.clone();
        actix_web::rt::spawn(async move {
            actor
                .send(GetClient {
                    client_id,
                    span: span(),
                })
                .await
        })
    };
    entered.notified().await;

    // Rotation commits and the cache is invalidated while A is parked.
    let mut rotated = original.clone();
    rotated.client_secret = "new-secret".to_string();
    storage.save_client(&rotated.for_storage()).await.unwrap();
    actor
        .send(InvalidateClient {
            client_id: client_id.clone(),
        })
        .await
        .unwrap();

    release.notify_one();
    let seen = lookup.await.unwrap().unwrap().unwrap();
    assert!(
        seen.verify_secret("old-secret"),
        "A began before the change"
    );

    // A's fill was queued ahead of these requests; it must have been refused.
    assert!(!validate(&actor, &client_id, "old-secret").await.unwrap());
    assert!(validate(&actor, &client_id, "new-secret").await.unwrap());
}

#[actix_web::test]
async fn delete_client_message_evicts_cached_record() {
    let client = make_client();
    let client_id = client.client_id.clone();
    let (storage, entered, release) = GatedStorage::new(client);
    // Open the gate so no lookup parks.
    release.notify_one();
    let _ = entered;
    let dyn_storage: DynStorage = storage;
    let actor = ClientActor::new(dyn_storage).start();

    actor
        .send(GetClient {
            client_id: client_id.clone(),
            span: span(),
        })
        .await
        .unwrap()
        .unwrap();
    actor
        .send(DeleteClient {
            client_id: client_id.clone(),
            span: span(),
        })
        .await
        .unwrap()
        .unwrap();
    let err = actor
        .send(GetClient {
            client_id,
            span: span(),
        })
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.error, "invalid_client");
}

#[actix_web::test]
async fn metadata_update_does_not_write_secret_or_enabled() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let url = format!("sqlite://{}", tmp.path().display());
    std::mem::forget(tmp);
    let storage = oauth2_storage_factory::create_storage(&url).await.unwrap();
    storage.init().await.unwrap();

    let original = make_client();
    storage.save_client(&original).await.unwrap();

    // A copy read before a rotation and a disable (e.g. from a cache).
    let mut stale = storage
        .get_client(&original.client_id)
        .await
        .unwrap()
        .unwrap();
    storage
        .set_client_secret(&original.client_id, "rotated-secret")
        .await
        .unwrap();
    storage
        .set_client_enabled(&original.client_id, false)
        .await
        .unwrap();

    stale.name = "renamed".to_string();
    storage.update_client_metadata(&stale).await.unwrap();

    let stored = storage
        .get_client(&original.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.name, "renamed");
    assert!(stored.verify_secret("rotated-secret"));
    assert!(!stored.enabled);
}

#[actix_web::test]
async fn update_client_message_returns_stored_state_and_drops_cache() {
    let client = make_client();
    let client_id = client.client_id.clone();
    let (storage, _entered, release) = GatedStorage::new(client.clone());
    release.notify_one();
    let dyn_storage: DynStorage = storage.clone();
    let actor = ClientActor::new(dyn_storage).start();

    let mut edited = client.clone();
    edited.name = "renamed".to_string();
    let updated = actor
        .send(UpdateClient {
            client: edited,
            span: span(),
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.name, "renamed");
    assert!(validate(&actor, &client_id, "old-secret").await.unwrap());
}
