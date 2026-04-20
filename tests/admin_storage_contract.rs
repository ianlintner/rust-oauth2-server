//! Storage-backend contract tests for the admin-maintainer trait methods
//! added in V17 (user/client management, denylist, audit log, bulk revoke).
//!
//! Mirrors `tests/common/run_storage_contract` in spirit but scoped to the
//! admin-specific surface. Currently runs only against the SQLx backend —
//! MongoDB admin methods are partial (denylist/audit fall back to trait
//! no-ops).

use oauth2_core::{
    AuditLogEntry, Client, DenylistEntry, ListQuery, Token, User, DENYLIST_KIND_IP,
    DENYLIST_KIND_USERNAME,
};
use oauth2_ports::DynStorage;

async fn setup_storage() -> DynStorage {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let url = format!("sqlite://{}", tmp.path().display());
    std::mem::forget(tmp);
    let storage = oauth2_storage_factory::create_storage(&url)
        .await
        .expect("create storage");
    storage.init().await.expect("init");
    storage
}

fn seed_user(name: &str) -> User {
    User::new(
        name.to_string(),
        "$argon2id$seed".to_string(),
        format!("{name}@test.example"),
    )
}

fn seed_client(suffix: &str) -> Client {
    Client::new(
        format!("client-{suffix}"),
        "secret".to_string(),
        vec!["https://example.com/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        format!("Client {suffix}"),
    )
}

// ---------------------------------------------------------------------------
// User management
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn update_user_persists_changes() {
    let storage = setup_storage().await;
    let mut user = seed_user("u_update");
    storage.save_user(&user).await.unwrap();

    user.email = "changed@test.example".to_string();
    user.role = "admin".to_string();
    user.enabled = false;
    user.password_hash = "$argon2id$new".to_string();
    user.updated_at = chrono::Utc::now();

    storage.update_user(&user).await.unwrap();
    let reloaded = storage.get_user_by_id(&user.id).await.unwrap().unwrap();
    assert_eq!(reloaded.email, "changed@test.example");
    assert_eq!(reloaded.role, "admin");
    assert!(!reloaded.enabled);
    assert_eq!(reloaded.password_hash, "$argon2id$new");
}

#[actix_web::test]
async fn set_user_enabled_flips_flag() {
    let storage = setup_storage().await;
    let user = seed_user("u_enable");
    storage.save_user(&user).await.unwrap();

    storage.set_user_enabled(&user.id, false).await.unwrap();
    assert!(
        !storage
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap()
            .enabled
    );

    storage.set_user_enabled(&user.id, true).await.unwrap();
    assert!(
        storage
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap()
            .enabled
    );
}

#[actix_web::test]
async fn set_user_role_updates_row() {
    let storage = setup_storage().await;
    let user = seed_user("u_role");
    storage.save_user(&user).await.unwrap();
    storage.set_user_role(&user.id, "admin").await.unwrap();

    assert_eq!(
        storage
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap()
            .role,
        "admin"
    );
}

#[actix_web::test]
async fn set_user_password_hash_replaces_hash() {
    let storage = setup_storage().await;
    let user = seed_user("u_pw");
    storage.save_user(&user).await.unwrap();
    storage
        .set_user_password_hash(&user.id, "$argon2id$fresh")
        .await
        .unwrap();

    assert_eq!(
        storage
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap()
            .password_hash,
        "$argon2id$fresh"
    );
}

#[actix_web::test]
async fn delete_user_removes_row_and_nulls_token_references() {
    let storage = setup_storage().await;
    let user = seed_user("u_del");
    storage.save_user(&user).await.unwrap();
    let client = seed_client("del");
    storage.save_client(&client).await.unwrap();

    let token = Token::new(
        "t_del".to_string(),
        None,
        client.client_id.clone(),
        Some(user.id.clone()),
        "read".to_string(),
        3600,
        None,
    );
    storage.save_token(&token).await.unwrap();

    storage.delete_user(&user.id).await.unwrap();
    assert!(storage.get_user_by_id(&user.id).await.unwrap().is_none());

    let t = storage
        .get_token_by_access_token("t_del")
        .await
        .unwrap()
        .unwrap();
    assert!(t.revoked, "associated token is revoked");
    assert!(t.user_id.is_none(), "user_id is unlinked to satisfy FK");
}

// ---------------------------------------------------------------------------
// Client management extensions
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn set_client_enabled_persists() {
    let storage = setup_storage().await;
    let client = seed_client("enable");
    storage.save_client(&client).await.unwrap();

    storage
        .set_client_enabled(&client.client_id, false)
        .await
        .unwrap();
    assert!(
        !storage
            .get_client(&client.client_id)
            .await
            .unwrap()
            .unwrap()
            .enabled
    );

    storage
        .set_client_enabled(&client.client_id, true)
        .await
        .unwrap();
    assert!(
        storage
            .get_client(&client.client_id)
            .await
            .unwrap()
            .unwrap()
            .enabled
    );
}

#[actix_web::test]
async fn set_client_secret_replaces_secret() {
    let storage = setup_storage().await;
    let client = seed_client("secret");
    storage.save_client(&client).await.unwrap();

    storage
        .set_client_secret(&client.client_id, "brand-new-secret")
        .await
        .unwrap();
    let reloaded = storage
        .get_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.client_secret, "brand-new-secret");
}

// ---------------------------------------------------------------------------
// Denylist
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn denylist_add_find_remove_round_trip() {
    let storage = setup_storage().await;
    let entry = DenylistEntry::new(DENYLIST_KIND_IP, "198.51.100.1", "test", "admin");
    storage.add_denylist_entry(&entry).await.unwrap();

    let found = storage
        .find_denylist_entry(DENYLIST_KIND_IP, "198.51.100.1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.reason, "test");

    storage.remove_denylist_entry(&entry.id).await.unwrap();
    assert!(storage
        .find_denylist_entry(DENYLIST_KIND_IP, "198.51.100.1")
        .await
        .unwrap()
        .is_none());
}

#[actix_web::test]
async fn denylist_upsert_on_duplicate_kind_value() {
    let storage = setup_storage().await;
    let first = DenylistEntry::new(DENYLIST_KIND_USERNAME, "mallory", "first", "admin");
    storage.add_denylist_entry(&first).await.unwrap();

    let second = DenylistEntry::new(DENYLIST_KIND_USERNAME, "mallory", "updated", "admin");
    storage.add_denylist_entry(&second).await.unwrap();

    let page = storage.list_denylist(&ListQuery::default()).await.unwrap();
    assert_eq!(page.total, 1);
    let found = storage
        .find_denylist_entry(DENYLIST_KIND_USERNAME, "mallory")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.reason, "updated");
}

#[actix_web::test]
async fn denylist_list_is_paginated() {
    let storage = setup_storage().await;
    for i in 0..12 {
        let entry = DenylistEntry::new(DENYLIST_KIND_IP, &format!("10.0.0.{i}"), "bulk", "admin");
        storage.add_denylist_entry(&entry).await.unwrap();
    }

    let q = ListQuery {
        limit: Some(5),
        offset: Some(0),
        ..Default::default()
    };
    let page = storage.list_denylist(&q).await.unwrap();
    assert_eq!(page.items.len(), 5);
    assert_eq!(page.total, 12);

    let q = ListQuery {
        limit: Some(5),
        offset: Some(10),
        ..Default::default()
    };
    let page = storage.list_denylist(&q).await.unwrap();
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.total, 12);
}

#[actix_web::test]
async fn denylist_find_skips_expired_entries() {
    let storage = setup_storage().await;
    let mut entry = DenylistEntry::new(DENYLIST_KIND_IP, "192.0.2.50", "stale", "admin");
    entry.expires_at = Some(chrono::Utc::now() - chrono::Duration::hours(1));
    storage.add_denylist_entry(&entry).await.unwrap();

    assert!(storage
        .find_denylist_entry(DENYLIST_KIND_IP, "192.0.2.50")
        .await
        .unwrap()
        .is_none());
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn audit_log_write_and_list_newest_first() {
    let storage = setup_storage().await;

    for i in 0..3 {
        let mut entry = AuditLogEntry::new("admin", "admin@test.example", &format!("a.{i}"));
        entry.created_at = chrono::Utc::now() + chrono::Duration::seconds(i);
        storage.write_audit_log(&entry).await.unwrap();
    }

    let page = storage.list_audit_log(&ListQuery::default()).await.unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(
        page.items[0].action, "a.2",
        "desc order returns newest first"
    );
}

#[actix_web::test]
async fn audit_log_respects_limit_offset() {
    let storage = setup_storage().await;
    for i in 0..7 {
        let mut entry = AuditLogEntry::new("admin", "admin@test.example", &format!("a.{i:02}"));
        entry.created_at = chrono::Utc::now() + chrono::Duration::seconds(i);
        storage.write_audit_log(&entry).await.unwrap();
    }

    let q = ListQuery {
        limit: Some(2),
        offset: Some(2),
        ..Default::default()
    };
    let page = storage.list_audit_log(&q).await.unwrap();
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.total, 7);
}

// ---------------------------------------------------------------------------
// Bulk token revocation
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn revoke_tokens_by_client_id_only_touches_that_client() {
    let storage = setup_storage().await;
    let c1 = seed_client("a");
    let c2 = seed_client("b");
    storage.save_client(&c1).await.unwrap();
    storage.save_client(&c2).await.unwrap();

    for (id, client) in [("t1", &c1), ("t2", &c2), ("t3", &c1)] {
        storage
            .save_token(&Token::new(
                id.to_string(),
                None,
                client.client_id.clone(),
                None,
                "read".to_string(),
                3600,
                None,
            ))
            .await
            .unwrap();
    }

    let count = storage
        .revoke_tokens_by_client_id(&c1.client_id)
        .await
        .unwrap();
    assert_eq!(count, 2);

    let t1 = storage
        .get_token_by_access_token("t1")
        .await
        .unwrap()
        .unwrap();
    let t2 = storage
        .get_token_by_access_token("t2")
        .await
        .unwrap()
        .unwrap();
    let t3 = storage
        .get_token_by_access_token("t3")
        .await
        .unwrap()
        .unwrap();
    assert!(t1.revoked);
    assert!(!t2.revoked);
    assert!(t3.revoked);
}

#[actix_web::test]
async fn revoke_tokens_by_client_id_idempotent() {
    let storage = setup_storage().await;
    let c = seed_client("idem");
    storage.save_client(&c).await.unwrap();
    storage
        .save_token(&Token::new(
            "t".to_string(),
            None,
            c.client_id.clone(),
            None,
            "read".to_string(),
            3600,
            None,
        ))
        .await
        .unwrap();

    let first = storage
        .revoke_tokens_by_client_id(&c.client_id)
        .await
        .unwrap();
    let second = storage
        .revoke_tokens_by_client_id(&c.client_id)
        .await
        .unwrap();
    assert_eq!(first, 1);
    assert_eq!(second, 0, "already-revoked tokens are not counted again");
}
