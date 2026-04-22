use async_trait::async_trait;
use tracing::{field, Instrument};

use oauth2_core::{
    AuditLogEntry, AuthorizationCode, Client, DenylistEntry, DeviceAuthorization, ListQuery,
    OAuth2Error, Page, Token, User,
};
use oauth2_ports::{DynStorage, Storage};

use crate::telemetry::annotate_span_with_trace_ids;

/// A thin wrapper around a `DynStorage` that creates a tracing span for each storage call.
///
/// Spans use OpenTelemetry semantic convention field names (`db.system`,
/// `db.operation`, `db.name`, `net.peer.name`, `otel.kind`) so that when the
/// `otel` feature is enabled in `oauth2-observability`, the
/// `tracing-opentelemetry` bridge exports them as standard DB client spans
/// that show up correctly in Tempo/Jaeger service graphs.
///
/// `db_name` and `net_peer_name` are optional — callers that don't know the
/// real values (e.g. tests, in-memory SQLite) pass `None` and the fields are
/// recorded as empty strings.
pub struct ObservedStorage {
    inner: DynStorage,
    db_system: String,
    db_name: String,
    net_peer_name: String,
}

impl ObservedStorage {
    pub fn new(
        inner: DynStorage,
        db_system: String,
        db_name: Option<String>,
        net_peer_name: Option<String>,
    ) -> Self {
        Self {
            inner,
            db_system,
            db_name: db_name.unwrap_or_default(),
            net_peer_name: net_peer_name.unwrap_or_default(),
        }
    }

    fn span(&self, operation: &'static str) -> tracing::Span {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = operation,
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
        );
        annotate_span_with_trace_ids(&span);
        span
    }

    fn token_prefix(token: &str) -> String {
        token.chars().take(12).collect::<String>()
    }
}

#[async_trait]
impl Storage for ObservedStorage {
    async fn init(&self) -> Result<(), OAuth2Error> {
        let span = self.span("init");
        async move { self.inner.init().await }
            .instrument(span)
            .await
    }

    async fn save_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "save_client",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            client_id = %client.client_id
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.save_client(client).await }
            .instrument(span)
            .await
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "get_client",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            client_id = %client_id
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.get_client(client_id).await }
            .instrument(span)
            .await
    }

    async fn update_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "update_client",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            client_id = %client.client_id
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.update_client(client).await }
            .instrument(span)
            .await
    }

    async fn delete_client(&self, client_id: &str) -> Result<(), OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "delete_client",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            client_id = %client_id
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.delete_client(client_id).await }
            .instrument(span)
            .await
    }

    async fn save_user(&self, user: &User) -> Result<(), OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "save_user",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            user_id = %user.id,
            username = %user.username
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.save_user(user).await }
            .instrument(span)
            .await
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "get_user_by_username",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            username = %username
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.get_user_by_username(username).await }
            .instrument(span)
            .await
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>, OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "get_user_by_id",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            user_id = %user_id
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.get_user_by_id(user_id).await }
            .instrument(span)
            .await
    }

    async fn save_token(&self, token: &Token) -> Result<(), OAuth2Error> {
        // Never log full tokens.
        let token_prefix = Self::token_prefix(&token.access_token);
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "save_token",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            token_prefix = %token_prefix,
            client_id = %token.client_id,
            user_id = %token.user_id.as_deref().unwrap_or(""),
            revoked = token.revoked
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.save_token(token).await }
            .instrument(span)
            .await
    }

    async fn get_token_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        let token_prefix = Self::token_prefix(access_token);
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "get_token_by_access_token",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            token_prefix = %token_prefix,
            token_len = access_token.len()
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.get_token_by_access_token(access_token).await }
            .instrument(span)
            .await
    }

    async fn get_token_by_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        let token_prefix = Self::token_prefix(refresh_token);
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "get_token_by_refresh_token",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            token_prefix = %token_prefix,
            token_len = refresh_token.len()
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.get_token_by_refresh_token(refresh_token).await }
            .instrument(span)
            .await
    }

    async fn revoke_token(&self, token: &str) -> Result<(), OAuth2Error> {
        let token_prefix = Self::token_prefix(token);
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "revoke_token",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            token_prefix = %token_prefix,
            token_len = token.len()
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.revoke_token(token).await }
            .instrument(span)
            .await
    }

    async fn set_token_family(&self, access_token: &str, family: &str) -> Result<(), OAuth2Error> {
        let token_prefix = Self::token_prefix(access_token);
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "set_token_family",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            token_prefix = %token_prefix,
            token_family = %family
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.set_token_family(access_token, family).await }
            .instrument(span)
            .await
    }

    async fn revoke_token_family(&self, family: &str) -> Result<u64, OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "revoke_token_family",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            token_family = %family
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.revoke_token_family(family).await }
            .instrument(span)
            .await
    }

    async fn revoke_tokens_by_user_id(&self, user_id: &str) -> Result<u64, OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "revoke_tokens_by_user_id",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            user_id = %user_id
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.revoke_tokens_by_user_id(user_id).await }
            .instrument(span)
            .await
    }

    async fn save_authorization_code(
        &self,
        auth_code: &AuthorizationCode,
    ) -> Result<(), OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "save_authorization_code",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            client_id = %auth_code.client_id,
            user_id = %auth_code.user_id
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.save_authorization_code(auth_code).await }
            .instrument(span)
            .await
    }

    async fn get_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, OAuth2Error> {
        let code_prefix = code.chars().take(12).collect::<String>();
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "get_authorization_code",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            code_prefix = %code_prefix,
            code_len = code.len()
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.get_authorization_code(code).await }
            .instrument(span)
            .await
    }

    async fn mark_authorization_code_used(&self, code: &str) -> Result<(), OAuth2Error> {
        let code_prefix = code.chars().take(12).collect::<String>();
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "mark_authorization_code_used",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            code_prefix = %code_prefix,
            code_len = code.len()
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.mark_authorization_code_used(code).await }
            .instrument(span)
            .await
    }

    async fn save_device_authorization(
        &self,
        device_auth: &DeviceAuthorization,
    ) -> Result<(), OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "save_device_authorization",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            client_id = %device_auth.client_id,
            user_code = %device_auth.user_code
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.save_device_authorization(device_auth).await }
            .instrument(span)
            .await
    }

    async fn get_device_authorization_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceAuthorization>, OAuth2Error> {
        let code_prefix = device_code.chars().take(12).collect::<String>();
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "get_device_authorization_by_device_code",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            code_prefix = %code_prefix,
            code_len = device_code.len()
        );
        annotate_span_with_trace_ids(&span);
        async move {
            self.inner
                .get_device_authorization_by_device_code(device_code)
                .await
        }
        .instrument(span)
        .await
    }

    async fn get_device_authorization_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceAuthorization>, OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "get_device_authorization_by_user_code",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            user_code = %user_code
        );
        annotate_span_with_trace_ids(&span);
        async move {
            self.inner
                .get_device_authorization_by_user_code(user_code)
                .await
        }
        .instrument(span)
        .await
    }

    async fn approve_device_authorization(
        &self,
        user_code: &str,
        user_id: &str,
    ) -> Result<(), OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "approve_device_authorization",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            user_code = %user_code,
            user_id = %user_id
        );
        annotate_span_with_trace_ids(&span);
        async move {
            self.inner
                .approve_device_authorization(user_code, user_id)
                .await
        }
        .instrument(span)
        .await
    }

    async fn deny_device_authorization(&self, user_code: &str) -> Result<(), OAuth2Error> {
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "deny_device_authorization",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            user_code = %user_code
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.deny_device_authorization(user_code).await }
            .instrument(span)
            .await
    }

    async fn mark_device_authorization_used(&self, device_code: &str) -> Result<(), OAuth2Error> {
        let code_prefix = device_code.chars().take(12).collect::<String>();
        let span = tracing::info_span!(
            "db.query",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = %self.db_system,
            "db.operation" = "mark_device_authorization_used",
            "db.name" = %self.db_name,
            "net.peer.name" = %self.net_peer_name,
            "otel.kind" = "client",
            code_prefix = %code_prefix,
            code_len = device_code.len()
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.mark_device_authorization_used(device_code).await }
            .instrument(span)
            .await
    }

    async fn healthcheck(&self) -> Result<(), OAuth2Error> {
        let span = self.span("healthcheck");
        async move { self.inner.healthcheck().await }
            .instrument(span)
            .await
    }

    async fn list_all_clients(&self) -> Result<Vec<Client>, OAuth2Error> {
        let span = self.span("list_all_clients");
        async move { self.inner.list_all_clients().await }
            .instrument(span)
            .await
    }

    async fn list_all_users(&self) -> Result<Vec<User>, OAuth2Error> {
        let span = self.span("list_all_users");
        async move { self.inner.list_all_users().await }
            .instrument(span)
            .await
    }

    async fn list_all_tokens(&self) -> Result<Vec<Token>, OAuth2Error> {
        let span = self.span("list_all_tokens");
        async move { self.inner.list_all_tokens().await }
            .instrument(span)
            .await
    }

    async fn list_clients_page(&self, q: &ListQuery) -> Result<Page<Client>, OAuth2Error> {
        let span = self.span("list_clients_page");
        let q = q.clone();
        async move { self.inner.list_clients_page(&q).await }
            .instrument(span)
            .await
    }

    async fn list_users_page(&self, q: &ListQuery) -> Result<Page<User>, OAuth2Error> {
        let span = self.span("list_users_page");
        let q = q.clone();
        async move { self.inner.list_users_page(&q).await }
            .instrument(span)
            .await
    }

    async fn list_tokens_page(&self, q: &ListQuery) -> Result<Page<Token>, OAuth2Error> {
        let span = self.span("list_tokens_page");
        let q = q.clone();
        async move { self.inner.list_tokens_page(&q).await }
            .instrument(span)
            .await
    }

    async fn list_device_authorizations_page(
        &self,
        q: &ListQuery,
    ) -> Result<Page<DeviceAuthorization>, OAuth2Error> {
        let span = self.span("list_device_authorizations_page");
        let q = q.clone();
        async move { self.inner.list_device_authorizations_page(&q).await }
            .instrument(span)
            .await
    }

    async fn list_all_device_authorizations(
        &self,
    ) -> Result<Vec<DeviceAuthorization>, OAuth2Error> {
        let span = self.span("list_all_device_authorizations");
        async move { self.inner.list_all_device_authorizations().await }
            .instrument(span)
            .await
    }

    async fn expire_device_authorization(&self, device_code: &str) -> Result<(), OAuth2Error> {
        let span = self.span("expire_device_authorization");
        let dc = device_code.to_string();
        async move { self.inner.expire_device_authorization(&dc).await }
            .instrument(span)
            .await
    }

    // --- Admin: user management ---

    async fn update_user(&self, user: &User) -> Result<(), OAuth2Error> {
        let span = self.span("update_user");
        async move { self.inner.update_user(user).await }
            .instrument(span)
            .await
    }

    async fn delete_user(&self, user_id: &str) -> Result<(), OAuth2Error> {
        let span = self.span("delete_user");
        let id = user_id.to_string();
        async move { self.inner.delete_user(&id).await }
            .instrument(span)
            .await
    }

    async fn set_user_enabled(&self, user_id: &str, enabled: bool) -> Result<(), OAuth2Error> {
        let span = self.span("set_user_enabled");
        let id = user_id.to_string();
        async move { self.inner.set_user_enabled(&id, enabled).await }
            .instrument(span)
            .await
    }

    async fn set_user_role(&self, user_id: &str, role: &str) -> Result<(), OAuth2Error> {
        let span = self.span("set_user_role");
        let id = user_id.to_string();
        let role = role.to_string();
        async move { self.inner.set_user_role(&id, &role).await }
            .instrument(span)
            .await
    }

    async fn set_user_password_hash(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> Result<(), OAuth2Error> {
        let span = self.span("set_user_password_hash");
        let id = user_id.to_string();
        let hash = password_hash.to_string();
        async move { self.inner.set_user_password_hash(&id, &hash).await }
            .instrument(span)
            .await
    }

    // --- Admin: client management extensions ---

    async fn set_client_enabled(&self, client_id: &str, enabled: bool) -> Result<(), OAuth2Error> {
        let span = self.span("set_client_enabled");
        let id = client_id.to_string();
        async move { self.inner.set_client_enabled(&id, enabled).await }
            .instrument(span)
            .await
    }

    async fn set_client_secret(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), OAuth2Error> {
        let span = self.span("set_client_secret");
        let id = client_id.to_string();
        let secret = client_secret.to_string();
        async move { self.inner.set_client_secret(&id, &secret).await }
            .instrument(span)
            .await
    }

    // --- Admin: denylist ---

    async fn add_denylist_entry(&self, entry: &DenylistEntry) -> Result<(), OAuth2Error> {
        let span = self.span("add_denylist_entry");
        async move { self.inner.add_denylist_entry(entry).await }
            .instrument(span)
            .await
    }

    async fn remove_denylist_entry(&self, id: &str) -> Result<(), OAuth2Error> {
        let span = self.span("remove_denylist_entry");
        let id = id.to_string();
        async move { self.inner.remove_denylist_entry(&id).await }
            .instrument(span)
            .await
    }

    async fn list_denylist(&self, q: &ListQuery) -> Result<Page<DenylistEntry>, OAuth2Error> {
        let span = self.span("list_denylist");
        async move { self.inner.list_denylist(q).await }
            .instrument(span)
            .await
    }

    async fn find_denylist_entry(
        &self,
        kind: &str,
        value: &str,
    ) -> Result<Option<DenylistEntry>, OAuth2Error> {
        let span = self.span("find_denylist_entry");
        let kind = kind.to_string();
        let value = value.to_string();
        async move { self.inner.find_denylist_entry(&kind, &value).await }
            .instrument(span)
            .await
    }

    // --- Admin: audit log ---

    async fn write_audit_log(&self, entry: &AuditLogEntry) -> Result<(), OAuth2Error> {
        let span = self.span("write_audit_log");
        async move { self.inner.write_audit_log(entry).await }
            .instrument(span)
            .await
    }

    async fn list_audit_log(&self, q: &ListQuery) -> Result<Page<AuditLogEntry>, OAuth2Error> {
        let span = self.span("list_audit_log");
        async move { self.inner.list_audit_log(q).await }
            .instrument(span)
            .await
    }

    // --- Admin: bulk token revocation ---

    async fn revoke_tokens_by_client_id(&self, client_id: &str) -> Result<u64, OAuth2Error> {
        let span = self.span("revoke_tokens_by_client_id");
        let id = client_id.to_string();
        async move { self.inner.revoke_tokens_by_client_id(&id).await }
            .instrument(span)
            .await
    }

    // --- Backend capability flags ---

    async fn supports_denylist(&self) -> bool {
        self.inner.supports_denylist().await
    }

    async fn supports_audit_log(&self) -> bool {
        self.inner.supports_audit_log().await
    }
}
