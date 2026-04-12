use async_trait::async_trait;
use tracing::{field, Instrument};

use oauth2_core::{AuthorizationCode, Client, DeviceAuthorization, OAuth2Error, Token, User};
use oauth2_ports::{DynStorage, Storage};

use crate::telemetry::annotate_span_with_trace_ids;

/// A thin wrapper around a `DynStorage` that creates a tracing span for each storage call.
///
/// This lets request spans (created by actix middleware) extend naturally through
/// actors/handlers down into persistence calls.
pub struct ObservedStorage {
    inner: DynStorage,
    db_system: String,
}

impl ObservedStorage {
    pub fn new(inner: DynStorage, db_system: String) -> Self {
        Self { inner, db_system }
    }

    fn span(&self, operation: &'static str) -> tracing::Span {
        let span = tracing::info_span!(
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = operation
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "save_client",
            client_id = %client.client_id
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.save_client(client).await }
            .instrument(span)
            .await
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error> {
        let span = tracing::info_span!(
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "get_client",
            client_id = %client_id
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.get_client(client_id).await }
            .instrument(span)
            .await
    }

    async fn update_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        let span = tracing::info_span!(
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "update_client",
            client_id = %client.client_id
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.update_client(client).await }
            .instrument(span)
            .await
    }

    async fn delete_client(&self, client_id: &str) -> Result<(), OAuth2Error> {
        let span = tracing::info_span!(
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "delete_client",
            client_id = %client_id
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.delete_client(client_id).await }
            .instrument(span)
            .await
    }

    async fn save_user(&self, user: &User) -> Result<(), OAuth2Error> {
        let span = tracing::info_span!(
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "save_user",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "get_user_by_username",
            username = %username
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.get_user_by_username(username).await }
            .instrument(span)
            .await
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>, OAuth2Error> {
        let span = tracing::info_span!(
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "get_user_by_id",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "save_token",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "get_token_by_access_token",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "get_token_by_refresh_token",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "revoke_token",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "set_token_family",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "revoke_token_family",
            token_family = %family
        );
        annotate_span_with_trace_ids(&span);
        async move { self.inner.revoke_token_family(family).await }
            .instrument(span)
            .await
    }

    async fn revoke_tokens_by_user_id(&self, user_id: &str) -> Result<u64, OAuth2Error> {
        let span = tracing::info_span!(
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "revoke_tokens_by_user_id",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "save_authorization_code",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "get_authorization_code",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "mark_authorization_code_used",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "save_device_authorization",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "get_device_authorization_by_device_code",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "get_device_authorization_by_user_code",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "approve_device_authorization",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "deny_device_authorization",
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
            "db",
            trace_id = field::Empty,
            span_id = field::Empty,
            db_system = %self.db_system,
            db_operation = "mark_device_authorization_used",
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
}
