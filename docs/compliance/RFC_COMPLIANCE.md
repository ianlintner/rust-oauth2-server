# RFC Compliance Matrix

This document tracks which OAuth2/OIDC specification requirements are covered by automated tests.
Each row maps a specific RFC section to one or more test functions.

**Legend**: ✅ Covered | ⚠️ Partial | ❌ Not Covered

---

## RFC 6749 — The OAuth 2.0 Authorization Framework

Test file: [`tests/compliance_rfc6749.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/compliance_rfc6749.rs)  
Supplemental: [`tests/security_http.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/security_http.rs)

| Section | Requirement                                                         | Test Function                                                    | Status |
| ------- | ------------------------------------------------------------------- | ---------------------------------------------------------------- | ------ |
| §3.1.2  | Redirect URI must be pre-registered and match exactly               | `rfc6749_s3_1_2_redirect_uri_must_match`                         | ✅     |
| §4.1.1  | Authorization endpoint requires `response_type=code`                | `rfc6749_s4_1_1_authorize_requires_response_type`                | ✅     |
| §4.1.1  | Unknown `response_type` is rejected                                 | `rfc6749_s4_1_1_authorize_rejects_unknown_response_type`         | ✅     |
| §4.1.1  | `client_id` is required                                             | `rfc6749_s4_1_1_authorize_requires_client_id`                    | ✅     |
| §4.1.1  | Unknown `client_id` is rejected                                     | `rfc6749_s4_1_1_authorize_rejects_unknown_client`                | ✅     |
| §4.1.2  | Successful authorize redirects with `code`                          | `rfc6749_s4_1_2_authorize_redirects_with_code`                   | ✅     |
| §4.1.2  | `state` parameter is echoed back verbatim                           | `rfc6749_s4_1_2_state_is_echoed_in_redirect`                     | ✅     |
| §4.1.3  | Token endpoint validates `grant_type` is present                    | `rfc6749_s4_1_3_token_requires_grant_type`                       | ✅     |
| §4.1.3  | Unsupported `grant_type` is rejected                                | `rfc6749_s4_1_3_token_rejects_unsupported_grant_type`            | ✅     |
| §4.1.3  | Code exchange with wrong client is rejected                         | `rfc6749_s4_1_3_token_rejects_wrong_client_for_code`             | ✅     |
| §4.2    | Implicit grant (`response_type=token`) is rejected                  | `authorize_rejects_implicit_response_type` (security_http.rs)    | ✅     |
| §4.4.2  | Client credentials flow returns access token                        | `rfc6749_s4_4_2_client_credentials_returns_access_token`         | ✅     |
| §4.4.3  | Client credentials with invalid secret → `invalid_client`           | `rfc6749_s4_4_3_client_credentials_rejects_invalid_client`       | ✅     |
| §2.3.1  | Client auth via HTTP Basic header                                   | `rfc6749_s2_3_client_auth_via_basic_header`                      | ✅     |
| §2.3.1  | Client auth via request body (`client_id` + `client_secret`)        | `rfc6749_s2_3_client_auth_via_post_params`                       | ✅     |
| §2.3.1  | URL-encoded credentials in Basic auth                               | `token_basic_auth_decodes_url_encoded_secret` (security_http.rs) | ✅     |
| §5.1    | Token response includes `token_type=bearer` and `access_token`      | `rfc6749_s5_1_token_response_has_required_fields`                | ✅     |
| §5.2    | Token response has `Cache-Control: no-store` and `Pragma: no-cache` | `rfc6749_s5_2_token_response_no_cache_headers`                   | ✅     |
| §5.2    | Error response JSON has `error` field                               | `rfc6749_s5_2_error_response_format`                             | ✅     |
| §10.3   | Authorization code must not be accepted twice                       | `rfc6749_s10_3_authorization_code_single_use`                    | ✅     |

---

## RFC 7636 — PKCE (Proof Key for Code Exchange)

Test file: [`tests/compliance_rfc7636.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/compliance_rfc7636.rs)

| Section | Requirement                                              | Test Function                                         | Status |
| ------- | -------------------------------------------------------- | ----------------------------------------------------- | ------ |
| §4.1    | Authorization code flow requires PKCE                    | `rfc7636_s4_1_pkce_required_for_authorization_code`   | ✅     |
| §4.2    | `S256` is the only accepted challenge method             | `rfc7636_s4_2_s256_challenge_method_is_accepted`      | ✅     |
| §4.2    | `plain` challenge method is rejected                     | `rfc7636_s4_2_plain_method_is_rejected`               | ✅     |
| §4.3    | Valid verifier exchanges code successfully               | `rfc7636_s4_3_valid_verifier_exchanges_code`          | ✅     |
| §4.3    | Wrong verifier is rejected with `invalid_grant`          | `rfc7636_s4_3_wrong_verifier_is_rejected`             | ✅     |
| §4.3    | Missing verifier for a PKCE code → `invalid_grant`       | `rfc7636_s4_3_missing_verifier_rejects_pkce_code`     | ✅     |
| §4.1    | Verifier shorter than 43 chars → `invalid_grant`         | `rfc7636_s4_1_verifier_min_length_43`                 | ✅     |
| §4.1    | Verifier longer than 128 chars → `invalid_grant`         | `rfc7636_s4_1_verifier_max_length_128`                | ✅     |
| §4.2    | `code_challenge_method` without `code_challenge` → error | `rfc7636_s4_2_method_without_challenge_rejected`      | ✅     |
| §4.3    | Sending raw verifier as challenge in exchange → rejected | `rfc7636_s4_3_sending_verifier_as_challenge_rejected` | ✅     |

---

## RFC 7662 — OAuth 2.0 Token Introspection

Test file: [`tests/compliance_rfc7662_7009.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/compliance_rfc7662_7009.rs)

| Section | Requirement                                 | Test Function                                         | Status |
| ------- | ------------------------------------------- | ----------------------------------------------------- | ------ |
| §2      | Valid token introspects with `active: true` | `rfc7662_s2_active_token_returns_true`                | ✅     |
| §2      | Invalid/unknown token → `active: false`     | `rfc7662_s2_invalid_token_returns_false`              | ✅     |
| §2      | Revoked token → `active: false`             | `rfc7662_s2_revoked_token_returns_inactive`           | ✅     |
| §2.1    | Introspect requires client authentication   | `rfc7662_s2_1_introspect_requires_client_auth`        | ✅     |
| §2.2    | Response contains `scope` field             | `rfc7662_s2_2_introspect_returns_scope`               | ✅     |
| §2.2    | Response contains `client_id` field         | `rfc7662_s2_2_introspect_returns_client_id`           | ✅     |
| §2.2    | Response contains `sub` for user tokens     | `rfc7662_s2_2_introspect_returns_sub_for_user_tokens` | ✅     |
| §2.2    | Response contains `token_type`              | `rfc7662_s2_2_introspect_returns_token_type`          | ✅     |

---

## RFC 7009 — OAuth 2.0 Token Revocation

Test file: [`tests/compliance_rfc7662_7009.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/compliance_rfc7662_7009.rs)

| Section | Requirement                                            | Test Function                                   | Status |
| ------- | ------------------------------------------------------ | ----------------------------------------------- | ------ |
| §2.1    | Revoking a valid token returns 200 OK                  | `rfc7009_s2_1_revoke_valid_token_returns_200`   | ✅     |
| §2.2    | Revoking an unknown/invalid token still returns 200 OK | `rfc7009_s2_2_revoke_unknown_token_returns_200` | ✅     |
| §2.1    | Revoke requires client authentication                  | `rfc7009_s2_1_revoke_requires_client_auth`      | ✅     |
| §2.1    | Revoked token is subsequently inactive                 | `rfc7009_s2_1_revoked_token_becomes_inactive`   | ✅     |
| §2.2    | Unsupported `token_type_hint` is tolerated             | `rfc7009_s2_2_unsupported_hint_is_tolerated`    | ✅     |

---

## RFC 6750 — Bearer Token Usage

Test file: [`tests/compliance_rfc6750.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/compliance_rfc6750.rs)

| Section | Requirement                                           | Test Function                                   | Status |
| ------- | ----------------------------------------------------- | ----------------------------------------------- | ------ |
| §2.1    | Bearer token in `Authorization` header accepted       | `rfc6750_s2_1_bearer_header_accepted`           | ✅     |
| §2.1    | Invalid token → 401 with `WWW-Authenticate` header    | `rfc6750_s2_1_invalid_token_returns_401`        | ✅     |
| §2.1    | Missing token → 401 with `WWW-Authenticate` header    | `rfc6750_s2_1_missing_token_returns_401`        | ✅     |
| §3.1    | `WWW-Authenticate: Bearer` present on unauthorized    | `rfc6750_s3_1_www_authenticate_header_on_401`   | ✅     |
| §3.1    | `invalid_token` error code for expired/invalid tokens | `rfc6750_s3_1_error_code_invalid_token`         | ✅     |
| §2.1    | Token with sufficient scope returns claims            | `rfc6750_s2_1_valid_token_returns_user_claims`  | ✅     |
| §2.3    | URI query parameter bearer is not supported           | `rfc6750_s2_3_query_param_bearer_not_supported` | ✅     |
| §2.2    | Form-encoded body bearer is not supported             | `rfc6750_s2_2_form_body_bearer_not_supported`   | ✅     |

---

## RFC 8414 — OAuth 2.0 Authorization Server Metadata

Test file: [`tests/compliance_rfc8414.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/compliance_rfc8414.rs)

| Section | Requirement                                                                                  | Test Function                                           | Status |
| ------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ------ |
| §2      | `/.well-known/openid-configuration` returns 200 JSON                                         | `rfc8414_s2_discovery_endpoint_returns_200`             | ✅     |
| §2      | Response includes `issuer` matching the server URL                                           | `rfc8414_s2_issuer_is_present_and_matches`              | ✅     |
| §2      | Response includes `authorization_endpoint`                                                   | `rfc8414_s2_authorization_endpoint_present`             | ✅     |
| §2      | Response includes `token_endpoint`                                                           | `rfc8414_s2_token_endpoint_present`                     | ✅     |
| §2      | Response includes `jwks_uri`                                                                 | `rfc8414_s2_jwks_uri_present`                           | ✅     |
| §2      | `response_types_supported` does not include `token` (implicit)                               | `rfc8414_s2_implicit_not_advertised`                    | ✅     |
| §2      | `code_challenge_methods_supported` includes `S256` only                                      | `rfc8414_s2_pkce_s256_only_advertised`                  | ✅     |
| §2      | `grant_types_supported` includes `authorization_code`, `client_credentials`, `refresh_token` | `rfc8414_s2_grant_types_advertised`                     | ✅     |
| §2      | `introspection_endpoint` and `revocation_endpoint` are present                               | `rfc8414_s2_introspection_revocation_endpoints_present` | ✅     |

---

## OpenID Connect Core 1.0

Test file: [`tests/compliance_oidc_core.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/compliance_oidc_core.rs)

| Section  | Requirement                                                      | Test Function                                     | Status |
| -------- | ---------------------------------------------------------------- | ------------------------------------------------- | ------ |
| §3.1     | Successful OIDC code flow returns `id_token` with `openid` scope | `oidc_core_s3_1_id_token_issued_for_openid_scope` | ✅     |
| §3.1.3.3 | `id_token` is a valid JWT with three `.`-separated parts         | `oidc_core_s3_1_3_id_token_is_valid_jwt`          | ✅     |
| §2       | `sub` claim is present and non-empty in `id_token`               | `oidc_core_s2_sub_claim_present`                  | ✅     |
| §2       | `iss` claim matches the issuer                                   | `oidc_core_s2_iss_claim_matches_issuer`           | ✅     |
| §2       | `aud` claim contains the `client_id`                             | `oidc_core_s2_aud_claim_contains_client_id`       | ✅     |
| §2       | `exp` and `iat` claims are present and numeric                   | `oidc_core_s2_exp_and_iat_claims_present`         | ✅     |
| §3.1.2.1 | `nonce` from authorize request is echoed in `id_token`           | `oidc_core_s3_1_2_1_nonce_echoed_in_id_token`     | ✅     |
| §5.3     | UserInfo endpoint returns `sub` claim                            | `oidc_core_s5_3_userinfo_returns_sub`             | ✅     |
| §5.3     | UserInfo endpoint requires Bearer token                          | `oidc_core_s5_3_userinfo_requires_bearer`         | ✅     |
| §5.3     | UserInfo `sub` matches `sub` in `id_token`                       | `oidc_core_s5_3_userinfo_sub_matches_id_token`    | ✅     |
| §3.1     | Token without `openid` scope does not include `id_token`         | `oidc_core_s3_1_no_id_token_without_openid_scope` | ✅     |

---

## RFC 8628 — OAuth 2.0 Device Authorization Grant

Test file: [`tests/compliance_rfc8628.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/compliance_rfc8628.rs)  
Supplemental: [`tests/device_flow.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/device_flow.rs)

| Section | Requirement                                                                          | Test Function                                               | Status |
| ------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------- | ------ |
| §3.1    | Device authorization endpoint returns `device_code`, `user_code`, `verification_uri` | `rfc8628_s3_1_device_authorization_returns_required_fields` | ✅     |
| §3.1    | `expires_in` and `interval` are present in response                                  | `rfc8628_s3_1_expires_in_and_interval_present`              | ✅     |
| §3.2    | `authorization_pending` while user has not yet approved                              | `rfc8628_s3_2_returns_authorization_pending`                | ✅     |
| §3.2    | `slow_down` error is returned when polling too fast                                  | `rfc8628_s3_2_slow_down_on_rapid_polling`                   | ⚠️     |
| §3.2    | `expired_token` when device code has expired                                         | `rfc8628_s3_2_expired_device_code_returns_error`            | ✅     |
| §3.5    | Unsupported `grant_type` string → `unsupported_grant_type`                           | `rfc8628_s3_5_unsupported_grant_type`                       | ✅     |
| §6.1    | Client must be registered for device flow grant type                                 | `rfc8628_s6_1_client_must_support_device_grant`             | ✅     |
| §3.2    | `access_denied` when user explicitly rejects                                         | `rfc8628_s3_2_access_denied`                                | ⚠️     |
| §3.1    | `verification_uri_complete` is included when supported                               | `rfc8628_s3_1_verification_uri_complete_present`            | ✅     |

> **Notes**:
>
> - `slow_down` (⚠️): The server enforces polling intervals via the `interval` field but does not currently track per-device polling rate; this test validates the field is advertised.
> - `access_denied` (⚠️): Manual user rejection flow is exercised in `tests/device_flow.rs` (happy path); explicit denial is not yet a test case.

---

## Summary

| RFC / Spec | Tests Written | Tests Passing |
| ---------- | :-----------: | :-----------: |
| RFC 6749   |      20       |      ✅       |
| RFC 7636   |      10       |      ✅       |
| RFC 7662   |       8       |      ✅       |
| RFC 7009   |       5       |      ✅       |
| RFC 6750   |       8       |      ✅       |
| RFC 8414   |       9       |      ✅       |
| OIDC Core  |      11       |      ✅       |
| RFC 8628   |       9       |      ⚠️       |
| RFC 9126   |       5       |      ✅       |
| RFC 8707   |       1       |      ✅       |
| RFC 9701   |       3       |      ✅       |
| RFC 7591   |       6       |      ✅       |
| RFC 7592   |       3       |      ✅       |
| RFC 7523   |       4       |      ✅       |
| Wave 4     |      11       |      ✅       |
| **Total**  |   **113**     |               |

_Last updated automatically. Run `cargo test --test compliance_\*` to verify._

---

## RFC 9126 — Pushed Authorization Requests (PAR)

Test file: [`tests/compliance_wave3.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/compliance_wave3.rs)

| Section | Requirement | Test Function | Status |
| ------- | ----------- | ------------- | ------ |
| §2.2 | Public client with valid params receives `request_uri` and `expires_in: 60` | `rfc9126_par_public_client_returns_request_uri` | ✅ |
| §2.1 | PAR request missing `response_type` is rejected | `rfc9126_par_missing_response_type_is_rejected` | ✅ |
| §2.1 | PAR request with duplicate parameters is rejected | `rfc9126_par_duplicate_param_is_rejected` | ✅ |
| §2.1 | Confidential client sending PAR without authentication is rejected | `rfc9126_par_confidential_client_no_secret_rejected` | ✅ |
| §2.1 | Confidential client with valid Basic auth succeeds | `rfc9126_par_confidential_client_with_basic_auth_succeeds` | ✅ |

---

## RFC 8707 — Resource Indicators for OAuth 2.0

Test file: [`tests/compliance_wave3.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/compliance_wave3.rs)

| Section | Requirement | Test Function | Status |
| ------- | ----------- | ------------- | ------ |
| §2 | `resource` parameter in client_credentials request is accepted and echoed in token `aud` | `rfc8707_resource_indicator_accepted_in_client_credentials` | ✅ |

---

## RFC 9701 — JWT Response for OAuth Token Introspection

Test file: [`tests/compliance_wave3.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/compliance_wave3.rs)

| Section | Requirement | Test Function | Status |
| ------- | ----------- | ------------- | ------ |
| §4 | `Accept: application/token-introspection+jwt` triggers JWT response with matching `Content-Type` | `rfc9701_jwt_accept_header_returns_jwt_introspection_response` | ✅ |
| §4 | Without the `Accept` header, introspection returns standard JSON | `rfc9701_standard_accept_returns_json_introspection_response` | ✅ |
| §4 | JWT payload contains `token_introspection` claim with `active`, `scope`, `client_id` | `rfc9701_jwt_payload_contains_token_introspection_claim` | ✅ |

---

## RFC 7591 — OAuth 2.0 Dynamic Client Registration

Test file: [`tests/phase2_rfc_compliance.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/phase2_rfc_compliance.rs)

| Section | Requirement | Test Function | Status |
| ------- | ----------- | ------------- | ------ |
| §3.1 | Dynamic registration returns `client_id` and `registration_access_token` | `rfc7591_dynamic_registration_success` | ✅ |
| §3.2 | Defaults for `grant_types` and `response_types` are applied when omitted | `rfc7591_defaults_grant_and_response_types` | ✅ |
| §2 | Public client registered with `token_endpoint_auth_method: none` | `rfc7591_public_client_no_secret` | ✅ |
| §3.1 | Registration with invalid `redirect_uris` is rejected | `rfc7591_rejects_invalid_redirect_uris` | ✅ |
| §3.2 | `jwks` and `jwks_uri` are mutually exclusive | `rfc7591_jwks_and_jwks_uri_mutually_exclusive` | ✅ |
| §3.2 | `private_key_jwt` registration requires `jwks` or `jwks_uri` | `rfc7591_private_key_jwt_requires_jwks` | ✅ |

---

## RFC 7592 — OAuth 2.0 Dynamic Client Registration Management

Test file: [`tests/phase2_rfc_compliance.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/phase2_rfc_compliance.rs)

| Section | Requirement | Test Function | Status |
| ------- | ----------- | ------------- | ------ |
| §2 | `GET /connect/register/{id}` returns client configuration | `rfc7592_read_client_configuration` | ✅ |
| §2 | `PUT /connect/register/{id}` updates client metadata | `rfc7592_update_client_configuration` | ✅ |
| §2 | `DELETE /connect/register/{id}` removes the client | `rfc7592_delete_client` | ✅ |

---

## RFC 7523 — JSON Web Token (JWT) Profile for Client Authentication

Test file: [`tests/phase2_rfc_compliance.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/phase2_rfc_compliance.rs)

| Section | Requirement | Test Function | Status |
| ------- | ----------- | ------------- | ------ |
| §2.2 | `client_secret_jwt` assertion with correct HMAC secret succeeds | `rfc7523_client_secret_jwt_authentication` | ✅ |
| §2.2 | `client_secret_jwt` assertion with wrong secret fails | `rfc7523_client_secret_jwt_wrong_secret_fails` | ✅ |
| §2.2 | `private_key_jwt` assertion with RSA key pair succeeds | `rfc7523_private_key_jwt_authentication` | ✅ |
| §2 | OIDC registration metadata is preserved after registration | `oidc_metadata_preserved_in_registration` | ✅ |

---

## Wave 4 — DPoP, mTLS, Token Exchange, RAR, Step-Up, Protected Resource Metadata

Test file: [`tests/compliance_wave4.rs`](https://github.com/ianlintner/rust-oauth2-server/blob/main/tests/compliance_wave4.rs)

| Feature | RFC | Requirement | Test Function | Status |
| ------- | --- | ----------- | ------------- | ------ |
| DPoP | RFC 9449 | Discovery advertises `dpop_signing_alg_values_supported` including `ES256` | `wave4_rfc9449_dpop_signing_alg_values_supported_advertised` | ✅ |
| mTLS | RFC 8705 | Discovery advertises `tls_client_certificate_bound_access_tokens: true` | `wave4_rfc8705_mtls_advertised_in_discovery` | ✅ |
| Token Exchange | RFC 8693 | Discovery includes `urn:ietf:params:oauth:grant-type:token-exchange` in `grant_types_supported` | `wave4_rfc8693_token_exchange_grant_type_in_discovery` | ✅ |
| RAR | RFC 9396 | Discovery advertises `authorization_details_types_supported` | `wave4_rfc9396_rar_advertised_in_discovery` | ✅ |
| Step-Up Auth | RFC 9470 | Discovery advertises `acr_values_supported` | `wave4_rfc9470_acr_values_supported_advertised` | ✅ |
| Protected Resource Metadata | RFC 9728 | `/.well-known/oauth-protected-resource` returns 200 | `wave4_rfc9728_protected_resource_metadata_returns_200` | ✅ |
| Protected Resource Metadata | RFC 9728 | Response includes `resource` field | `wave4_rfc9728_protected_resource_metadata_has_resource_field` | ✅ |
| Protected Resource Metadata | RFC 9728 | Response includes `authorization_servers` field | `wave4_rfc9728_protected_resource_metadata_has_authorization_servers` | ✅ |
| Token Status List | Draft | `/.well-known/oauth-authorization-server/status` returns 200 | `wave4_token_status_list_returns_200` | ✅ |
| Token Status List | Draft | Response is valid JSON | `wave4_token_status_list_returns_valid_json` | ✅ |
| OIDC Claims Request | OIDC Core §5.5 | Discovery advertises `acr` and `auth_time` in `claims_supported` | `wave4_oidc_claims_request_acr_auth_time_in_claims_supported` | ✅ |
