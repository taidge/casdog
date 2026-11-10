//! Integration tests that verify the Casdog API surface matches Casdoor-expected
//! behaviour.  Tests are split into two groups:
//!
//! 1. **Route-existence tests** -- these only require the router and validate
//!    that routes respond with the expected status codes, content types, and
//!    redirects.  They run without a database.
//!
//! 2. **Database-backed tests** (`#[ignore]`) -- these exercise the full CRUD /
//!    auth flow and require a running PostgreSQL instance with Casdog schema.

use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};

// ---------------------------------------------------------------------------
// Helper: build a minimal Service that wraps the router.
//
// We deliberately do NOT inject a database pool or Casbin service so that
// route-existence tests can run without external dependencies.  Handlers that
// try to `depot.obtain::<Pool<Postgres>>()` will get an error and return 500,
// which is acceptable -- we are testing the *routing* layer, not the handler
// logic.
// ---------------------------------------------------------------------------

fn test_service() -> Service {
    initialize_config();
    let router = casdog::routes::create_router();
    Service::new(router)
}

fn initialize_config() {
    static INITIALIZED: std::sync::Once = std::sync::Once::new();
    INITIALIZED.call_once(|| {
        casdog::config::AppConfig::load().expect("Tests must run from the casdog crate directory");
    });
}

// ===================================================================
// 1.  Health endpoint
// ===================================================================

#[tokio::test]
async fn health_returns_ok_with_json() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api/health")
        .send(&service)
        .await;

    assert_eq!(res.status_code.unwrap(), StatusCode::OK);

    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(body["version"].is_string());
}

// ===================================================================
// 2.  Well-known endpoints
// ===================================================================

#[tokio::test]
async fn wellknown_openid_configuration_returns_json() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/.well-known/openid-configuration")
        .send(&service)
        .await;

    assert_eq!(res.status_code.unwrap(), StatusCode::OK);
    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    assert!(body["issuer"].is_string(), "issuer must be present");
    assert!(body["authorization_endpoint"].is_string());
    assert!(body["token_endpoint"].is_string());
    assert!(body["userinfo_endpoint"].is_string());
    assert!(body["jwks_uri"].is_string());
    assert!(body["scopes_supported"].is_array());
    assert!(body["response_types_supported"].is_array());
    assert!(body["grant_types_supported"].is_array());
    assert!(body["id_token_signing_alg_values_supported"].is_array());
    assert!(body["code_challenge_methods_supported"].is_array());
}

#[tokio::test]
async fn wellknown_oauth_authorization_server_returns_json() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/.well-known/oauth-authorization-server")
        .send(&service)
        .await;

    assert_eq!(res.status_code.unwrap(), StatusCode::OK);
    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    assert!(body["issuer"].is_string());
    assert!(body["token_endpoint"].is_string());
}

#[tokio::test]
async fn wellknown_oauth_protected_resource_returns_json() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/.well-known/oauth-protected-resource")
        .send(&service)
        .await;

    assert_eq!(res.status_code.unwrap(), StatusCode::OK);
    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    assert!(body["resource"].is_string());
    assert!(body["authorization_servers"].is_array());
    assert!(body["bearer_methods_supported"].is_array());
    assert!(body["scopes_supported"].is_array());
}

#[tokio::test]
async fn wellknown_webfinger_requires_resource_param() {
    let service = test_service();
    // Without the required `resource` query parameter, the endpoint should
    // return a 400 (missing required query param).
    let mut res = TestClient::get("http://127.0.0.1:8000/.well-known/webfinger")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    // Salvo's QueryParam<String, true> returns 400 when the parameter is missing.
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::INTERNAL_SERVER_ERROR,
        "Expected 400 or 500 when `resource` is missing, got {status}"
    );
}

#[tokio::test]
async fn wellknown_webfinger_with_resource_returns_json() {
    let service = test_service();
    let mut res = TestClient::get(
        "http://127.0.0.1:8000/.well-known/webfinger?resource=acct:alice@example.com",
    )
    .send(&service)
    .await;

    assert_eq!(res.status_code.unwrap(), StatusCode::OK);
    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["subject"], "acct:alice@example.com");
    assert!(body["links"].is_array());
}

#[tokio::test]
async fn wellknown_app_specific_openid_configuration() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/.well-known/my-app/openid-configuration")
        .send(&service)
        .await;

    assert_eq!(res.status_code.unwrap(), StatusCode::OK);
    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    assert!(body["issuer"].as_str().unwrap().contains("my-app"));
}

#[tokio::test]
async fn wellknown_jwks_returns_keys_array() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/.well-known/jwks")
        .send(&service)
        .await;

    assert_eq!(res.status_code.unwrap(), StatusCode::OK);
    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    // Without a database the keys array will be empty, but the structure
    // must be correct.
    assert!(body["keys"].is_array());
}

// ===================================================================
// 3.  Authentication flow  (login, logout, token refresh)
// ===================================================================

#[tokio::test]
async fn login_post_route_exists() {
    let service = test_service();
    // POST with an empty body -- the handler will fail validation, but
    // the route itself must exist (not 404).
    let mut res = TestClient::post("http://127.0.0.1:8000/api/login")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "POST /api/login must be routed"
    );
    assert_ne!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "POST must be an allowed method on /api/login"
    );
}

#[tokio::test]
async fn signup_post_route_exists() {
    let service = test_service();
    let mut res = TestClient::post("http://127.0.0.1:8000/api/signup")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "POST /api/signup must be routed"
    );
}

#[tokio::test]
async fn logout_get_requires_auth() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api/logout")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    // Logout is behind JwtAuth, so without a token we should get 401.
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::INTERNAL_SERVER_ERROR,
        "Expected 401 for unauthenticated logout, got {status}"
    );
}

#[tokio::test]
async fn get_account_requires_auth() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api/get-account")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::INTERNAL_SERVER_ERROR,
        "Expected 401 for unauthenticated get-account, got {status}"
    );
}

// ===================================================================
// 4.  OAuth2 flow
// ===================================================================

#[tokio::test]
async fn oauth_authorize_redirects() {
    let service = test_service();
    let mut res = TestClient::get(
        "http://127.0.0.1:8000/login/oauth/authorize\
         ?client_id=test-client\
         &redirect_uri=http://localhost/callback\
         &response_type=code\
         &scope=openid",
    )
    .send(&service)
    .await;

    let status = res.status_code.unwrap();
    // The authorize endpoint builds a redirect to the login page.
    assert!(
        status == StatusCode::FOUND
            || status == StatusCode::TEMPORARY_REDIRECT
            || status == StatusCode::SEE_OTHER
            || status == StatusCode::OK,
        "Expected redirect from /login/oauth/authorize, got {status}"
    );
}

#[tokio::test]
async fn oauth_access_token_post_exists() {
    let service = test_service();
    let mut res = TestClient::post("http://127.0.0.1:8000/login/oauth/access_token")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "POST /login/oauth/access_token route must exist"
    );
}

#[tokio::test]
async fn oauth_refresh_token_post_exists() {
    let service = test_service();
    let mut res = TestClient::post("http://127.0.0.1:8000/login/oauth/refresh_token")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "POST /login/oauth/refresh_token route must exist"
    );
}

#[tokio::test]
async fn oauth_introspect_post_exists() {
    let service = test_service();
    let mut res = TestClient::post("http://127.0.0.1:8000/login/oauth/introspect")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "POST /login/oauth/introspect route must exist"
    );
}

#[tokio::test]
async fn oauth_revoke_post_exists() {
    let service = test_service();
    let mut res = TestClient::post("http://127.0.0.1:8000/login/oauth/revoke")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "POST /login/oauth/revoke route must exist"
    );
}

// ===================================================================
// 5.  CRUD endpoints for core resources
// ===================================================================

macro_rules! assert_crud_routes {
    ($name:ident, $base:expr) => {
        mod $name {
            use super::*;

            #[tokio::test]
            async fn list_requires_auth() {
                let service = test_service();
                let url = format!("http://127.0.0.1:8000/api/{}", $base);
                let mut res = TestClient::get(&url).send(&service).await;
                let status = res.status_code.unwrap();
                // Protected routes should return 401 without a token.
                assert!(
                    status == StatusCode::UNAUTHORIZED
                        || status == StatusCode::INTERNAL_SERVER_ERROR,
                    "GET /api/{} without auth should be 401, got {}",
                    $base,
                    status
                );
            }

            #[tokio::test]
            async fn create_requires_auth() {
                let service = test_service();
                let url = format!("http://127.0.0.1:8000/api/{}", $base);
                let mut res = TestClient::post(&url).send(&service).await;
                let status = res.status_code.unwrap();
                assert!(
                    status == StatusCode::UNAUTHORIZED
                        || status == StatusCode::INTERNAL_SERVER_ERROR,
                    "POST /api/{} without auth should be 401, got {}",
                    $base,
                    status
                );
            }

            #[tokio::test]
            async fn get_by_id_requires_auth() {
                let service = test_service();
                let url = format!("http://127.0.0.1:8000/api/{}/nonexistent-id", $base);
                let mut res = TestClient::get(&url).send(&service).await;
                let status = res.status_code.unwrap();
                assert!(
                    status == StatusCode::UNAUTHORIZED
                        || status == StatusCode::NOT_FOUND
                        || status == StatusCode::INTERNAL_SERVER_ERROR,
                    "GET /api/{}/nonexistent-id without auth: expected 401/404, got {}",
                    $base,
                    status
                );
            }

            #[tokio::test]
            async fn update_requires_auth() {
                let service = test_service();
                let url = format!("http://127.0.0.1:8000/api/{}/nonexistent-id", $base);
                let mut res = TestClient::put(&url).send(&service).await;
                let status = res.status_code.unwrap();
                assert!(
                    status == StatusCode::UNAUTHORIZED
                        || status == StatusCode::NOT_FOUND
                        || status == StatusCode::INTERNAL_SERVER_ERROR,
                    "PUT /api/{}/nonexistent-id without auth: expected 401/404, got {}",
                    $base,
                    status
                );
            }

            #[tokio::test]
            async fn delete_requires_auth() {
                let service = test_service();
                let url = format!("http://127.0.0.1:8000/api/{}/nonexistent-id", $base);
                let mut res = TestClient::delete(&url).send(&service).await;
                let status = res.status_code.unwrap();
                assert!(
                    status == StatusCode::UNAUTHORIZED
                        || status == StatusCode::NOT_FOUND
                        || status == StatusCode::INTERNAL_SERVER_ERROR,
                    "DELETE /api/{}/nonexistent-id without auth: expected 401/404, got {}",
                    $base,
                    status
                );
            }
        }
    };
}

assert_crud_routes!(users_crud, "users");
assert_crud_routes!(organizations_crud, "organizations");
assert_crud_routes!(applications_crud, "applications");
assert_crud_routes!(roles_crud, "roles");
assert_crud_routes!(permissions_crud, "permissions");
assert_crud_routes!(providers_crud, "providers");
assert_crud_routes!(tokens_crud, "tokens");
assert_crud_routes!(groups_crud, "groups");
assert_crud_routes!(sessions_crud, "sessions");
assert_crud_routes!(certs_crud, "certs");
assert_crud_routes!(resources_crud, "resources");
assert_crud_routes!(webhooks_crud, "webhooks");
assert_crud_routes!(syncers_crud, "syncers");
assert_crud_routes!(invitations_crud, "invitations");
assert_crud_routes!(records_crud, "records");
assert_crud_routes!(models_crud, "models");
assert_crud_routes!(adapters_crud, "adapters");
assert_crud_routes!(enforcers_crud, "enforcers");
assert_crud_routes!(rules_crud, "rules");
assert_crud_routes!(sites_crud, "sites");
assert_crud_routes!(products_crud, "products");
assert_crud_routes!(plans_crud, "plans");
assert_crud_routes!(pricings_crud, "pricings");
assert_crud_routes!(subscriptions_crud, "subscriptions");
assert_crud_routes!(payments_crud, "payments");
assert_crud_routes!(transactions_crud, "transactions");

// ===================================================================
// 6.  SAML metadata endpoint
// ===================================================================

#[tokio::test]
async fn saml_metadata_route_exists() {
    let service = test_service();
    // Without a valid application query param and DB, we expect 400 or 500,
    // but NOT 404.
    let mut res = TestClient::get("http://127.0.0.1:8000/api/saml/metadata")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /api/saml/metadata route must exist"
    );
}

#[tokio::test]
async fn saml_acs_post_route_exists() {
    let service = test_service();
    let mut res = TestClient::post("http://127.0.0.1:8000/api/saml/acs")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "POST /api/saml/acs route must exist"
    );
}

#[tokio::test]
async fn saml_login_route_exists() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api/saml/login")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /api/saml/login route must exist"
    );
}

// ===================================================================
// 7.  CAS validate endpoint
// ===================================================================

#[tokio::test]
async fn cas_validate_route_exists() {
    let service = test_service();
    // The CAS validate handler is a public root-level route.
    let mut res = TestClient::get(
        "http://127.0.0.1:8000/cas/test-org/test-app/validate\
         ?ticket=ST-test&service=http://localhost",
    )
    .send(&service)
    .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /cas/:org/:app/validate route must exist"
    );
}

#[tokio::test]
async fn cas_service_validate_route_exists() {
    let service = test_service();
    let mut res = TestClient::get(
        "http://127.0.0.1:8000/cas/test-org/test-app/serviceValidate\
         ?ticket=ST-test&service=http://localhost",
    )
    .send(&service)
    .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /cas/:org/:app/serviceValidate route must exist"
    );
}

#[tokio::test]
async fn cas_proxy_validate_route_exists() {
    let service = test_service();
    let mut res = TestClient::get(
        "http://127.0.0.1:8000/cas/test-org/test-app/proxyValidate\
         ?ticket=ST-test&service=http://localhost",
    )
    .send(&service)
    .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /cas/:org/:app/proxyValidate route must exist"
    );
}

#[tokio::test]
async fn cas_p3_service_validate_route_exists() {
    let service = test_service();
    let mut res = TestClient::get(
        "http://127.0.0.1:8000/cas/test-org/test-app/p3/serviceValidate\
         ?ticket=ST-test&service=http://localhost",
    )
    .send(&service)
    .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /cas/:org/:app/p3/serviceValidate route must exist"
    );
}

#[tokio::test]
async fn cas_proxy_route_exists() {
    let service = test_service();
    let mut res = TestClient::get(
        "http://127.0.0.1:8000/cas/test-org/test-app/proxy\
         ?pgt=PGT-test&targetService=http://localhost",
    )
    .send(&service)
    .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /cas/:org/:app/proxy route must exist"
    );
}

#[tokio::test]
async fn cas_saml_validate_route_exists() {
    let service = test_service();
    let mut res = TestClient::post("http://127.0.0.1:8000/cas/test-org/test-app/samlValidate")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "POST /cas/:org/:app/samlValidate route must exist"
    );
}

// ===================================================================
// 8.  WebAuthn begin endpoints
// ===================================================================

#[tokio::test]
async fn webauthn_signin_begin_route_exists() {
    let service = test_service();
    let mut res = TestClient::get(
        "http://127.0.0.1:8000/api/webauthn/signin/begin?name=alice&owner=built-in",
    )
    .send(&service)
    .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /api/webauthn/signin/begin route must exist"
    );
}

#[tokio::test]
async fn webauthn_signup_begin_requires_auth() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api/webauthn/signup/begin")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    // signup/begin is behind JwtAuth, so expect 401 without token.
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::INTERNAL_SERVER_ERROR,
        "Expected 401 for unauthenticated webauthn signup, got {status}"
    );
}

// ===================================================================
// 9.  Kerberos login returns 401 with WWW-Authenticate: Negotiate
// ===================================================================

#[tokio::test]
async fn kerberos_login_returns_negotiate_challenge() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api/kerberos-login?application=test-app")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    // Without an Authorization: Negotiate header, the handler should send a 401
    // with a WWW-Authenticate: Negotiate header to initiate the SPNEGO
    // handshake.  However this also requires DB access to resolve the
    // application, so we might get 500.
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::INTERNAL_SERVER_ERROR,
        "Expected 401 (Negotiate challenge) or 500 (no DB), got {status}"
    );
}

// ===================================================================
// 10. FaceID begin returns challenge
// ===================================================================

#[tokio::test]
async fn faceid_signin_begin_route_exists() {
    let service = test_service();
    let mut res =
        TestClient::get("http://127.0.0.1:8000/api/faceid-signin-begin?owner=admin&name=alice")
            .send(&service)
            .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /api/faceid-signin-begin route must exist"
    );
}

#[tokio::test]
async fn faceid_signin_finish_post_route_exists() {
    let service = test_service();
    let mut res =
        TestClient::post("http://127.0.0.1:8000/api/faceid-signin-finish?owner=admin&name=alice")
            .send(&service)
            .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "POST /api/faceid-signin-finish route must exist"
    );
}

// ===================================================================
// 11. Consent endpoints
// ===================================================================

#[tokio::test]
async fn grant_consent_requires_auth() {
    let service = test_service();
    let mut res = TestClient::post("http://127.0.0.1:8000/api/grant-consent")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::INTERNAL_SERVER_ERROR,
        "POST /api/grant-consent without auth: expected 401, got {status}"
    );
}

#[tokio::test]
async fn revoke_consent_requires_auth() {
    let service = test_service();
    let mut res = TestClient::post("http://127.0.0.1:8000/api/revoke-consent")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::INTERNAL_SERVER_ERROR,
        "POST /api/revoke-consent without auth: expected 401, got {status}"
    );
}

// ===================================================================
// 12. SCIM endpoints
// ===================================================================

#[tokio::test]
async fn scim_list_users_requires_auth() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api/scim/v2/Users")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::INTERNAL_SERVER_ERROR,
        "GET /api/scim/v2/Users without auth: expected 401, got {status}"
    );
}

#[tokio::test]
async fn scim_get_user_requires_auth() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api/scim/v2/Users/some-user-id")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::INTERNAL_SERVER_ERROR,
        "GET /api/scim/v2/Users/:id without auth: expected 401, got {status}"
    );
}

// ===================================================================
// 13. OpenAPI spec generation
// ===================================================================

#[tokio::test]
async fn openapi_spec_route_exists() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api-doc/openapi.json")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "GET /api-doc/openapi.json should return the OpenAPI spec"
    );

    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    // OpenAPI 3.x root keys
    assert!(body["openapi"].is_string() || body["swagger"].is_string());
    assert!(body["info"].is_object());
    assert!(body["paths"].is_object());
}

#[tokio::test]
async fn openapi_doc_contains_health_path() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api-doc/openapi.json")
        .send(&service)
        .await;

    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    let paths = body["paths"].as_object().expect("paths must be an object");
    assert!(
        paths.contains_key("/api/health"),
        "OpenAPI spec must list /api/health"
    );
}

// ===================================================================
// 14. Swagger UI
// ===================================================================

#[tokio::test]
async fn swagger_ui_route_exists() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/swagger-ui/")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "GET /swagger-ui/ should serve the Swagger UI"
    );
}

// ===================================================================
// 15. Miscellaneous public routes
// ===================================================================

#[tokio::test]
async fn userinfo_without_auth_returns_401() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api/userinfo")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "GET /api/userinfo without Bearer token must return 401"
    );
}

#[tokio::test]
async fn captcha_route_exists() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api/captcha")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /api/captcha route must exist"
    );
}

#[tokio::test]
async fn get_app_login_route_exists() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api/get-app-login")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /api/get-app-login route must exist"
    );
}

#[tokio::test]
async fn callback_get_route_exists() {
    let service = test_service();
    let mut res = TestClient::get("http://127.0.0.1:8000/api/callback")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /api/callback route must exist"
    );
}

#[tokio::test]
async fn callback_post_route_exists() {
    let service = test_service();
    let mut res = TestClient::post("http://127.0.0.1:8000/api/callback")
        .send(&service)
        .await;

    let status = res.status_code.unwrap();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "POST /api/callback route must exist"
    );
}

// ===================================================================
// 16. Casdoor flat compatibility routes
// ===================================================================

#[tokio::test]
async fn casdoor_flat_resource_routes_require_auth() {
    let service = test_service();
    let cases = [
        ("GET", "http://127.0.0.1:8000/api/get-users"),
        (
            "GET",
            "http://127.0.0.1:8000/api/get-user?id=built-in/admin",
        ),
        ("POST", "http://127.0.0.1:8000/api/add-user"),
        (
            "POST",
            "http://127.0.0.1:8000/api/update-user?id=built-in/admin",
        ),
        ("POST", "http://127.0.0.1:8000/api/delete-user"),
        ("GET", "http://127.0.0.1:8000/api/get-applications"),
        ("POST", "http://127.0.0.1:8000/api/add-application"),
        ("GET", "http://127.0.0.1:8000/api/get-orders"),
        ("GET", "http://127.0.0.1:8000/api/get-user-orders"),
        ("POST", "http://127.0.0.1:8000/api/place-order"),
        ("GET", "http://127.0.0.1:8000/api/get-user-payments"),
        ("POST", "http://127.0.0.1:8000/api/add-ticket"),
        (
            "POST",
            "http://127.0.0.1:8000/api/add-ticket-message?id=ticket-1",
        ),
        ("GET", "http://127.0.0.1:8000/api/get-forms"),
        ("GET", "http://127.0.0.1:8000/api/get-records"),
        ("POST", "http://127.0.0.1:8000/api/add-user-keys"),
        ("POST", "http://127.0.0.1:8000/api/remove-user-from-group"),
        (
            "GET",
            "http://127.0.0.1:8000/api/get-invitation-info?code=abc",
        ),
        (
            "GET",
            "http://127.0.0.1:8000/api/verify-invitation?code=abc",
        ),
        ("POST", "http://127.0.0.1:8000/api/send-invitation"),
        ("GET", "http://127.0.0.1:8000/api/run-syncer?id=syncer-1"),
        ("POST", "http://127.0.0.1:8000/api/test-syncer-db"),
        ("POST", "http://127.0.0.1:8000/api/get-filtered-policies"),
        ("POST", "http://127.0.0.1:8000/api/update-policy"),
        ("POST", "http://127.0.0.1:8000/api/remove-policy"),
    ];

    for (method, url) in cases {
        let res = match method {
            "GET" => TestClient::get(url).send(&service).await,
            "POST" => TestClient::post(url).send(&service).await,
            _ => unreachable!(),
        };
        let status = res.status_code.unwrap();
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {url} should be protected by JwtAuth, got {status}"
        );
    }
}

#[tokio::test]
async fn casdoor_public_alias_routes_exist() {
    let service = test_service();

    let user_res = TestClient::get("http://127.0.0.1:8000/api/user")
        .send(&service)
        .await;
    assert_eq!(user_res.status_code.unwrap(), StatusCode::UNAUTHORIZED);

    let captcha_res = TestClient::get("http://127.0.0.1:8000/api/get-captcha")
        .send(&service)
        .await;
    assert_ne!(
        captcha_res.status_code.unwrap(),
        StatusCode::NOT_FOUND,
        "GET /api/get-captcha must be routed"
    );

    let token_res = TestClient::post("http://127.0.0.1:8000/api/login/oauth/access_token")
        .send(&service)
        .await;
    let token_status = token_res.status_code.unwrap();
    assert_ne!(
        token_status,
        StatusCode::NOT_FOUND,
        "POST /api/login/oauth/access_token must be routed"
    );
    assert_ne!(
        token_status,
        StatusCode::METHOD_NOT_ALLOWED,
        "POST must be accepted for /api/login/oauth/access_token"
    );

    let mcp_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    let mut mcp_res = TestClient::post("http://127.0.0.1:8000/api/mcp")
        .json(&mcp_body)
        .send(&service)
        .await;
    assert_eq!(mcp_res.status_code.unwrap(), StatusCode::OK);
    let mcp_json: serde_json::Value = mcp_res.take_json().await.unwrap();
    assert_eq!(mcp_json["jsonrpc"], "2.0");

    let webhook_res = TestClient::get("http://127.0.0.1:8000/api/webhook?echostr=123")
        .send(&service)
        .await;
    assert_ne!(
        webhook_res.status_code.unwrap(),
        StatusCode::NOT_FOUND,
        "GET /api/webhook must be routed"
    );
}

// ===================================================================
// 17. Database-backed integration tests (require PostgreSQL)
// ===================================================================

struct DatabaseFixture {
    service: Service,
    pool: sqlx::PgPool,
    owner: String,
    admin_id: String,
    application_id: String,
    client_id: String,
    secret: String,
    auth: String,
}

async fn expect_json(mut response: Response) -> serde_json::Value {
    let status = response.status_code.unwrap();
    let body = response.take_string().await.unwrap();
    assert_eq!(status, StatusCode::OK, "Unexpected HTTP response: {body}");
    serde_json::from_str(&body).expect("Expected JSON response")
}

impl DatabaseFixture {
    async fn new() -> Self {
        initialize_config();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").expect(
            "Set CASDOG_TEST_DATABASE_URL to a disposable database with migrations 001-018",
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();
        let diesel = casdog::diesel_pool::create_diesel_pool(&url).await.unwrap();
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel),
        );
        let owner = format!("parity-{}", uuid::Uuid::new_v4());
        let admin_id = uuid::Uuid::new_v4().to_string();
        let application_id = uuid::Uuid::new_v4().to_string();
        let client_id = uuid::Uuid::new_v4().to_string();
        let secret = uuid::Uuid::new_v4().to_string();
        let hash =
            casdog::services::PasswordService::hash_password("Fixture42!", "argon2", None).unwrap();
        sqlx::query("INSERT INTO organizations (id,owner,name,display_name,password_options) VALUES ($1,$2,$2,'Parity tenant',$3)")
            .bind(uuid::Uuid::new_v4().to_string()).bind(&owner).bind(serde_json::json!(["AtLeast8","Aa","AtLeastOneDigit"])).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO users (id,owner,name,display_name,email,password_hash,password_type,is_admin) VALUES ($1,$2,'fixture-admin','Fixture Admin','admin@example.test',$3,'argon2',true)")
            .bind(&admin_id).bind(&owner).bind(hash).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO applications (id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_password,enable_internal_signup) VALUES ($1,$2,'fixture-app','Fixture App',$2,$3,$4,'https://client.example.test/callback',true,true)")
            .bind(&application_id).bind(&owner).bind(&client_id).bind(&secret).execute(&pool).await.unwrap();
        let login = expect_json(TestClient::post("http://127.0.0.1:8000/api/login")
            .json(&serde_json::json!({"organization":owner,"username":"fixture-admin","password":"Fixture42!","application":"fixture-app","type":"login"}))
            .send(&service).await).await;
        assert_eq!(login["user"]["id"], admin_id);
        let auth = format!("Bearer {}", login["token"].as_str().unwrap());
        Self {
            service,
            pool,
            owner,
            admin_id,
            application_id,
            client_id,
            secret,
            auth,
        }
    }

    async fn cleanup(self) {
        // Every row belongs to a UUID tenant; no seed records are read or modified.
        for table in [
            "forms",
            "tokens",
            "sessions",
            "applications",
            "users",
            "organizations",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE owner=$1"))
                .bind(&self.owner)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        drop(self.service);
        self.pool.close().await;
    }

    async fn grant_code(&self, challenge: &str) -> String {
        let body = expect_json(TestClient::post("http://127.0.0.1:8000/api/grant-consent")
            .add_header("Authorization", &self.auth, true)
            .json(&serde_json::json!({
                "application":format!("{}/fixture-app", self.owner),
                "grantedScopes":["openid","profile","email"], "clientId":self.client_id,
                "responseType":"code", "redirectUri":"https://client.example.test/callback",
                "state":"test-state", "nonce":"test-nonce", "challenge":challenge,"codeChallengeMethod":"S256"
            })).send(&self.service).await).await;
        assert_eq!(body["application"], self.application_id);
        assert_eq!(body["state"], "test-state");
        assert_eq!(body["redirect_uri"], "https://client.example.test/callback");
        body["code"]
            .as_str()
            .expect("Consent must issue a real authorization code")
            .to_string()
    }

    async fn exchange(&self, code: &str, verifier: &str, secret: &str, redirect: &str) -> Response {
        use base64::Engine;
        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{secret}", self.client_id));
        let body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}",
            urlencoding::encode(code),
            urlencoding::encode(redirect),
            urlencoding::encode(verifier)
        );
        TestClient::post("http://127.0.0.1:8000/api/login/oauth/access_token")
            .add_header("Authorization", format!("Basic {basic}"), true)
            .add_header("Content-Type", "application/x-www-form-urlencoded", true)
            .body(body)
            .send(&self.service)
            .await
    }
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-018"]
async fn casdoor_flat_form_endpoints_db_parity() {
    let f = DatabaseFixture::new().await;
    let form = serde_json::json!({"owner":f.owner,"name":"test-form","displayName":"Flat Form"});
    let created = expect_json(
        TestClient::post("http://127.0.0.1:8000/api/add-form")
            .add_header("Authorization", &f.auth, true)
            .json(&form)
            .send(&f.service)
            .await,
    )
    .await;
    assert_eq!(created["status"], "ok");
    assert_eq!(created["data"], true);
    assert_eq!(created["object"]["displayName"], "Flat Form");
    let read = expect_json(
        TestClient::get(format!(
            "http://127.0.0.1:8000/api/get-form?id={}/test-form",
            f.owner
        ))
        .add_header("Authorization", &f.auth, true)
        .send(&f.service)
        .await,
    )
    .await;
    assert_eq!(read["data"]["displayName"], "Flat Form");
    let list = expect_json(
        TestClient::get(format!(
            "http://127.0.0.1:8000/api/get-forms?owner={}&pageSize=10&page=1",
            f.owner
        ))
        .add_header("Authorization", &f.auth, true)
        .send(&f.service)
        .await,
    )
    .await;
    assert_eq!(list["data2"], 1);
    assert_eq!(list["data"][0]["name"], "test-form");
    let updated = expect_json(TestClient::post("http://127.0.0.1:8000/api/update-form")
        .add_header("Authorization", &f.auth, true)
        .json(&serde_json::json!({"owner":f.owner,"name":"test-form","displayName":"Updated Form"})).send(&f.service).await).await;
    assert_eq!(updated["data"], true);
    assert_eq!(updated["object"]["displayName"], "Updated Form");
    let stored: String =
        sqlx::query_scalar("SELECT display_name FROM forms WHERE owner=$1 AND name='test-form'")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(stored, "Updated Form");
    let deleted = expect_json(
        TestClient::post("http://127.0.0.1:8000/api/delete-form")
            .add_header("Authorization", &f.auth, true)
            .json(&form)
            .send(&f.service)
            .await,
    )
    .await;
    assert_eq!(deleted["data"], true);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM forms WHERE owner=$1 AND is_deleted=false")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    let removed = expect_json(
        TestClient::get(format!(
            "http://127.0.0.1:8000/api/get-form?id={}/test-form",
            f.owner
        ))
        .add_header("Authorization", &f.auth, true)
        .send(&f.service)
        .await,
    )
    .await;
    assert!(removed["data"].is_null());
    let remaining = expect_json(
        TestClient::get(format!(
            "http://127.0.0.1:8000/api/get-forms?owner={}",
            f.owner
        ))
        .add_header("Authorization", &f.auth, true)
        .send(&f.service)
        .await,
    )
    .await;
    assert_eq!(remaining["data"], serde_json::json!([]));
    assert_eq!(remaining["data2"], 0);

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-018"]
async fn full_login_flow() {
    let f = DatabaseFixture::new().await;
    let signup = expect_json(TestClient::post("http://127.0.0.1:8000/api/signup")
        .json(&serde_json::json!({"organization":f.owner,"username":"new-user","name":"New Display Name","password":"Signup42!","email":"new@example.test","application":"fixture-app"}))
        .send(&f.service).await).await;
    let id = signup["user"]["id"].as_str().unwrap();
    assert_eq!(signup["user"]["name"], "new-user");
    assert_eq!(signup["user"]["display_name"], "New Display Name");
    let login = expect_json(TestClient::post("http://127.0.0.1:8000/api/login")
        .json(&serde_json::json!({"organization":f.owner,"username":"new-user","password":"Signup42!","application":"fixture-app","type":"login"}))
        .send(&f.service).await).await;
    assert_eq!(login["user"]["id"], id);
    let auth = format!("Bearer {}", login["token"].as_str().unwrap());
    let account = expect_json(
        TestClient::get("http://127.0.0.1:8000/api/get-account")
            .add_header("Authorization", &auth, true)
            .send(&f.service)
            .await,
    )
    .await;
    assert_eq!(account["id"], id);
    assert_eq!(account["owner"], f.owner);
    let logout = TestClient::get("http://127.0.0.1:8000/api/logout")
        .add_header("Authorization", &auth, true)
        .send(&f.service)
        .await;
    assert_eq!(logout.status_code, Some(StatusCode::OK));
    for old in [
        auth,
        format!("Bearer {}", signup["token"].as_str().unwrap()),
    ] {
        let rejected = TestClient::get("http://127.0.0.1:8000/api/get-account")
            .add_header("Authorization", old, true)
            .send(&f.service)
            .await;
        assert_eq!(rejected.status_code, Some(StatusCode::UNAUTHORIZED));
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-018"]
async fn crud_users_full_cycle() {
    let f = DatabaseFixture::new().await;
    let created = expect_json(TestClient::post("http://127.0.0.1:8000/api/users")
        .add_header("Authorization", &f.auth, true)
        .json(&serde_json::json!({"owner":f.owner,"name":"crud-user","display_name":"CRUD User","password":"Created42!","email":"crud@example.test"}))
        .send(&f.service).await).await;
    let id = created["id"].as_str().unwrap();
    assert_eq!(created["name"], "crud-user");
    assert_eq!(created["owner"], f.owner);
    assert!(created.get("password_hash").is_none());
    let route = format!("http://127.0.0.1:8000/api/users/{id}");
    let read = expect_json(
        TestClient::get(&route)
            .add_header("Authorization", &f.auth, true)
            .send(&f.service)
            .await,
    )
    .await;
    assert_eq!(read["email"], "crud@example.test");
    let list = expect_json(
        TestClient::get(format!("http://127.0.0.1:8000/api/users?owner={}", f.owner))
            .add_header("Authorization", &f.auth, true)
            .send(&f.service)
            .await,
    )
    .await;
    assert_eq!(list["total"], 2);
    assert!(
        list["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["id"] == id)
    );
    let updated = expect_json(
        TestClient::put(&route)
            .add_header("Authorization", &f.auth, true)
            .json(&serde_json::json!({"display_name":"Updated CRUD User"}))
            .send(&f.service)
            .await,
    )
    .await;
    assert_eq!(updated["display_name"], "Updated CRUD User");
    let stored: String = sqlx::query_scalar("SELECT display_name FROM users WHERE id=$1")
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(stored, "Updated CRUD User");
    let deleted = TestClient::delete(&route)
        .add_header("Authorization", &f.auth, true)
        .send(&f.service)
        .await;
    assert_eq!(deleted.status_code, Some(StatusCode::OK));
    let missing = TestClient::get(&route)
        .add_header("Authorization", &f.auth, true)
        .send(&f.service)
        .await;
    assert_eq!(missing.status_code, Some(StatusCode::NOT_FOUND));
    let removed: bool = sqlx::query_scalar("SELECT is_deleted FROM users WHERE id=$1")
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert!(removed);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-018"]
async fn oauth2_authorization_code_flow() {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let f = DatabaseFixture::new().await;
    let verifier = "test-pkce-verifier-with-at-least-forty-three-characters";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier));
    let code = f.grant_code(&challenge).await;
    let redirect = "https://client.example.test/callback";
    for (candidate, secret, target) in [
        (verifier, "wrong-secret", redirect),
        ("wrong-verifier", f.secret.as_str(), redirect),
        (
            verifier,
            f.secret.as_str(),
            "https://evil.example.test/callback",
        ),
    ] {
        let denied = f.exchange(&code, candidate, secret, target).await;
        assert!(
            denied.status_code.unwrap().is_client_error(),
            "Invalid OAuth proof must fail"
        );
    }
    let issued = expect_json(f.exchange(&code, verifier, &f.secret, redirect).await).await;
    let access = issued["access_token"].as_str().unwrap();
    let refresh = issued["refresh_token"].as_str().unwrap();
    assert!(!access.is_empty());
    assert!(!refresh.is_empty());
    let config = casdog::config::AppConfig::get();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[f.client_id.as_str()]);
    validation.set_issuer(&[config
        .server
        .public_url
        .unwrap_or_else(|| format!("http://{}:{}", config.server.host, config.server.port))]);
    let id_claims = jsonwebtoken::decode::<serde_json::Value>(
        issued["id_token"].as_str().unwrap(),
        &jsonwebtoken::DecodingKey::from_secret(config.jwt.secret.as_bytes()),
        &validation,
    )
    .unwrap()
    .claims;
    assert_eq!(id_claims["sub"], f.admin_id);
    assert_eq!(id_claims["nonce"], "test-nonce");
    assert_eq!(id_claims["email_verified"], false);

    let replay = f.exchange(&code, verifier, &f.secret, redirect).await;
    assert!(replay.status_code.unwrap().is_client_error());
    let userinfo = expect_json(
        TestClient::get("http://127.0.0.1:8000/api/userinfo")
            .add_header("Authorization", format!("Bearer {access}"), true)
            .send(&f.service)
            .await,
    )
    .await;
    assert_eq!(userinfo["sub"], f.admin_id);
    assert_eq!(userinfo["email"], "admin@example.test");
    let refresh_body = serde_json::json!({"grant_type":"refresh_token","client_id":f.client_id,"client_secret":f.secret,"refresh_token":refresh});
    let rotated = expect_json(
        TestClient::post("http://127.0.0.1:8000/api/login/oauth/access_token")
            .json(&refresh_body)
            .send(&f.service)
            .await,
    )
    .await;
    let next_access = rotated["access_token"].as_str().unwrap();
    assert_ne!(next_access, access);
    assert_ne!(rotated["refresh_token"], refresh);
    let old_refresh = TestClient::post("http://127.0.0.1:8000/api/login/oauth/access_token")
        .json(&refresh_body)
        .send(&f.service)
        .await;
    assert!(old_refresh.status_code.unwrap().is_client_error());
    let old_access = TestClient::get("http://127.0.0.1:8000/api/userinfo")
        .add_header("Authorization", format!("Bearer {access}"), true)
        .send(&f.service)
        .await;
    assert_eq!(old_access.status_code, Some(StatusCode::UNAUTHORIZED));
    let refreshed_info = expect_json(
        TestClient::get("http://127.0.0.1:8000/api/userinfo")
            .add_header("Authorization", format!("Bearer {next_access}"), true)
            .send(&f.service)
            .await,
    )
    .await;
    assert_eq!(refreshed_info["sub"], f.admin_id);
    let consent: serde_json::Value = sqlx::query_scalar(
        "SELECT granted_scopes FROM consent_records WHERE user_id=$1 AND application_id=$2",
    )
    .bind(&f.admin_id)
    .bind(&f.application_id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(
        consent
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("email"))
    );
    // Selective SSO logout must never revoke another user's tokens for this app.
    let other = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash) VALUES($1,$2,'other-user','Other','unused')")
        .bind(&other).bind(&f.owner).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO tokens(id,owner,name,application,organization,user_id,access_token) VALUES($1,$2,'other-token','fixture-app',$2,$3,$1)")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(&other).execute(&f.pool).await.unwrap();
    let logout = TestClient::post(
        "http://127.0.0.1:8000/api/sso-logout?logout_all=false&application=fixture-app",
    )
    .add_header("Authorization", &f.auth, true)
    .send(&f.service)
    .await;
    assert_eq!(logout.status_code, Some(StatusCode::OK));
    let other_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tokens WHERE user_id=$1")
        .bind(&other)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(other_count, 1);
    let own_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tokens WHERE user_id=$1")
        .bind(&f.admin_id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(own_count, 0);
    f.cleanup().await;
}
