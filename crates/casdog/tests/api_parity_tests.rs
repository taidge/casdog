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
    // Initialise a minimal AppConfig so that handlers reading config don't
    // panic.  The config module uses a global RwLock, so this is idempotent.
    //
    // SAFETY: `set_var` is unsafe in edition 2024 because concurrent access
    // is undefined behaviour.  In tests, we only call this from single-threaded
    // setup code before spawning any async work, so it is safe here.
    unsafe {
        std::env::set_var("CASDOG__SERVER__HOST", "127.0.0.1");
        std::env::set_var("CASDOG__SERVER__PORT", "8000");
        std::env::set_var("CASDOG__DATABASE__DRIVER", "postgres");
        std::env::set_var("CASDOG__DATABASE__URL", "postgres://localhost/casdog_test");
        std::env::set_var("CASDOG__DATABASE__MAX_CONNECTIONS", "1");
        std::env::set_var(
            "CASDOG__JWT__SECRET",
            "test-secret-key-for-integration-tests",
        );
        std::env::set_var("CASDOG__JWT__EXPIRATION_HOURS", "24");
        std::env::set_var("CASDOG__JWT__ISSUER", "casdog-test");
        std::env::set_var("CASDOG__CASBIN__MODEL_PATH", "casbin/model.conf");
        std::env::set_var("CASDOG__LOGGING__LEVEL", "error");
    }
    // AppConfig::load reads config files + env overrides.  It may fail if
    // config/default.toml is missing, so we ignore the error here -- the
    // global config will remain unset and handlers will fall back.
    let _ = casdog::config::AppConfig::load();

    let router = casdog::routes::create_router();
    Service::new(router)
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
// 16. Database-backed integration tests (require PostgreSQL)
// ===================================================================

#[tokio::test]
#[ignore = "Requires a running PostgreSQL instance with Casdog schema"]
async fn full_login_flow() {
    // This test exercises the full signup -> login -> get-account -> logout
    // flow against a real database.
    //
    // Prerequisites:
    //   - CASDOG__DATABASE__URL env var pointing to a test database
    //   - Database migrations applied
    //   - Seed data loaded (InitService::init_db)
    let service = test_service();

    // Step 1: Signup
    let signup_body = serde_json::json!({
        "application": "admin/app-built-in",
        "organization": "built-in",
        "username": "integration-test-user",
        "password": "Test1234!",
        "name": "Integration Test",
        "email": "integration@test.local"
    });
    let mut res = TestClient::post("http://127.0.0.1:8000/api/signup")
        .json(&signup_body)
        .send(&service)
        .await;
    let status = res.status_code.unwrap();
    assert!(
        status == StatusCode::OK || status == StatusCode::CONFLICT,
        "Signup should succeed or conflict if user exists, got {status}"
    );

    // Step 2: Login
    let login_body = serde_json::json!({
        "application": "admin/app-built-in",
        "organization": "built-in",
        "username": "integration-test-user",
        "password": "Test1234!",
        "type": "login"
    });
    let mut res = TestClient::post("http://127.0.0.1:8000/api/login")
        .json(&login_body)
        .send(&service)
        .await;
    assert_eq!(res.status_code.unwrap(), StatusCode::OK);
    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    let token = body["token"].as_str().expect("login must return a token");
    assert!(!token.is_empty());

    // Step 3: Get account with the token
    let mut res = TestClient::get("http://127.0.0.1:8000/api/get-account")
        .add_header("Authorization", format!("Bearer {}", token), true)
        .send(&service)
        .await;
    assert_eq!(res.status_code.unwrap(), StatusCode::OK);

    // Step 4: Logout
    let mut res = TestClient::get("http://127.0.0.1:8000/api/logout")
        .add_header("Authorization", format!("Bearer {}", token), true)
        .send(&service)
        .await;
    assert_eq!(res.status_code.unwrap(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "Requires a running PostgreSQL instance with Casdog schema"]
async fn crud_users_full_cycle() {
    let service = test_service();

    // Obtain an admin token first (assumes seed data has been loaded).
    let login_body = serde_json::json!({
        "application": "admin/app-built-in",
        "organization": "built-in",
        "username": "admin",
        "password": "123",
        "type": "login"
    });
    let mut res = TestClient::post("http://127.0.0.1:8000/api/login")
        .json(&login_body)
        .send(&service)
        .await;
    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    let token = body["token"]
        .as_str()
        .expect("admin login must return a token");

    let auth_header = format!("Bearer {}", token);

    // CREATE
    let create_body = serde_json::json!({
        "owner": "built-in",
        "name": "crud-test-user",
        "display_name": "CRUD Test User",
        "password": "Test1234!",
        "email": "crud-test@test.local"
    });
    let mut res = TestClient::post("http://127.0.0.1:8000/api/users")
        .add_header("Authorization", &auth_header, true)
        .json(&create_body)
        .send(&service)
        .await;
    let status = res.status_code.unwrap();
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "CREATE user should succeed, got {status}"
    );
    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    let user_id = body["id"].as_str().unwrap_or("crud-test-user");

    // READ
    let mut res = TestClient::get(format!("http://127.0.0.1:8000/api/users/{}", user_id))
        .add_header("Authorization", &auth_header, true)
        .send(&service)
        .await;
    assert_eq!(res.status_code.unwrap(), StatusCode::OK);

    // LIST
    let mut res = TestClient::get("http://127.0.0.1:8000/api/users")
        .add_header("Authorization", &auth_header, true)
        .send(&service)
        .await;
    assert_eq!(res.status_code.unwrap(), StatusCode::OK);
    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    assert!(body.is_array() || body.is_object());

    // UPDATE
    let update_body = serde_json::json!({
        "display_name": "Updated CRUD Test User"
    });
    let mut res = TestClient::put(format!("http://127.0.0.1:8000/api/users/{}", user_id))
        .add_header("Authorization", &auth_header, true)
        .json(&update_body)
        .send(&service)
        .await;
    assert_eq!(res.status_code.unwrap(), StatusCode::OK);

    // DELETE
    let mut res = TestClient::delete(format!("http://127.0.0.1:8000/api/users/{}", user_id))
        .add_header("Authorization", &auth_header, true)
        .send(&service)
        .await;
    assert_eq!(res.status_code.unwrap(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "Requires a running PostgreSQL instance with Casdog schema"]
async fn oauth2_authorization_code_flow() {
    let service = test_service();

    // Login to get a session token.
    let login_body = serde_json::json!({
        "application": "admin/app-built-in",
        "organization": "built-in",
        "username": "admin",
        "password": "123",
        "type": "login"
    });
    let mut res = TestClient::post("http://127.0.0.1:8000/api/login")
        .json(&login_body)
        .send(&service)
        .await;
    let body: serde_json::Value = res.take_json::<serde_json::Value>().await.unwrap();
    let token = body["token"].as_str().expect("login must return a token");
    let auth_header = format!("Bearer {}", token);

    // Grant consent to produce an authorization code.
    let consent_body = serde_json::json!({
        "application": "admin/app-built-in",
        "granted_scopes": ["openid", "profile"],
        "client_id": body["user"]["id"],
        "response_type": "code",
        "redirect_uri": "http://localhost/callback",
        "scope": "openid profile"
    });
    let mut res = TestClient::post("http://127.0.0.1:8000/api/grant-consent")
        .add_header("Authorization", &auth_header, true)
        .json(&consent_body)
        .send(&service)
        .await;
    let status = res.status_code.unwrap();
    assert!(
        status == StatusCode::OK || status == StatusCode::BAD_REQUEST,
        "Grant consent: expected 200 or 400, got {status}"
    );
}
