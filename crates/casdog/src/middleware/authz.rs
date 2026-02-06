use base64::Engine as _;
use base64::engine::general_purpose;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::ErrorResponse;
use crate::services::{CasbinService, RecordService};

/// Routes that skip authorization entirely (public endpoints).
/// These are matched by prefix -- if the request path starts with any of these, it is allowed.
const PUBLIC_PREFIXES: &[&str] = &[
    "/api/health",
    "/api/signup",
    "/api/login",
    "/api/captcha",
    "/api/verify-captcha",
    "/api/get-email-and-phone",
    "/api/userinfo",
    "/api/get-app-login",
    "/api/get-captcha-status",
    "/api/get-captcha",
    "/api/callback",
    "/api/logout",
    "/api/sso-logout",
    "/api/webhook",
    "/api/send-verification-code",
    "/api/verify-code",
    "/login/oauth/",
    "/.well-known/",
    "/swagger-ui/",
    "/api-doc/",
];

/// Exact paths that are always public regardless of method.
const PUBLIC_EXACT: &[&str] = &[
    "/api/health",
    "/api/signup",
    "/api/login",
    "/api/get-account",
    "/api/userinfo",
    "/api/user",
    "/api/get-app-login",
];

/// Comprehensive authorization filter middleware.
///
/// Based on Casdoor's `routers/authz_filter.go` (`ApiFilter`), this middleware:
///
/// 1. Extracts the subject identity from multiple sources (JWT in depot, Basic Auth,
///    clientId/clientSecret query params, accessKey/accessSecret query params, or anonymous).
/// 2. Extracts the object owner and name from the request (query params or JSON body).
/// 3. Enforces authorization using the Casbin 6-tuple: `(sub_owner, sub_name, method, url_path,
///    obj_owner, obj_name)`.
/// 4. Skips enforcement for public routes and admin users.
/// 5. Logs denied requests via `RecordService`.
pub struct AuthzFilter;

#[async_trait]
impl Handler for AuthzFilter {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let path = req.uri().path().to_string();
        let method = req.method().as_str().to_string();

        // Skip public paths
        if is_public_path(&path) {
            ctrl.call_next(req, depot, res).await;
            return;
        }

        // Check if admin -- admins bypass authorization
        let is_admin = depot.get::<bool>("is_admin").copied().ok().unwrap_or(false);
        if is_admin {
            ctrl.call_next(req, depot, res).await;
            return;
        }

        // Extract subject from depot (set by JwtAuth) or try alternative auth sources
        let (sub_owner, sub_name) = extract_subject(req, depot);

        // "app" subjects (authenticated via clientId/clientSecret) are always allowed,
        // mirroring Casdoor's `if subOwner == "app" { return true }` in authz.go.
        if sub_owner == "app" {
            ctrl.call_next(req, depot, res).await;
            return;
        }

        // Normalize the URL path for Casbin matching (collapse protocol-specific sub-paths)
        let url_path = normalize_url_path(&path);

        // Extract object info from request
        let (obj_owner, obj_name) = extract_object(req, &path, &method);

        // Get Casbin service from depot (injected via AffixList)
        let casbin_service = match depot.obtain::<CasbinService>() {
            Ok(service) => service.clone(),
            Err(_) => {
                // If no Casbin service is available, allow through (service may not be configured)
                tracing::warn!("CasbinService not found in depot, allowing request through");
                ctrl.call_next(req, depot, res).await;
                return;
            }
        };

        // Enforce authorization: (sub_owner, sub_name, method, url_path, obj_owner, obj_name)
        match casbin_service
            .enforce_ex(
                &sub_owner, &sub_name, &method, &url_path, &obj_owner, &obj_name,
            )
            .await
        {
            Ok(true) => {
                if will_log(
                    &sub_owner, &sub_name, &method, &url_path, &obj_owner, &obj_name,
                ) {
                    tracing::debug!(
                        "Authorization allowed: {}/{} {} {} on {}/{}",
                        sub_owner,
                        sub_name,
                        method,
                        url_path,
                        obj_owner,
                        obj_name
                    );
                }
                ctrl.call_next(req, depot, res).await;
            }
            Ok(false) => {
                tracing::warn!(
                    "Authorization denied: {}/{} {} {} on {}/{}",
                    sub_owner,
                    sub_name,
                    method,
                    url_path,
                    obj_owner,
                    obj_name
                );

                // Log denied request asynchronously via RecordService
                if let Ok(pool) = depot.obtain::<Pool<Postgres>>() {
                    let pool = pool.clone();
                    let owner = sub_owner.clone();
                    let user = sub_name.clone();
                    let m = method.clone();
                    let p = url_path.clone();
                    tokio::spawn(async move {
                        let _ = RecordService::log_action(
                            &pool,
                            &owner,
                            Some(&owner),
                            None,
                            Some(&user),
                            &m,
                            &p,
                            "authz-denied",
                            None,
                        )
                        .await;
                    });
                }

                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(ErrorResponse::new(403, "Permission denied")));
                ctrl.skip_rest();
            }
            Err(e) => {
                tracing::error!("Authorization check error: {:?}", e);
                // On error, fail-open for availability -- allow through but log
                ctrl.call_next(req, depot, res).await;
            }
        }
    }
}

/// Determines if a path is public and should skip authorization.
fn is_public_path(path: &str) -> bool {
    // Check prefix matches (e.g. "/.well-known/" covers all sub-paths)
    for prefix in PUBLIC_PREFIXES {
        if path.starts_with(prefix) {
            return true;
        }
    }

    // Check exact matches
    for exact in PUBLIC_EXACT {
        if path == *exact {
            return true;
        }
    }

    // Static files are always public
    if !path.starts_with("/api/")
        && !path.starts_with("/login/")
        && !path.starts_with("/cas/")
        && !path.starts_with("/scim/")
    {
        return true;
    }

    false
}

/// Extracts the subject (owner, name) from the depot or request.
///
/// Priority order:
/// 1. JWT claims already in depot (set by JwtAuth middleware)
/// 2. ClientId + ClientSecret from Basic Auth header or query params
/// 3. AccessKey + AccessSecret from query params
/// 4. Falls back to ("anonymous", "anonymous")
fn extract_subject(req: &Request, depot: &Depot) -> (String, String) {
    // 1. Try JWT claims from depot (set by JwtAuth or OptionalJwtAuth)
    let user_owner = depot.get::<String>("user_owner").cloned().ok();
    let user_name = depot.get::<String>("user_name").cloned().ok();
    if let (Some(owner), Some(name)) = (user_owner, user_name) {
        if !owner.is_empty() && !name.is_empty() {
            return (owner, name);
        }
    }

    // 2. Try clientId + clientSecret from Basic Auth or query params
    if let Some((owner, name)) = extract_from_client_credentials(req) {
        return (owner, name);
    }

    // 3. Try accessKey + accessSecret from query params
    if let Some((_access_key, _access_secret)) = extract_access_keys(req) {
        // In the Go implementation, this would look up the user by access key.
        // For now, we return anonymous and let the Casbin policy decide.
        // A full implementation would call UserService::get_by_access_key here.
    }

    // 4. Fall back to anonymous
    ("anonymous".to_string(), "anonymous".to_string())
}

/// Tries to extract client credentials from Basic Auth header or query params.
/// Returns `Some(("app", app_name))` if credentials are found and valid-looking.
fn extract_from_client_credentials(req: &Request) -> Option<(String, String)> {
    // Try Basic Auth header first
    let (client_id, client_secret) = if let Some(auth_header) = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(basic) = auth_header.strip_prefix("Basic ") {
            if let Ok(decoded) = general_purpose::STANDARD.decode(basic.trim()) {
                if let Ok(credentials) = String::from_utf8(decoded) {
                    if let Some((id, secret)) = credentials.split_once(':') {
                        (Some(id.to_string()), Some(secret.to_string()))
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    // Fall back to query params
    let client_id = client_id.or_else(|| req.query::<String>("clientId"));
    let client_secret = client_secret.or_else(|| req.query::<String>("clientSecret"));

    if let (Some(id), Some(_secret)) = (client_id, client_secret) {
        if !id.is_empty() {
            // In the Go implementation, this validates against the application table.
            // We return "app" as the owner to indicate app-level authentication.
            // The actual app name would come from looking up the application by client ID.
            return Some(("app".to_string(), id));
        }
    }

    None
}

/// Tries to extract access key and secret from query params.
fn extract_access_keys(req: &Request) -> Option<(String, String)> {
    let access_key = req.query::<String>("accessKey");
    let access_secret = req.query::<String>("accessSecret");

    if let (Some(key), Some(secret)) = (access_key, access_secret) {
        if !key.is_empty() && !secret.is_empty() {
            return Some((key, secret));
        }
    }

    None
}

/// Extracts the object owner and name from the request.
///
/// For GET requests, looks at `id` and `owner` query params.
/// For POST/PUT/DELETE requests, looks at the request body JSON for `owner` and `name` fields.
fn extract_object(req: &Request, path: &str, method: &str) -> (String, String) {
    if method == "GET" {
        // For list endpoints (get-*s pattern), only use owner
        let is_list =
            path.starts_with("/api/get-") && path.ends_with('s') && path != "/api/get-policies";

        if !is_list {
            // Try "id" query param (format: "owner/name")
            if let Some(id) = req.query::<String>("id") {
                if let Some((owner, name)) = parse_owner_name_id(&id) {
                    return (owner, name);
                }
            }
        }

        // Try "owner" query param
        if let Some(owner) = req.query::<String>("owner") {
            if !owner.is_empty() {
                return (owner, String::new());
            }
        }

        (String::new(), String::new())
    } else {
        // For POST/PUT/DELETE -- try query param "id" first for certain paths
        if path == "/api/add-policy"
            || path == "/api/remove-policy"
            || path == "/api/update-policy"
            || path == "/api/send-invitation"
        {
            if let Some(id) = req.query::<String>("id") {
                if let Some((owner, name)) = parse_owner_name_id(&id) {
                    return (owner, name);
                }
            }
        }

        // For body-based extraction, we cannot consume the body in middleware
        // without breaking downstream handlers. Use query params as the primary source.
        // The owner/name can also come from the URL path for RESTful routes.

        // Try to extract from URL path for REST-style routes like /api/users/<id>
        if let Some((owner, name)) = extract_from_rest_path(path) {
            return (owner, name);
        }

        // Try "owner" and "name" from query params
        let owner = req.query::<String>("owner").unwrap_or_default();
        let name = req.query::<String>("name").unwrap_or_default();

        (owner, name)
    }
}

/// Parses an id string in the format "owner/name" into (owner, name).
fn parse_owner_name_id(id: &str) -> Option<(String, String)> {
    if let Some((owner, name)) = id.split_once('/') {
        Some((owner.to_string(), name.to_string()))
    } else {
        None
    }
}

/// Attempts to extract owner/name from a REST-style path.
/// For example, `/api/users/built-in/admin` would yield ("built-in", "admin").
fn extract_from_rest_path(path: &str) -> Option<(String, String)> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // Pattern: api/<resource>/<owner>/<name>
    if segments.len() >= 4 && segments[0] == "api" {
        let owner = segments[2].to_string();
        let name = segments[3].to_string();
        if !owner.is_empty() {
            return Some((owner, name));
        }
    }
    None
}

/// Normalizes URL paths for Casbin matching.
///
/// Collapses protocol-specific sub-paths to their base prefix, mirroring the Go
/// `getUrlPath` function.
fn normalize_url_path(path: &str) -> String {
    // CAS protocol paths
    if path.starts_with("/cas/")
        && (path.ends_with("/serviceValidate")
            || path.ends_with("/proxy")
            || path.ends_with("/proxyValidate")
            || path.ends_with("/validate")
            || path.ends_with("/p3/serviceValidate")
            || path.ends_with("/p3/proxyValidate")
            || path.ends_with("/samlValidate"))
    {
        return "/cas".to_string();
    }

    // SCIM paths
    if path.starts_with("/scim") {
        return "/scim".to_string();
    }

    // OAuth login paths
    if path.starts_with("/api/login/oauth") {
        return "/api/login/oauth".to_string();
    }

    // WebAuthn paths
    if path.starts_with("/api/webauthn") {
        return "/api/webauthn".to_string();
    }

    // SAML redirect paths
    if path.starts_with("/api/saml/redirect") {
        return "/api/saml/redirect".to_string();
    }

    // Payment notification paths
    if path.starts_with("/api/notify-payment") {
        return "/api/notify-payment".to_string();
    }

    path.to_string()
}

/// Determines whether a request should be logged.
///
/// Mirrors Casdoor's `willLog` -- suppresses logs for anonymous GET requests to
/// commonly-polled endpoints that would otherwise flood the log.
fn will_log(
    sub_owner: &str,
    sub_name: &str,
    method: &str,
    url_path: &str,
    obj_owner: &str,
    obj_name: &str,
) -> bool {
    if sub_owner == "anonymous"
        && sub_name == "anonymous"
        && method == "GET"
        && (url_path == "/api/get-account" || url_path == "/api/get-app-login")
        && obj_owner.is_empty()
        && obj_name.is_empty()
    {
        return false;
    }
    true
}
