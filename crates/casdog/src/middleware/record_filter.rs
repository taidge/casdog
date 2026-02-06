use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::services::RecordService;

/// Paths that should not be logged (static files, health checks, swagger docs).
const SKIP_LOG_PREFIXES: &[&str] = &["/swagger-ui/", "/api-doc/", "/api/health", "/.well-known/"];

/// Global audit record middleware.
///
/// Logs ALL API requests to the records table after the response has been produced.
/// Based on Casdoor's `routers/record.go` (`RecordMessage` / `AfterRecordMessage`).
///
/// The logging is performed asynchronously via `tokio::spawn` so that it does not
/// block the response from being sent to the client.
pub struct RecordFilter;

#[async_trait]
impl Handler for RecordFilter {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let method = req.method().as_str().to_string();
        let uri = req.uri().path().to_string();
        let client_ip = req.remote_addr().to_string();

        // Call the next handler first so we can capture the response status
        ctrl.call_next(req, depot, res).await;

        // Skip logging for static files, health checks, swagger, etc.
        if should_skip_logging(&uri) {
            return;
        }

        // Extract user info from depot (set by JwtAuth or OptionalJwtAuth)
        let user_owner = depot
            .get::<String>("user_owner")
            .cloned()
            .ok()
            .unwrap_or_default();
        let user_name = depot
            .get::<String>("user_name")
            .cloned()
            .ok()
            .unwrap_or_default();
        let status = res.status_code.map(|s| s.as_u16()).unwrap_or(200);

        // Derive a human-readable action from the HTTP method and path
        let action = derive_action(&method, &uri);

        // Log the request asynchronously so we do not block the response
        if let Ok(pool) = depot.obtain::<Pool<Postgres>>() {
            let pool = pool.clone();
            tokio::spawn(async move {
                let _ = RecordService::log_action(
                    &pool,
                    if user_owner.is_empty() {
                        "anonymous"
                    } else {
                        &user_owner
                    },
                    if user_owner.is_empty() {
                        None
                    } else {
                        Some(&user_owner)
                    },
                    Some(&client_ip),
                    if user_name.is_empty() {
                        None
                    } else {
                        Some(&user_name)
                    },
                    &method,
                    &uri,
                    &action,
                    Some(&format!("status:{}", status)),
                )
                .await;
            });
        }
    }
}

/// Returns `true` if the given URI should be excluded from audit logging.
fn should_skip_logging(uri: &str) -> bool {
    // Skip known noisy/non-API prefixes
    for prefix in SKIP_LOG_PREFIXES {
        if uri.starts_with(prefix) {
            return true;
        }
    }

    // Skip static file requests (anything not under /api/, /login/, /cas/, /scim/)
    if !uri.starts_with("/api/")
        && !uri.starts_with("/login/")
        && !uri.starts_with("/cas/")
        && !uri.starts_with("/scim/")
    {
        return true;
    }

    false
}

/// Derives a human-readable action name from the HTTP method and URI path.
///
/// Examples:
/// - `GET  /api/users`           -> `"get-users"`
/// - `POST /api/users`           -> `"create-user"`
/// - `PUT  /api/users/<id>`      -> `"update-user"`
/// - `DELETE /api/users/<id>`    -> `"delete-user"`
/// - `POST /api/login`           -> `"login"`
/// - `POST /api/signup`          -> `"signup"`
/// - `POST /api/logout`          -> `"logout"`
fn derive_action(method: &str, uri: &str) -> String {
    // Handle well-known action paths first
    match uri {
        "/api/login" => return "login".to_string(),
        "/api/signup" => return "signup".to_string(),
        "/api/logout" | "/api/sso-logout" => return "logout".to_string(),
        "/api/get-account" => return "get-account".to_string(),
        "/api/set-password" => return "set-password".to_string(),
        "/api/check-user-password" => return "check-user-password".to_string(),
        "/api/send-email" => return "send-email".to_string(),
        "/api/send-sms" => return "send-sms".to_string(),
        "/api/send-notification" => return "send-notification".to_string(),
        _ => {}
    }

    // Extract the resource name from the path
    // Pattern: /api/<resource>[/<id>]
    let segments: Vec<&str> = uri.trim_start_matches('/').split('/').collect();

    if segments.len() >= 2 && segments[0] == "api" {
        let resource = segments[1];

        // Map HTTP method to CRUD action prefix
        let prefix = match method {
            "GET" => "get",
            "POST" => "create",
            "PUT" => "update",
            "DELETE" => "delete",
            "PATCH" => "patch",
            _ => method,
        };

        // Singularize the resource name for non-GET actions or when an id segment exists
        let resource_name = if segments.len() > 2 || method != "GET" {
            singularize(resource)
        } else {
            resource.to_string()
        };

        return format!("{}-{}", prefix, resource_name);
    }

    // For OAuth and other non-standard paths, use method + path
    if uri.starts_with("/login/oauth/") {
        let action = uri.strip_prefix("/login/oauth/").unwrap_or("oauth");
        return format!("oauth-{}", action);
    }

    // CAS / SCIM / SAML paths
    if uri.starts_with("/cas/") {
        return "cas-validate".to_string();
    }
    if uri.starts_with("/scim/") {
        return "scim-request".to_string();
    }

    // Fallback: method-path
    format!(
        "{}-{}",
        method.to_lowercase(),
        uri.trim_start_matches('/').replace('/', "-")
    )
}

/// Naively singularizes a resource name by stripping a trailing "s".
fn singularize(resource: &str) -> String {
    if resource.ends_with("ies") {
        // e.g., "policies" -> "policy"
        let mut s = resource[..resource.len() - 3].to_string();
        s.push('y');
        s
    } else if resource.ends_with("ses") {
        // e.g., "addresses" -> "address"
        resource[..resource.len() - 2].to_string()
    } else if resource.ends_with('s') && !resource.ends_with("ss") {
        resource[..resource.len() - 1].to_string()
    } else {
        resource.to_string()
    }
}
