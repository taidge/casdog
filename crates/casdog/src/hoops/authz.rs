use salvo::prelude::*;
use serde_json::Value;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};

/// Identity supplied only by the validating authentication hoop. Request parameters
/// and credential-shaped headers are never a source of authorization decisions.
#[derive(Debug, Clone)]
pub struct Principal {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub admin: bool,
}

impl Principal {
    pub fn from_depot(depot: &Depot) -> AppResult<Self> {
        let read = |key| {
            depot
                .get::<String>(key)
                .ok()
                .cloned()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| AppError::Authentication("Authenticated user required".into()))
        };
        Ok(Self {
            id: read("user_id")?,
            owner: read("user_owner")?,
            name: read("user_name")?,
            admin: depot.get::<bool>("is_admin").copied().unwrap_or(false),
        })
    }
    pub fn global_admin(&self) -> bool {
        self.admin && self.owner == "built-in"
    }
    pub fn check_owner(&self, object: &Value, table: &str) -> AppResult<()> {
        if self.global_admin() {
            return Ok(());
        }
        let own = if table == "organizations" {
            object.get("name").and_then(Value::as_str) == Some(self.owner.as_str())
        } else {
            object.get("owner").and_then(Value::as_str) == Some(self.owner.as_str())
        };
        let sync_target_allowed = table != "syncers"
            || object.get("organization").and_then(Value::as_str) == Some(self.owner.as_str());
        if own && sync_target_allowed {
            Ok(())
        } else {
            Err(denied())
        }
    }
    pub fn owns_user(&self, object: &Value) -> bool {
        object.get("owner").and_then(Value::as_str) == Some(self.owner.as_str())
            && object.get("id").and_then(Value::as_str) == Some(self.id.as_str())
    }
}

fn denied() -> AppError {
    AppError::Authorization("Permission denied for this tenant or operation".into())
}

/// Closed table mapping: no request-controlled SQL identifiers.
pub fn resource_table(resource: &str) -> Option<&'static str> {
    Some(match resource {
        "users" => "users",
        "organizations" => "organizations",
        "applications" => "applications",
        "roles" => "roles",
        "permissions" => "permissions",
        "providers" => "providers",
        "tokens" => "tokens",
        "groups" => "groups",
        "sessions" => "sessions",
        "certs" => "certificates",
        "resources" => "resources",
        "webhooks" => "webhooks",
        "syncers" => "syncers",
        "invitations" => "invitations",
        "records" => "records",
        "models" => "casbin_models",
        "adapters" => "casbin_adapters",
        "enforcers" => "casbin_enforcers",
        "rules" => "rules",
        "sites" => "sites",
        "products" => "products",
        "plans" => "plans",
        "pricings" => "pricings",
        "subscriptions" => "subscriptions",
        "payments" => "payments",
        "transactions" => "transactions",
        "orders" => "orders",
        "tickets" => "tickets",
        "forms" => "forms",
        _ => return None,
    })
}

pub async fn stored_object(pool: &Pool<Postgres>, table: &str, id: &str) -> AppResult<Value> {
    // All callers pass a literal or resource_table result. REST identifiers are exact IDs.
    sqlx::query_scalar::<_, Value>(&format!("SELECT to_jsonb(t) FROM {table} t WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Resource not found".into()))
}

/// Validate foreign references as well as the row's owner. Otherwise a tenant-owned
/// membership/application can still grant access to another tenant's identity.
pub async fn validate_references(
    pool: &Pool<Postgres>,
    principal: &Principal,
    body: &Value,
) -> AppResult<()> {
    if principal.global_admin() {
        return Ok(());
    }
    let Some(object) = body.as_object() else {
        return Err(denied());
    };
    for (key, value) in object {
        let key = snake_case(key);
        if matches!(key.as_str(), "owner" | "organization") {
            if value
                .as_str()
                .is_some_and(|value| !value.is_empty() && value != principal.owner)
            {
                return Err(denied());
            }
        }
        let table = match key.as_str() {
            "user_id" => Some("users"),
            "role_id" => Some("roles"),
            "permission_id" => Some("permissions"),
            "group_id" | "parent_id" => Some("groups"),
            "application_id" => Some("applications"),
            "provider_id" => Some("providers"),
            "invitation_id" => Some("invitations"),
            "payment_id" => Some("payments"),
            "order_id" => Some("orders"),
            _ => None,
        };
        if let Some(table) = table {
            if let Some(id) = value.as_str().filter(|s| !s.is_empty()) {
                principal.check_owner(&stored_object(pool, table, id).await?, table)?;
            }
        }
        if matches!(
            key.as_str(),
            "application" | "provider" | "model" | "adapter"
        ) {
            if let Some(reference) = value.as_str().filter(|s| !s.is_empty()) {
                let table = match key.as_str() {
                    "application" => "applications",
                    "provider" => "providers",
                    "model" => "casbin_models",
                    _ => "casbin_adapters",
                };
                check_named_reference(pool, principal, table, reference).await?;
            }
        }
        if matches!(
            key.as_str(),
            "users" | "roles" | "groups" | "providers" | "permissions"
        ) {
            if let Some(values) = value.as_array() {
                let table = resource_table(&key).ok_or_else(denied)?;
                for value in values {
                    let reference = value
                        .as_str()
                        .or_else(|| value.get("name").and_then(Value::as_str));
                    if let Some(reference) = reference {
                        check_named_reference(pool, principal, table, reference).await?;
                    } else {
                        return Err(denied());
                    }
                }
            }
        }
    }
    Ok(())
}

/// Singular commerce/token `user` fields are IAM references; Syncer.user is an
/// external database login and must not be interpreted as an IAM identity.
pub async fn validate_resource_references(
    pool: &Pool<Postgres>,
    principal: &Principal,
    body: &Value,
    table: &str,
) -> AppResult<()> {
    validate_references(pool, principal, body).await?;
    if !principal.global_admin()
        && matches!(
            table,
            "tokens" | "orders" | "payments" | "subscriptions" | "transactions"
        )
    {
        if let Some(user) = body
            .get("user")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            check_named_reference(pool, principal, "users", user).await?;
        }
    }
    Ok(())
}

async fn validate_order_targets(
    pool: &Pool<Postgres>,
    principal: &Principal,
    object: &Value,
) -> AppResult<()> {
    let mut references = serde_json::Map::new();
    for key in ["user", "application", "provider", "payment_id"] {
        if let Some(value) = object.get(key) {
            references.insert(key.into(), value.clone());
        }
    }
    validate_resource_references(pool, principal, &Value::Object(references), "orders").await
}

async fn check_named_reference(
    pool: &Pool<Postgres>,
    p: &Principal,
    table: &str,
    reference: &str,
) -> AppResult<()> {
    let object: Option<Value> = if let Some((owner, name)) = reference.split_once('/') {
        if owner != p.owner {
            return Err(denied());
        }
        sqlx::query_scalar(&format!(
            "SELECT to_jsonb(t) FROM {table} t WHERE owner=$1 AND name=$2"
        ))
        .bind(owner)
        .bind(name)
        .fetch_optional(pool)
        .await?
    } else {
        // Downstream resolvers prefer UUIDs over names. Check that exact resolution,
        // so naming an owned object after another tenant's UUID cannot bypass scope.
        sqlx::query_scalar(&format!("SELECT to_jsonb(t) FROM {table} t WHERE id=$1 OR (owner=$2 AND name=$1) ORDER BY (id=$1) DESC LIMIT 1"))
            .bind(reference).bind(&p.owner).fetch_optional(pool).await?
    };
    p.check_owner(&object.ok_or_else(denied)?, table)
}

pub fn validate_profile(body: &Value) -> AppResult<()> {
    let object = body.as_object().ok_or_else(denied)?;
    const FIELDS: &[&str] = &[
        "display_name",
        "avatar",
        "first_name",
        "last_name",
        "location",
        "address",
        "country_code",
        "region",
        "language",
        "affiliation",
        "title",
        "homepage",
        "bio",
        "tag",
        "gender",
        "birthday",
        "education",
    ];
    if object
        .keys()
        .all(|key| FIELDS.contains(&snake_case(key).as_str()))
    {
        Ok(())
    } else {
        Err(denied())
    }
}

fn snake_case(key: &str) -> String {
    let mut result = String::new();
    for c in key.chars() {
        if c.is_ascii_uppercase() {
            result.push('_');
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }
    result
}

/// Mounted only on protected routes, after JwtAuth. Every route is either explicitly
/// tenant-scoped, delegates to an audited self-service handler, or requires global admin.
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
        match authorize(req, depot).await {
            Ok(()) => {
                ctrl.call_next(req, depot, res).await;
            }
            Err(error) => {
                error.write(req, depot, res).await;
                ctrl.skip_rest();
            }
        }
    }
}

async fn authorize(req: &mut Request, depot: &Depot) -> AppResult<()> {
    let p = Principal::from_depot(depot)?;
    if p.global_admin() {
        return Ok(());
    }
    let path = req
        .uri()
        .path()
        .trim_end_matches('/')
        .trim_start_matches("/api/")
        .to_string();
    let method = req.method().as_str().to_string();
    // These handlers bind identity/proofs to the authenticated user themselves.
    if matches!(
        path.as_str(),
        "logout"
            | "get-account"
            | "is-session-duplicated"
            | "get-idp-discovery"
            | "set-password"
            | "check-user-password"
            | "reset-email-or-phone"
            | "verify-identification"
            | "login/oauth/device/verify"
            | "login/oauth/device/authorize"
            | "grant-consent"
            | "revoke-consent"
            | "sso-logout"
            | "unlink"
            | "exit-impersonate-user"
            | "mfa/setup"
            | "mfa/verify"
            | "mfa/enable"
            | "mfa/setup/initiate"
            | "mfa/setup/verify"
            | "mfa/setup/enable"
            | "mfa/delete"
            | "mfa/set-preferred"
            | "delete-mfa"
            | "set-preferred-mfa"
            | "webauthn/signup/begin"
            | "webauthn/signup/finish"
            | "webauthn/credentials"
            | "send-email"
            | "send-sms"
            | "send-notification"
            | "oauth/register"
            | "verification/send-code"
            | "verification/verify-code"
            | "verification/reset-email-or-phone"
    ) || (path.starts_with("webauthn/credentials/") && method == "DELETE")
        || path == "auth/links"
        || (path.starts_with("auth/") && (path.ends_with("/unlink") || path.ends_with("/link")))
        || path == "scim/v2/Users"
        || path.starts_with("scim/v2/Users/")
    {
        return Ok(());
    }

    // These handlers enforce tenant and resource policy against persisted rows.
    if matches!(
        path.as_str(),
        "get-agents"
            | "upload-resource"
            | "get-openclaw-session-transcript"
            | "sync-mcp-tool"
            | "scan"
            | "get-agent"
            | "add-agent"
            | "update-agent"
            | "delete-agent"
            | "get-entries"
            | "get-entry"
            | "add-entry"
            | "update-entry"
            | "delete-entry"
            | "get-keys"
            | "get-key"
            | "add-key"
            | "update-key"
            | "delete-key"
            | "get-servers"
            | "get-server"
            | "add-server"
            | "update-server"
            | "delete-server"
            | "get-global-keys"
            | "get-mcp-access-token"
            | "get-online-servers"
            | "get-integrations"
            | "get-integration"
            | "install-integration"
            | "delete-integration"
            | "get-marketplace-index"
            | "get-marketplace-bundle"
            | "get-openclaw-session-graph"
            | "get-webhook-events"
            | "get-webhook-event-detail"
            | "delete-webhook-event"
            | "replay-webhook-event"
            | "get-coupons"
            | "get-coupon"
            | "add-coupon"
            | "update-coupon"
            | "delete-coupon"
            | "validate-coupon"
            | "buy-product"
            | "set-subscription-auto-renew"
            | "get-dashboard-heatmap"
            | "get-dashboard-mfa"
            | "get-dashboard-providers"
            | "get-setting"
            | "update-setting"
            | "get-email-and-phone"
            | "update-permissions"
            | "update-cert-domain-expire"
    ) {
        return Ok(());
    }

    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Authorization database unavailable".into()))?;
    let body = if matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        let bytes = req
            .payload()
            .await
            .map_err(|_| AppError::Validation("Cannot read request body".into()))?;
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(bytes)
                .map_err(|_| AppError::Validation("Invalid JSON body".into()))?
        }
    } else {
        Value::Null
    };

    // Generic compatibility CRUD already checks actual rows, explicit policy grants,
    // self profile fields and list ownership. Still validate cross-resource references.
    if let Some((verb, resource)) = path.split_once('-') {
        let plural = if resource == "pricings" {
            resource.to_string()
        } else {
            format!("{resource}s")
        };
        if matches!(verb, "get" | "add" | "update" | "delete")
            && (resource_table(resource).is_some() || resource_table(&plural).is_some())
        {
            if resource == "organization" && matches!(verb, "add" | "delete") {
                return Err(denied());
            }
            if !body.is_null() {
                let mut references = body.clone();
                if resource == "organization" {
                    if let Some(object) = references.as_object_mut() {
                        object.remove("owner");
                    }
                }
                let table = resource_table(resource)
                    .or_else(|| resource_table(&plural))
                    .ok_or_else(denied)?;
                validate_resource_references(pool, &p, &references, table).await?;
            }
            return Ok(());
        }
    }
    if matches!(
        path.as_str(),
        "get-user-orders" | "get-user-payments" | "get-records-filter" | "add-user-keys"
    ) {
        if !body.is_null() {
            validate_references(pool, &p, &body).await?;
        }
        return Ok(());
    }

    if matches!(
        path.as_str(),
        "remove-user-from-group"
            | "get-invitation-info"
            | "send-invitation"
            | "run-syncer"
            | "add-ticket-message"
    ) {
        if !p.admin {
            return Err(denied());
        }
        return Ok(()); // each wrapper resolves and authorizes its stored target(s)
    }
    if matches!(
        path.as_str(),
        "get-sorted-users"
            | "get-user-count"
            | "get-organization-applications"
            | "get-default-application"
            | "get-ldaps"
    ) || (path == "ldap" && method == "GET")
    {
        if !p.admin {
            return Err(denied());
        }
        if req
            .query::<String>("owner")
            .is_some_and(|o| !o.is_empty() && o != p.owner)
        {
            return Err(denied());
        }
        req.queries_mut().insert("owner".into(), p.owner.clone());
        return Ok(());
    }
    if path == "get-user-application" {
        if !p.admin {
            return Err(denied());
        }
        let user_id = req.query::<String>("user_id").ok_or_else(denied)?;
        p.check_owner(&stored_object(pool, "users", &user_id).await?, "users")?;
        return Ok(());
    }
    if path == "get-permissions-by-submitter" {
        if !p.admin || req.query::<String>("submitter").as_deref() != Some(p.owner.as_str()) {
            return Err(denied());
        }
        return Ok(());
    }
    if path == "get-permissions-by-role" {
        if !p.admin {
            return Err(denied());
        }
        let id = req.query::<String>("role_id").ok_or_else(denied)?;
        p.check_owner(&stored_object(pool, "roles", &id).await?, "roles")?;
        return Ok(());
    }
    if path == "add-ldap" || (path == "ldap" && method == "POST") {
        if !p.admin || body.get("owner").and_then(Value::as_str) != Some(p.owner.as_str()) {
            return Err(denied());
        }
        return validate_references(pool, &p, &body).await;
    }
    if matches!(
        path.as_str(),
        "get-ldap" | "get-ldap-users" | "update-ldap" | "delete-ldap" | "ldap/users"
    ) || (path.starts_with("ldap/")
        && !matches!(path.as_str(), "ldap/sync-users" | "ldap/test-connection"))
    {
        if !p.admin {
            return Err(denied());
        }
        let id = req
            .query::<String>("id")
            .or_else(|| body.get("id").and_then(Value::as_str).map(str::to_string))
            .or_else(|| req.param::<String>("id"))
            .ok_or_else(denied)?;
        p.check_owner(&stored_object(pool, "providers", &id).await?, "providers")?;
        if !body.is_null() {
            validate_references(pool, &p, &body).await?;
        }
        return Ok(());
    }
    if matches!(
        path.as_str(),
        "pay-order" | "cancel-order" | "invoice-payment" | "payments/invoice"
    ) {
        if !p.admin {
            return Err(denied());
        }
        let table = if path.contains("order") {
            "orders"
        } else {
            "payments"
        };
        let id = req.query::<String>("id").ok_or_else(denied)?;
        let object = stored_object(pool, table, &id).await?;
        p.check_owner(&object, table)?;
        if table == "orders" {
            validate_order_targets(pool, &p, &object).await?;
        }
        if let Some(provider) = req.query::<String>("provider_name") {
            check_named_reference(pool, &p, "providers", &provider).await?;
        }
        return Ok(());
    }
    let segments: Vec<_> = path.split('/').collect();
    if let Some(table) = resource_table(segments[0]) {
        // Administrative operations on collections and foreign-key relationships.
        if matches!(
            path.as_str(),
            "roles/assign" | "permissions/assign" | "groups/add-user" | "groups/remove-user"
        ) {
            if !p.admin {
                return Err(denied());
            }
            validate_references(pool, &p, &body).await?;
            return Ok(());
        }
        if segments.len() == 3
            && matches!(
                (segments[0], segments[1]),
                ("roles", "user") | ("permissions", "role")
            )
        {
            let parent_table = if segments[0] == "roles" {
                "users"
            } else {
                "roles"
            };
            let object = stored_object(pool, parent_table, segments[2]).await?;
            p.check_owner(&object, parent_table)?;
            if !p.admin && !(parent_table == "users" && p.owns_user(&object)) {
                return Err(denied());
            }
            return Ok(());
        }
        if segments.len() == 1 {
            if method == "GET" {
                if !p.admin && !matches!(table, "users" | "organizations" | "sessions") {
                    return Err(denied());
                }
                if req
                    .query::<String>("owner")
                    .is_some_and(|o| !o.is_empty() && o != p.owner)
                {
                    return Err(denied());
                }
                req.queries_mut().insert("owner".into(), p.owner.clone());
                return Ok(());
            }
            if method == "POST" && p.admin && table != "organizations" {
                if body.get("owner").and_then(Value::as_str) != Some(p.owner.as_str()) {
                    return Err(denied());
                }
                validate_resource_references(pool, &p, &body, table).await?;
                return Ok(());
            }
            return Err(denied());
        }
        if path == "records/filter" {
            if !p.admin {
                return Err(denied());
            }
            validate_references(pool, &p, &body).await?;
            return Ok(()); // handler forces owner in its deserialized filter
        }
        if matches!(path.as_str(), "invitations/send" | "sessions/is-duplicated") {
            if !p.admin {
                return Err(denied());
            }
            validate_references(pool, &p, &body).await?;
            return Ok(());
        }
        // Only recognized suffixes may inherit object authorization.
        if segments.len() > 2
            && !(segments.len() == 3
                && matches!(
                    (segments[0], segments[2]),
                    ("groups", "users")
                        | ("syncers", "run")
                        | ("orders", "pay")
                        | ("orders", "cancel")
                ))
        {
            return Err(denied());
        }
        let object = stored_object(pool, table, segments[1]).await?;
        p.check_owner(&object, table)?;
        if !p.admin {
            match (table, method.as_str()) {
                ("users", "GET") if p.owns_user(&object) => {}
                ("users", "PUT" | "PATCH") if p.owns_user(&object) => validate_profile(&body)?,
                ("organizations", "GET") => {}
                ("sessions", "GET" | "DELETE")
                    if object.get("user_id").and_then(Value::as_str) == Some(p.id.as_str()) => {}
                _ => return Err(denied()),
            }
        }
        if table == "organizations" && method == "DELETE" {
            return Err(denied());
        }
        if table == "orders" {
            if segments.len() == 3 {
                validate_order_targets(pool, &p, &object).await?;
            }
            if let Some(provider) = req.query::<String>("provider_name") {
                check_named_reference(pool, &p, "providers", &provider).await?;
            }
        }
        if !body.is_null() {
            let mut references = body.clone();
            if table == "organizations" {
                if let Some(map) = references.as_object_mut() {
                    map.remove("owner");
                }
            }
            validate_resource_references(pool, &p, &references, table).await?;
        }
        return Ok(());
    }
    // Unclassified global collections, Casbin policy/engine operations, system metrics,
    // bulk imports, network test operations and payment callbacks remain global-admin only.
    Err(denied())
}
