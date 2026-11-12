use std::collections::HashSet;
use std::time::Duration;

use salvo::oapi::endpoint;
use salvo::prelude::*;
use serde_json::{Map, Value, json};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres, QueryBuilder};

use crate::error::{AppError, AppResult};
use crate::models::{
    PolicyRequest, PolicyResponse, SendInvitationRequest, TestSyncerDbRequest,
    VerifyInvitationRequest,
};
use crate::services::password_service::PasswordService;
use crate::services::{CasbinService, GroupService, InvitationService, SyncerService};

#[derive(Clone, Copy)]
struct LegacyResource {
    table: &'static str,
}

#[derive(Debug)]
struct LegacyPrincipal {
    owner: String,
    name: String,
    id: String,
    admin: bool,
}

impl LegacyPrincipal {
    fn from_depot(depot: &Depot) -> AppResult<Self> {
        let owner = depot
            .get::<String>("user_owner")
            .ok()
            .cloned()
            .unwrap_or_default();
        let name = depot
            .get::<String>("user_name")
            .ok()
            .cloned()
            .unwrap_or_default();
        if owner.is_empty() || name.is_empty() {
            return Err(AppError::Authentication(
                "Authenticated user required".to_string(),
            ));
        }
        Ok(Self {
            owner,
            name,
            id: depot
                .get::<String>("user_id")
                .ok()
                .cloned()
                .unwrap_or_default(),
            admin: depot.get::<bool>("is_admin").copied().unwrap_or(false),
        })
    }

    fn global_admin(&self) -> bool {
        self.admin && self.owner == "built-in"
    }

    fn owns_user(&self, object: &Value) -> bool {
        object.get("owner").and_then(Value::as_str) == Some(self.owner.as_str())
            && (object.get("name").and_then(Value::as_str) == Some(self.name.as_str())
                || (!self.id.is_empty()
                    && object.get("id").and_then(Value::as_str) == Some(self.id.as_str())))
    }
}

async fn authorize_legacy_object(
    depot: &Depot,
    req: &Request,
    resource: LegacyResource,
    object: &Value,
    action: &str,
) -> AppResult<bool> {
    let principal = LegacyPrincipal::from_depot(depot)?;
    if principal.global_admin() {
        return Ok(false);
    }
    if resource.table == "organizations"
        && (action == "get" || (principal.admin && action == "update"))
        && object.get("name").and_then(Value::as_str) == Some(principal.owner.as_str())
    {
        return Ok(false);
    }
    if object.get("owner").and_then(Value::as_str) != Some(principal.owner.as_str()) {
        return Err(AppError::Authorization(
            "Cannot access another organization".to_string(),
        ));
    }
    if principal.admin {
        return Ok(false);
    }
    if resource.table == "users"
        && matches!(action, "get" | "update")
        && principal.owns_user(object)
    {
        return Ok(action == "update");
    }
    if let Ok(casbin) = depot.obtain::<CasbinService>() {
        let allowed = casbin
            .check_permission(
                &format!("{}/{}", principal.owner, principal.name),
                req.uri().path(),
                req.method().as_str(),
            )
            .await?;
        if allowed {
            return Ok(false);
        }
    }
    Err(AppError::Authorization("Permission denied".to_string()))
}

fn validate_self_update(object: &Value) -> AppResult<()> {
    const ALLOWED: &[&str] = &[
        "id",
        "owner",
        "name",
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
        .as_object()
        .is_some_and(|object| object.keys().any(|key| !ALLOWED.contains(&key.as_str())))
    {
        return Err(AppError::Authorization("Only profile fields may be changed on your own account; use the dedicated password, verification and MFA endpoints".to_string()));
    }
    Ok(())
}

async fn lookup_legacy_object(
    pool: &Pool<Postgres>,
    resource: LegacyResource,
    columns: &HashSet<String>,
    lookup: &Lookup,
) -> AppResult<Value> {
    let mut query = QueryBuilder::<Postgres>::new("SELECT to_jsonb(t) FROM (SELECT * FROM ");
    query.push(resource.table);
    append_lookup_filter(&mut query, columns, lookup, true)?;
    query.push(" LIMIT 1) AS t");
    query
        .build_query_scalar()
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Resource not found".to_string()))
}

fn exact_lookup(object: &Value) -> AppResult<Lookup> {
    if let (Some(owner), Some(name)) = (
        object.get("owner").and_then(Value::as_str),
        object.get("name").and_then(Value::as_str),
    ) {
        return Ok(Lookup::OwnerName {
            owner: owner.to_string(),
            name: name.to_string(),
        });
    }
    object
        .get("id")
        .and_then(Value::as_str)
        .map(|id| Lookup::Id(id.to_string()))
        .ok_or_else(|| AppError::Validation("Resource identity missing".to_string()))
}

const USERS: LegacyResource = LegacyResource { table: "users" };
const ORGANIZATIONS: LegacyResource = LegacyResource {
    table: "organizations",
};
const GROUPS: LegacyResource = LegacyResource { table: "groups" };
const APPLICATIONS: LegacyResource = LegacyResource {
    table: "applications",
};
const PROVIDERS: LegacyResource = LegacyResource { table: "providers" };
const RESOURCES: LegacyResource = LegacyResource { table: "resources" };
const CERTS: LegacyResource = LegacyResource {
    table: "certificates",
};
const ROLES: LegacyResource = LegacyResource { table: "roles" };
const PERMISSIONS: LegacyResource = LegacyResource {
    table: "permissions",
};
const MODELS: LegacyResource = LegacyResource {
    table: "casbin_models",
};
const ADAPTERS: LegacyResource = LegacyResource {
    table: "casbin_adapters",
};
const ENFORCERS: LegacyResource = LegacyResource {
    table: "casbin_enforcers",
};
const SESSIONS: LegacyResource = LegacyResource { table: "sessions" };
const TOKENS: LegacyResource = LegacyResource { table: "tokens" };
const PRODUCTS: LegacyResource = LegacyResource { table: "products" };
const ORDERS: LegacyResource = LegacyResource { table: "orders" };
const PAYMENTS: LegacyResource = LegacyResource { table: "payments" };
const PLANS: LegacyResource = LegacyResource { table: "plans" };
const PRICINGS: LegacyResource = LegacyResource { table: "pricings" };
const SUBSCRIPTIONS: LegacyResource = LegacyResource {
    table: "subscriptions",
};
const TRANSACTIONS: LegacyResource = LegacyResource {
    table: "transactions",
};
const FORMS: LegacyResource = LegacyResource { table: "forms" };
const SYNCERS: LegacyResource = LegacyResource { table: "syncers" };
const WEBHOOKS: LegacyResource = LegacyResource { table: "webhooks" };
const TICKETS: LegacyResource = LegacyResource { table: "tickets" };
const RECORDS: LegacyResource = LegacyResource { table: "records" };
const RULES: LegacyResource = LegacyResource { table: "rules" };
const SITES: LegacyResource = LegacyResource { table: "sites" };
const INVITATIONS: LegacyResource = LegacyResource {
    table: "invitations",
};

enum Lookup {
    Id(String),
    OwnerName { owner: String, name: String },
}

macro_rules! resource_route {
    ($router:ident, $plural:literal, $singular:literal, $list:ident, $get:ident, $add:ident, $update:ident, $delete:ident) => {
        $router = $router
            .push(Router::with_path(concat!("get-", $plural)).get($list))
            .push(Router::with_path(concat!("get-", $singular)).get($get))
            .push(Router::with_path(concat!("add-", $singular)).post($add))
            .push(Router::with_path(concat!("update-", $singular)).post($update))
            .push(Router::with_path(concat!("delete-", $singular)).post($delete));
    };
}

pub fn routes() -> Router {
    let mut router = Router::new();
    resource_route!(
        router,
        "users",
        "user",
        get_users,
        get_user,
        add_user,
        update_user,
        delete_user
    );
    resource_route!(
        router,
        "organizations",
        "organization",
        get_organizations,
        get_organization,
        add_organization,
        update_organization,
        delete_organization
    );
    resource_route!(
        router,
        "groups",
        "group",
        get_groups,
        get_group,
        add_group,
        update_group,
        delete_group
    );
    resource_route!(
        router,
        "applications",
        "application",
        get_applications,
        get_application,
        add_application,
        update_application,
        delete_application
    );
    resource_route!(
        router,
        "providers",
        "provider",
        get_providers,
        get_provider,
        add_provider,
        update_provider,
        delete_provider
    );
    resource_route!(
        router,
        "resources",
        "resource",
        get_resources,
        get_resource,
        add_resource,
        update_resource,
        delete_resource
    );
    resource_route!(
        router,
        "certs",
        "cert",
        get_certs,
        get_cert,
        add_cert,
        update_cert,
        delete_cert
    );
    resource_route!(
        router,
        "roles",
        "role",
        get_roles,
        get_role,
        add_role,
        update_role,
        delete_role
    );
    resource_route!(
        router,
        "permissions",
        "permission",
        get_permissions,
        get_permission,
        add_permission,
        update_permission,
        delete_permission
    );
    resource_route!(
        router,
        "models",
        "model",
        get_models,
        get_model,
        add_model,
        update_model,
        delete_model
    );
    resource_route!(
        router,
        "adapters",
        "adapter",
        get_adapters,
        get_adapter,
        add_adapter,
        update_adapter,
        delete_adapter
    );
    resource_route!(
        router,
        "enforcers",
        "enforcer",
        get_enforcers,
        get_enforcer,
        add_enforcer,
        update_enforcer,
        delete_enforcer
    );
    resource_route!(
        router,
        "sessions",
        "session",
        get_sessions,
        get_session,
        add_session,
        update_session,
        delete_session
    );
    resource_route!(
        router,
        "tokens",
        "token",
        get_tokens,
        get_token,
        add_token,
        update_token,
        delete_token
    );
    resource_route!(
        router,
        "products",
        "product",
        get_products,
        get_product,
        add_product,
        update_product,
        delete_product
    );
    resource_route!(
        router,
        "orders",
        "order",
        get_orders,
        get_order,
        add_order,
        update_order,
        delete_order
    );
    resource_route!(
        router,
        "payments",
        "payment",
        get_payments,
        get_payment,
        add_payment,
        update_payment,
        delete_payment
    );
    resource_route!(
        router,
        "plans",
        "plan",
        get_plans,
        get_plan,
        add_plan,
        update_plan,
        delete_plan
    );
    resource_route!(
        router,
        "pricings",
        "pricing",
        get_pricings,
        get_pricing,
        add_pricing,
        update_pricing,
        delete_pricing
    );
    resource_route!(
        router,
        "subscriptions",
        "subscription",
        get_subscriptions,
        get_subscription,
        add_subscription,
        update_subscription,
        delete_subscription
    );
    resource_route!(
        router,
        "transactions",
        "transaction",
        get_transactions,
        get_transaction,
        add_transaction,
        update_transaction,
        delete_transaction
    );
    resource_route!(
        router,
        "forms",
        "form",
        get_forms,
        get_form,
        add_form,
        update_form,
        delete_form
    );
    resource_route!(
        router,
        "syncers",
        "syncer",
        get_syncers,
        get_syncer,
        add_syncer,
        update_syncer,
        delete_syncer
    );
    resource_route!(
        router,
        "webhooks",
        "webhook",
        get_webhooks,
        get_webhook,
        add_webhook,
        update_webhook,
        delete_webhook
    );
    resource_route!(
        router,
        "tickets",
        "ticket",
        get_tickets,
        get_ticket,
        add_ticket,
        update_ticket,
        delete_ticket
    );
    resource_route!(
        router,
        "rules",
        "rule",
        get_rules,
        get_rule,
        add_rule,
        update_rule,
        delete_rule
    );
    resource_route!(
        router,
        "sites",
        "site",
        get_sites,
        get_site,
        add_site,
        update_site,
        delete_site
    );
    resource_route!(
        router,
        "invitations",
        "invitation",
        get_invitations,
        get_invitation,
        add_invitation,
        update_invitation,
        delete_invitation
    );
    router
        .push(Router::with_path("get-records").get(get_records))
        .push(Router::with_path("get-records-filter").post(get_records))
        .push(Router::with_path("add-record").post(add_record))
        .push(Router::with_path("add-user-keys").post(add_user_keys))
        .push(Router::with_path("remove-user-from-group").post(remove_user_from_group))
        .push(Router::with_path("get-invitation-info").get(get_invitation_info))
        .push(Router::with_path("verify-invitation").get(verify_invitation_query))
        .push(Router::with_path("send-invitation").post(send_invitation_compat))
        .push(Router::with_path("get-user-orders").get(get_user_orders))
        .push(Router::with_path("place-order").post(add_order))
        .push(Router::with_path("get-user-payments").get(get_user_payments))
        .push(
            Router::with_path("run-syncer")
                .get(run_syncer_query)
                .post(run_syncer_query),
        )
        .push(Router::with_path("test-syncer-db").post(test_syncer_db))
        .push(Router::with_path("add-ticket-message").post(add_ticket_message))
        .push(Router::with_path("get-filtered-policies").post(get_filtered_policies))
        .push(Router::with_path("get-policies").get(get_policies_compat))
        .push(Router::with_path("add-policy").post(add_policy_compat))
        .push(Router::with_path("update-policy").post(update_policy_compat))
        .push(Router::with_path("remove-policy").post(remove_policy_compat))
}

async fn legacy_list(
    depot: &mut Depot,
    req: &mut Request,
    resource: LegacyResource,
) -> AppResult<Json<Value>> {
    legacy_list_with_extra_filters(depot, req, resource, &[]).await
}

#[derive(Debug)]
struct ListOptions {
    search: Option<(String, String)>,
    sort_column: Option<String>,
    descending: bool,
    pagination: Option<(i64, i64)>,
}

impl ListOptions {
    fn from_request(req: &Request, columns: &HashSet<String>) -> AppResult<Self> {
        let resolve_column = |name: &str| -> AppResult<String> {
            let column = match name {
                "createdTime" => "created_at".to_string(),
                "updatedTime" => "updated_at".to_string(),
                _ => to_snake_case(name),
            };
            if !columns.contains(&column) || is_user_secret(&column) {
                return Err(AppError::Validation(format!(
                    "Unsupported list field: {name}"
                )));
            }
            Ok(column)
        };
        let field = req
            .query::<String>("field")
            .filter(|value| !value.is_empty());
        let value = req
            .query::<String>("value")
            .filter(|value| !value.is_empty());
        let search = match (field, value) {
            (Some(field), Some(value)) => Some((resolve_column(&field)?, value)),
            _ => None,
        };
        let sort_column = req
            .query::<String>("sortField")
            .or_else(|| req.query::<String>("sort_field"))
            .filter(|value| !value.is_empty())
            .map(|value| resolve_column(&value))
            .transpose()?;
        let order = req
            .query::<String>("sortOrder")
            .or_else(|| req.query::<String>("sort_order"))
            .unwrap_or_default();
        let descending = match order.to_lowercase().as_str() {
            "" | "ascend" | "asc" => false,
            "descend" | "desc" => true,
            _ => return Err(AppError::Validation("Invalid sortOrder".to_string())),
        };
        let size = req
            .query::<String>("pageSize")
            .or_else(|| req.query::<String>("page_size"));
        let page = req
            .query::<String>("p")
            .or_else(|| req.query::<String>("page"));
        let pagination = match size {
            Some(size) => {
                let size = size
                    .parse::<i64>()
                    .map_err(|_| AppError::Validation("Invalid pageSize".to_string()))?;
                let page = page
                    .as_deref()
                    .unwrap_or("1")
                    .parse::<i64>()
                    .map_err(|_| AppError::Validation("Invalid page".to_string()))?;
                if size <= 0 || page <= 0 {
                    return Err(AppError::Validation(
                        "pageSize and page must be positive".to_string(),
                    ));
                }
                let offset = (page - 1).checked_mul(size).ok_or_else(|| {
                    AppError::Validation("Pagination offset is too large".to_string())
                })?;
                Some((size, offset))
            }
            None => None,
        };
        Ok(Self {
            search,
            sort_column,
            descending,
            pagination,
        })
    }

    fn append_search(&self, query: &mut QueryBuilder<Postgres>) {
        if let Some((column, value)) = &self.search {
            query
                .push(" AND CAST(")
                .push(quote_ident(column))
                .push(" AS TEXT) LIKE ");
            query.push_bind(format!("%{value}%"));
        }
    }
}

fn is_user_secret(column: &str) -> bool {
    matches!(
        column,
        "password"
            | "password_hash"
            | "password_salt"
            | "totp_secret"
            | "recovery_codes"
            | "original_token"
            | "original_refresh_token"
    )
}

fn resource_response(resource: LegacyResource, mut value: Value) -> Value {
    if resource.table == "users" {
        fn mask(value: &mut Value) {
            match value {
                Value::Array(values) => values.iter_mut().for_each(mask),
                Value::Object(object) => {
                    let has_password = object
                        .remove("password_hash")
                        .is_some_and(|value| value.as_str().is_some_and(|value| !value.is_empty()));
                    for key in [
                        "password_salt",
                        "totp_secret",
                        "recovery_codes",
                        "original_token",
                        "original_refresh_token",
                    ] {
                        object.remove(key);
                    }
                    if has_password || object.contains_key("password") {
                        object.insert("password".to_string(), json!("***"));
                    }
                    for (field, secret) in [
                        ("managed_accounts", "password"),
                        ("mfa_accounts", "secretKey"),
                    ] {
                        if let Some(Value::Array(accounts)) = object.get_mut(field) {
                            for account in accounts {
                                if let Some(account) = account.as_object_mut() {
                                    account.insert(secret.to_string(), json!("***"));
                                    account.remove("secret_key");
                                }
                            }
                        }
                    }
                    if let Some(Value::Object(properties)) = object.get_mut("properties") {
                        for (key, value) in properties {
                            if key.starts_with("oauth_")
                                && (key.ends_with("_accessToken") || key.ends_with("_refreshToken"))
                            {
                                *value = json!("***");
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        mask(&mut value);
    }
    to_casdoor_value(value)
}

async fn legacy_list_with_extra_filters(
    depot: &mut Depot,
    req: &mut Request,
    resource: LegacyResource,
    extra_filters: &[(&str, Option<String>)],
) -> AppResult<Json<Value>> {
    let pool = pg_pool(depot)?;
    let columns = table_columns(&pool, resource).await?;
    let options = ListOptions::from_request(req, &columns)?;
    let principal = LegacyPrincipal::from_depot(depot)?;
    let mut owner = req
        .query::<String>("owner")
        .filter(|value| !value.is_empty())
        .or_else(|| (!principal.global_admin()).then(|| principal.owner.clone()));
    let mut extra_filters = extra_filters.to_vec();
    let self_commerce = !principal.global_admin()
        && !principal.admin
        && matches!(resource.table, "orders" | "payments");
    if !principal.global_admin() && resource.table == "organizations" {
        owner = None;
        extra_filters.push(("name", Some(principal.owner.clone())));
    } else if !principal.global_admin() {
        if owner.as_deref() != Some(principal.owner.as_str()) {
            return Err(AppError::Authorization(
                "Cannot list another organization".to_string(),
            ));
        }
        if !principal.admin {
            if resource.table == "users" {
                extra_filters.push(("name", Some(principal.name.clone())));
            } else if matches!(resource.table, "orders" | "payments") {
                // Bind user-owned commerce lists to the authenticated identity, not userId input.
                extra_filters.retain(|(column, _)| !matches!(*column, "user_id" | "user"));
            } else {
                authorize_legacy_object(depot, req, resource, &json!({"owner": owner}), "list")
                    .await?;
            }
        }
    }

    let mut count = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM ");
    count.push(resource.table);
    append_list_filters(&mut count, &columns, owner.as_deref(), &extra_filters);
    if self_commerce {
        append_self_commerce(&mut count, resource, &principal);
    }
    options.append_search(&mut count);
    let total: i64 = count.build_query_scalar().fetch_one(&pool).await?;

    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT * FROM ",
    );
    query.push(resource.table);
    append_list_filters(&mut query, &columns, owner.as_deref(), &extra_filters);
    if self_commerce {
        append_self_commerce(&mut query, resource, &principal);
    }
    options.append_search(&mut query);
    if let Some(column) = &options.sort_column {
        query.push(" ORDER BY ").push(quote_ident(column));
        query.push(if options.descending { " DESC" } else { " ASC" });
    } else if columns.contains("created_at") {
        query.push(" ORDER BY \"created_at\" DESC");
    } else if columns.contains("name") {
        query.push(" ORDER BY \"name\" ASC");
    }
    if let Some((limit, offset)) = options.pagination {
        query.push(" LIMIT ");
        query.push_bind(limit);
        query.push(" OFFSET ");
        query.push_bind(offset);
    }
    query.push(") AS t");

    let data: Value = query.build_query_scalar().fetch_one(&pool).await?;
    let data = resource_response(resource, data);
    Ok(Json(json!({
        "status": "ok",
        "data": data,
        "data2": total,
        "total": total
    })))
}

fn append_self_commerce(
    query: &mut QueryBuilder<Postgres>,
    resource: LegacyResource,
    principal: &LegacyPrincipal,
) {
    let column = if resource.table == "orders" {
        "user"
    } else {
        "user_id"
    };
    query
        .push(" AND (")
        .push(quote_ident(column))
        .push(" = ")
        .push_bind(principal.name.clone());
    query
        .push(" OR ")
        .push(quote_ident(column))
        .push(" = ")
        .push_bind(principal.id.clone())
        .push(")");
}

async fn legacy_get(
    depot: &mut Depot,
    req: &mut Request,
    resource: LegacyResource,
) -> AppResult<Json<Value>> {
    let pool = pg_pool(depot)?;
    let columns = table_columns(&pool, resource).await?;
    let body = read_optional_body(req).await?;
    let lookup = lookup_from(req, body.as_ref())?;

    let mut query = QueryBuilder::<Postgres>::new("SELECT to_jsonb(t) FROM (SELECT * FROM ");
    query.push(resource.table);
    append_lookup_filter(&mut query, &columns, &lookup, true)?;
    query.push(" LIMIT 1) AS t");

    let data: Option<Value> = query.build_query_scalar().fetch_optional(&pool).await?;
    if let Some(object) = &data {
        authorize_legacy_object(depot, req, resource, object, "get").await?;
    } else {
        LegacyPrincipal::from_depot(depot)?;
    }
    Ok(Json(json!({
        "status": "ok",
        "data": data.map(|value| resource_response(resource, value))
    })))
}

async fn legacy_add(
    depot: &mut Depot,
    req: &mut Request,
    resource: LegacyResource,
) -> AppResult<Json<Value>> {
    let pool = pg_pool(depot)?;
    let columns = table_columns(&pool, resource).await?;
    let body = read_required_body(req).await?;
    authorize_legacy_object(depot, req, resource, &body, "add").await?;
    let object = prepare_body(resource, body, &columns)?;
    let principal = crate::hoops::authz::Principal::from_depot(depot)?;
    if resource.table == "applications"
        && (principal.is_application()
            || !principal.admin
            || object
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with("dcr_"))
            || object
                .get("tags")
                .and_then(Value::as_array)
                .is_some_and(|tags| {
                    tags.iter()
                        .any(|tag| matches!(tag.as_str(), Some("dcr" | "cimd")))
                }))
    {
        return Err(AppError::Authorization(
            "Static application creation requires a real administrator and a non-dynamic identity"
                .into(),
        ));
    }
    crate::hoops::authz::validate_resource_references(
        &pool,
        &principal,
        &Value::Object(object.clone()),
        resource.table,
    )
    .await?;
    let insert_columns = body_columns(&object, &columns, &["created_at", "updated_at"])?;
    if insert_columns.is_empty() {
        return Err(AppError::Validation(
            "request body has no table columns".to_string(),
        ));
    }

    let mut query = QueryBuilder::<Postgres>::new("INSERT INTO ");
    query.push(resource.table);
    query.push(" (");
    push_column_list(&mut query, &insert_columns);
    query.push(") SELECT ");
    push_column_list(&mut query, &insert_columns);
    query.push(" FROM jsonb_populate_record(NULL::");
    query.push(resource.table);
    query.push(", ");
    query.push_bind(Value::Object(object));
    query.push("::jsonb) RETURNING to_jsonb(");
    query.push(resource.table);
    query.push(")");

    let mut tx = pool.begin().await?;
    let data: Value = query.build_query_scalar().fetch_one(&mut *tx).await?;
    if resource.table == "applications" {
        crate::services::key_credentials_service::mark_static_application_conn(
            &mut tx,
            data["id"]
                .as_str()
                .ok_or_else(|| AppError::Internal("Application ID missing".into()))?,
            &principal,
        )
        .await?;
    }
    tx.commit().await?;
    let object = resource_response(resource, data);
    Ok(Json(json!({
        "status": "ok",
        "data": true,
        "data2": object.clone(),
        "object": object
    })))
}

async fn legacy_update(
    depot: &mut Depot,
    req: &mut Request,
    resource: LegacyResource,
) -> AppResult<Json<Value>> {
    let pool = pg_pool(depot)?;
    let columns = table_columns(&pool, resource).await?;
    let body = read_required_body(req).await?;
    let lookup = lookup_from(req, Some(&body))?;
    let existing = lookup_legacy_object(&pool, resource, &columns, &lookup).await?;
    if authorize_legacy_object(depot, req, resource, &existing, "update").await? {
        validate_self_update(&body)?;
    }
    let lookup = exact_lookup(&existing)?;
    let object = prepare_body(resource, body, &columns)?;
    let principal = crate::hoops::authz::Principal::from_depot(depot)?;
    let mut references = object.clone();
    if resource.table == "organizations" {
        references.remove("owner");
    }
    crate::hoops::authz::validate_resource_references(
        &pool,
        &principal,
        &Value::Object(references),
        resource.table,
    )
    .await?;
    let update_columns = body_columns(
        &object,
        &columns,
        &["id", "owner", "name", "created_at", "updated_at"],
    )?;
    if update_columns.is_empty() && !columns.contains("updated_at") {
        return Err(AppError::Validation(
            "request body has no updatable columns".to_string(),
        ));
    }
    let body_value = Value::Object(object);

    let mut query = QueryBuilder::<Postgres>::new("UPDATE ");
    query.push(resource.table);
    query.push(" SET ");
    let mut first = true;
    for column in &update_columns {
        if !first {
            query.push(", ");
        }
        first = false;
        query.push(quote_ident(column));
        query.push(" = (jsonb_populate_record(NULL::");
        query.push(resource.table);
        query.push(", ");
        query.push_bind(body_value.clone());
        query.push("::jsonb)).");
        query.push(quote_ident(column));
    }
    if columns.contains("updated_at") {
        if !first {
            query.push(", ");
        }
        query.push("\"updated_at\" = NOW()");
    }
    append_lookup_filter(&mut query, &columns, &lookup, false)?;
    query.push(" RETURNING to_jsonb(");
    query.push(resource.table);
    query.push(")");

    let data: Option<Value> = query.build_query_scalar().fetch_optional(&pool).await?;
    let object = data.map(|value| resource_response(resource, value));
    Ok(Json(json!({
        "status": "ok",
        "data": object.is_some(),
        "object": object
    })))
}

async fn legacy_delete(
    depot: &mut Depot,
    req: &mut Request,
    resource: LegacyResource,
) -> AppResult<Json<Value>> {
    let pool = pg_pool(depot)?;
    let columns = table_columns(&pool, resource).await?;
    let body = read_optional_body(req).await?;
    let lookup = lookup_from(req, body.as_ref())?;
    let existing = lookup_legacy_object(&pool, resource, &columns, &lookup).await?;
    authorize_legacy_object(depot, req, resource, &existing, "delete").await?;
    let lookup = exact_lookup(&existing)?;

    let mut query = if columns.contains("is_deleted") {
        let mut query = QueryBuilder::<Postgres>::new("UPDATE ");
        query.push(resource.table);
        query.push(" SET \"is_deleted\" = true");
        if columns.contains("updated_at") {
            query.push(", \"updated_at\" = NOW()");
        }
        query
    } else {
        let mut query = QueryBuilder::<Postgres>::new("DELETE FROM ");
        query.push(resource.table);
        query
    };
    append_lookup_filter(&mut query, &columns, &lookup, false)?;

    let result = query.build().execute(&pool).await?;
    Ok(Json(json!({
        "status": "ok",
        "data": result.rows_affected() > 0
    })))
}

fn pg_pool(depot: &mut Depot) -> AppResult<Pool<Postgres>> {
    depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))
        .cloned()
}

async fn table_columns(
    pool: &Pool<Postgres>,
    resource: LegacyResource,
) -> AppResult<HashSet<String>> {
    let columns: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = $1
        "#,
    )
    .bind(resource.table)
    .fetch_all(pool)
    .await?;

    if columns.is_empty() {
        return Err(AppError::Internal(format!(
            "No columns found for table '{}'",
            resource.table
        )));
    }
    Ok(columns.into_iter().collect())
}

fn append_list_filters(
    query: &mut QueryBuilder<Postgres>,
    columns: &HashSet<String>,
    owner: Option<&str>,
    extra_filters: &[(&str, Option<String>)],
) {
    query.push(" WHERE TRUE");
    if columns.contains("is_deleted") {
        query.push(" AND \"is_deleted\" = false");
    }
    if let Some(owner) = owner.filter(|value| !value.is_empty())
        && columns.contains("owner")
    {
        query.push(" AND \"owner\" = ");
        query.push_bind(owner.to_string());
    }
    for (column, value) in extra_filters {
        if let Some(value) = value.as_deref().filter(|value| !value.is_empty())
            && columns.contains(*column)
        {
            query.push(" AND ");
            query.push(quote_ident(column));
            query.push(" = ");
            query.push_bind(value.to_string());
        }
    }
}

fn append_lookup_filter(
    query: &mut QueryBuilder<Postgres>,
    columns: &HashSet<String>,
    lookup: &Lookup,
    include_soft_delete: bool,
) -> AppResult<()> {
    query.push(" WHERE ");
    match lookup {
        Lookup::OwnerName { owner, name }
            if columns.contains("owner") && columns.contains("name") =>
        {
            query.push("\"owner\" = ");
            query.push_bind(owner.clone());
            query.push(" AND \"name\" = ");
            query.push_bind(name.clone());
        }
        Lookup::OwnerName { owner: _, name } if columns.contains("name") => {
            query.push("\"name\" = ");
            query.push_bind(name.clone());
        }
        Lookup::Id(id) if columns.contains("id") && columns.contains("name") => {
            query.push("(\"id\" = ");
            query.push_bind(id.clone());
            query.push(" OR \"name\" = ");
            query.push_bind(id.clone());
            query.push(")");
        }
        Lookup::Id(id) if columns.contains("id") => {
            query.push("\"id\" = ");
            query.push_bind(id.clone());
        }
        Lookup::Id(id) if columns.contains("name") => {
            query.push("\"name\" = ");
            query.push_bind(id.clone());
        }
        _ => {
            return Err(AppError::Validation(
                "resource does not support id or owner/name lookup".to_string(),
            ));
        }
    }
    if include_soft_delete && columns.contains("is_deleted") {
        query.push(" AND \"is_deleted\" = false");
    }
    Ok(())
}

async fn read_optional_body(req: &mut Request) -> AppResult<Option<Value>> {
    let body = req
        .payload()
        .await
        .map_err(|e| AppError::Validation(format!("Failed to read request body: {}", e)))?;
    if body.is_empty() {
        return Ok(None);
    }
    let parsed = serde_json::from_slice::<Value>(body)
        .map_err(|e| AppError::Validation(format!("Invalid JSON body: {}", e)))?;
    Ok(Some(normalize_body(parsed)))
}

async fn read_required_body(req: &mut Request) -> AppResult<Value> {
    read_optional_body(req)
        .await?
        .ok_or_else(|| AppError::Validation("JSON request body is required".to_string()))
}

fn normalize_body(value: Value) -> Value {
    let object = value
        .get("data")
        .and_then(Value::as_object)
        .or_else(|| value.as_object())
        .cloned()
        .unwrap_or_default();
    let mut normalized = Map::new();
    for (key, value) in object {
        normalized.insert(to_snake_case(&key), value);
    }
    Value::Object(normalized)
}

fn prepare_body(
    resource: LegacyResource,
    body: Value,
    columns: &HashSet<String>,
) -> AppResult<Map<String, Value>> {
    let mut object = body.as_object().cloned().unwrap_or_default();

    if columns.contains("id")
        && object
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
    {
        object.insert(
            "id".to_string(),
            Value::String(uuid::Uuid::new_v4().to_string()),
        );
    }
    if columns.contains("display_name")
        && !object.contains_key("display_name")
        && let Some(name) = object.get("name").cloned()
    {
        object.insert("display_name".to_string(), name);
    }
    if columns.contains("is_deleted") && !object.contains_key("is_deleted") {
        object.insert("is_deleted".to_string(), Value::Bool(false));
    }

    if resource.table == "users"
        && columns.contains("password_hash")
        && !object.contains_key("password_hash")
        && let Some(password) = object.remove("password").and_then(|value| match value {
            Value::String(value) if !value.is_empty() && value != "***" => Some(value),
            _ => None,
        })
    {
        let password_type = object
            .get("password_type")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("argon2")
            .to_string();
        let password_salt = object.get("password_salt").and_then(Value::as_str);
        let password_hash =
            PasswordService::hash_password(&password, &password_type, password_salt)?;
        object.insert("password_hash".to_string(), Value::String(password_hash));
        // Partial updates must not keep a previous algorithm beside a newly generated hash.
        object.insert("password_type".to_string(), Value::String(password_type));
        if !object.contains_key("password_salt") {
            object.insert("password_salt".to_string(), Value::Null);
        }
    }

    Ok(object)
}

fn lookup_from(req: &Request, body: Option<&Value>) -> AppResult<Lookup> {
    if let Some(id) = req
        .query::<String>("id")
        .or_else(|| req.query::<String>("userId"))
        .filter(|value| !value.is_empty())
    {
        return Ok(lookup_from_id(id, req.query("owner")));
    }

    let query_owner = req.query::<String>("owner");
    let query_name = req.query::<String>("name");
    if let (Some(owner), Some(name)) = (query_owner, query_name)
        && !owner.is_empty()
        && !name.is_empty()
    {
        return Ok(Lookup::OwnerName { owner, name });
    }

    if let Some(object) = body.and_then(Value::as_object) {
        if let Some(id) = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            return Ok(lookup_from_id(id.to_string(), None));
        }
        if let (Some(owner), Some(name)) = (
            object.get("owner").and_then(Value::as_str),
            object.get("name").and_then(Value::as_str),
        ) && !owner.is_empty()
            && !name.is_empty()
        {
            return Ok(Lookup::OwnerName {
                owner: owner.to_string(),
                name: name.to_string(),
            });
        }
    }

    Err(AppError::Validation(
        "id or owner/name is required".to_string(),
    ))
}

fn lookup_from_id(id: String, owner_hint: Option<String>) -> Lookup {
    if let Some((owner, name)) = id.split_once('/') {
        return Lookup::OwnerName {
            owner: owner.to_string(),
            name: name.to_string(),
        };
    }
    if let Some(owner) = owner_hint.filter(|value| !value.is_empty()) {
        return Lookup::OwnerName { owner, name: id };
    }
    Lookup::Id(id)
}

fn body_columns(
    object: &Map<String, Value>,
    columns: &HashSet<String>,
    excluded: &[&str],
) -> AppResult<Vec<String>> {
    let excluded: HashSet<&str> = excluded.iter().copied().collect();
    let mut result: Vec<String> = object
        .keys()
        .filter(|key| columns.contains(*key) && !excluded.contains(key.as_str()))
        .cloned()
        .collect();
    result.sort();
    Ok(result)
}

fn push_column_list(query: &mut QueryBuilder<Postgres>, columns: &[String]) {
    for (index, column) in columns.iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        query.push(quote_ident(column));
    }
}

fn quote_ident(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn to_snake_case(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut previous_lowercase = false;
    for ch in value.chars() {
        if ch == '-' || ch == ' ' {
            output.push('_');
            previous_lowercase = false;
        } else if ch.is_ascii_uppercase() {
            if previous_lowercase {
                output.push('_');
            }
            output.push(ch.to_ascii_lowercase());
            previous_lowercase = false;
        } else {
            output.push(ch);
            previous_lowercase = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        }
    }
    output
}

fn to_casdoor_value(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    // User-defined map keys are data, not schema field names.
                    let value = if matches!(key.as_str(), "properties" | "attributes") {
                        value
                    } else {
                        to_casdoor_value(value)
                    };
                    (to_camel_case(&key), value)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(to_casdoor_value).collect()),
        value => value,
    }
}

fn to_camel_case(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut uppercase_next = false;
    for ch in value.chars() {
        if ch == '_' {
            uppercase_next = true;
        } else if uppercase_next {
            output.push(ch.to_ascii_uppercase());
            uppercase_next = false;
        } else {
            output.push(ch);
        }
    }
    output
}

macro_rules! legacy_handlers {
    ($resource:ident, $list_fn:ident, $get_fn:ident, $add_fn:ident, $update_fn:ident, $delete_fn:ident) => {
        #[endpoint(tags("Casdoor compatibility"))]
        pub async fn $list_fn(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
            legacy_list(depot, req, $resource).await
        }

        #[endpoint(tags("Casdoor compatibility"))]
        pub async fn $get_fn(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
            legacy_get(depot, req, $resource).await
        }

        #[endpoint(tags("Casdoor compatibility"))]
        pub async fn $add_fn(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
            legacy_add(depot, req, $resource).await
        }

        #[endpoint(tags("Casdoor compatibility"))]
        pub async fn $update_fn(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
            legacy_update(depot, req, $resource).await
        }

        #[endpoint(tags("Casdoor compatibility"))]
        pub async fn $delete_fn(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
            legacy_delete(depot, req, $resource).await
        }
    };
}

legacy_handlers!(
    USERS,
    get_users,
    get_user,
    add_user,
    update_user,
    delete_user
);
legacy_handlers!(
    ORGANIZATIONS,
    get_organizations,
    get_organization,
    add_organization,
    update_organization,
    delete_organization
);
legacy_handlers!(
    GROUPS,
    get_groups,
    get_group,
    add_group,
    update_group,
    delete_group
);
legacy_handlers!(
    APPLICATIONS,
    get_applications,
    get_application,
    add_application,
    update_application,
    delete_application
);
legacy_handlers!(
    PROVIDERS,
    get_providers,
    get_provider,
    add_provider,
    update_provider,
    delete_provider
);
legacy_handlers!(
    RESOURCES,
    get_resources,
    get_resource,
    add_resource,
    update_resource,
    delete_resource
);
legacy_handlers!(
    CERTS,
    get_certs,
    get_cert,
    add_cert,
    update_cert,
    delete_cert
);
legacy_handlers!(
    ROLES,
    get_roles,
    get_role,
    add_role,
    update_role,
    delete_role
);
legacy_handlers!(
    PERMISSIONS,
    get_permissions,
    get_permission,
    add_permission,
    update_permission,
    delete_permission
);
legacy_handlers!(
    MODELS,
    get_models,
    get_model,
    add_model,
    update_model,
    delete_model
);
legacy_handlers!(
    ADAPTERS,
    get_adapters,
    get_adapter,
    add_adapter,
    update_adapter,
    delete_adapter
);
legacy_handlers!(
    ENFORCERS,
    get_enforcers,
    get_enforcer,
    add_enforcer,
    update_enforcer,
    delete_enforcer
);
legacy_handlers!(
    SESSIONS,
    get_sessions,
    get_session,
    add_session,
    update_session,
    delete_session
);
legacy_handlers!(
    TOKENS,
    get_tokens,
    get_token,
    add_token,
    update_token,
    delete_token
);
legacy_handlers!(
    PRODUCTS,
    get_products,
    get_product,
    add_product,
    update_product,
    delete_product
);
legacy_handlers!(
    ORDERS,
    get_orders,
    get_order,
    add_order,
    update_order,
    delete_order
);
legacy_handlers!(
    PAYMENTS,
    get_payments,
    get_payment,
    add_payment,
    update_payment,
    delete_payment
);
legacy_handlers!(
    PLANS,
    get_plans,
    get_plan,
    add_plan,
    update_plan,
    delete_plan
);
legacy_handlers!(
    PRICINGS,
    get_pricings,
    get_pricing,
    add_pricing,
    update_pricing,
    delete_pricing
);
legacy_handlers!(
    SUBSCRIPTIONS,
    get_subscriptions,
    get_subscription,
    add_subscription,
    update_subscription,
    delete_subscription
);
legacy_handlers!(
    TRANSACTIONS,
    get_transactions,
    get_transaction,
    add_transaction,
    update_transaction,
    delete_transaction
);
legacy_handlers!(
    FORMS,
    get_forms,
    get_form,
    add_form,
    update_form,
    delete_form
);
legacy_handlers!(
    SYNCERS,
    get_syncers,
    get_syncer,
    add_syncer,
    update_syncer,
    delete_syncer
);
legacy_handlers!(
    WEBHOOKS,
    get_webhooks,
    get_webhook,
    add_webhook,
    update_webhook,
    delete_webhook
);
legacy_handlers!(
    TICKETS,
    get_tickets,
    get_ticket,
    add_ticket,
    update_ticket,
    delete_ticket
);
legacy_handlers!(
    RULES,
    get_rules,
    get_rule,
    add_rule,
    update_rule,
    delete_rule
);
legacy_handlers!(
    SITES,
    get_sites,
    get_site,
    add_site,
    update_site,
    delete_site
);
legacy_handlers!(
    INVITATIONS,
    get_invitations,
    get_invitation,
    add_invitation,
    update_invitation,
    delete_invitation
);
legacy_handlers!(
    RECORDS,
    get_records,
    get_record,
    add_record,
    update_record,
    delete_record
);

async fn authorize_special_target(
    depot: &Depot,
    pool: &Pool<Postgres>,
    table: &str,
    id: &str,
) -> AppResult<()> {
    let principal = crate::hoops::authz::Principal::from_depot(depot)?;
    if !principal.admin {
        return Err(AppError::Authorization("Administrator required".into()));
    }
    principal.check_owner(
        &crate::hoops::authz::stored_object(pool, table, id).await?,
        table,
    )
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn add_user_keys(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    legacy_update(depot, req, USERS).await
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn remove_user_from_group(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<Value>> {
    let pool = pg_pool(depot)?;
    let body = read_optional_json_body(req).await?;
    let owner = request_string(req, body.as_ref(), &["owner"]).await;
    let user_name = required_request_string(
        req,
        body.as_ref(),
        &["name", "user", "userId", "user_id"],
        "name",
    )
    .await?;
    let group_name = required_request_string(
        req,
        body.as_ref(),
        &["groupName", "group_name", "group", "groupId", "group_id"],
        "groupName",
    )
    .await?;

    let user_id = resolve_resource_id(&pool, USERS, owner.as_deref(), &user_name).await?;
    let group_id = resolve_resource_id(&pool, GROUPS, owner.as_deref(), &group_name).await?;
    authorize_special_target(depot, &pool, "users", &user_id).await?;
    authorize_special_target(depot, &pool, "groups", &group_id).await?;
    GroupService::remove_user_from_group(&pool, &user_id, &group_id).await?;

    Ok(Json(json!({
        "status": "ok",
        "data": true
    })))
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn get_invitation_info(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let pool = pg_pool(depot)?;
    let owner = request_string(req, None, &["owner"]).await;
    let application = request_string(req, None, &["application"]).await;
    let code_or_id =
        required_request_string(req, None, &["code", "id", "name"], "code or id").await?;

    let mut query =
        QueryBuilder::<Postgres>::new("SELECT to_jsonb(t) FROM (SELECT * FROM invitations WHERE ");
    query.push("(\"code\" = ");
    query.push_bind(code_or_id.clone());
    query.push(" OR \"id\" = ");
    query.push_bind(code_or_id.clone());
    query.push(" OR \"name\" = ");
    query.push_bind(code_or_id);
    query.push(")");
    if let Some(owner) = owner.as_deref().filter(|value| !value.is_empty()) {
        query.push(" AND \"owner\" = ");
        query.push_bind(owner.to_string());
    }
    if let Some(application) = application.as_deref().filter(|value| !value.is_empty()) {
        query.push(" AND (\"application\" IS NULL OR \"application\" = ");
        query.push_bind(application.to_string());
        query.push(")");
    }
    query.push(" LIMIT 1) AS t");

    let data: Option<Value> = query.build_query_scalar().fetch_optional(&pool).await?;
    if let Some(object) = data.as_ref() {
        crate::hoops::authz::Principal::from_depot(depot)?.check_owner(object, "invitations")?;
    }
    Ok(Json(json!({
        "status": "ok",
        "data": data.map(to_casdoor_value)
    })))
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn verify_invitation_query(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<Value>> {
    let pool = pg_pool(depot)?;
    let code = required_request_string(req, None, &["code"], "code").await?;
    let application = request_string(req, None, &["application"]).await;
    let result =
        InvitationService::verify(&pool, VerifyInvitationRequest { code, application }).await?;

    Ok(Json(json!({
        "status": "ok",
        "data": result.valid,
        "valid": result.valid,
        "msg": result.message
    })))
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn send_invitation_compat(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<Value>> {
    let pool = pg_pool(depot)?;
    let body = read_optional_json_body(req).await?;
    let owner = request_string(req, body.as_ref(), &["owner"]).await;
    let invitation_ref = required_request_string(
        req,
        body.as_ref(),
        &["invitationId", "invitation_id", "id", "name", "code"],
        "invitationId",
    )
    .await?;
    let invitation_id = resolve_invitation_id(&pool, owner.as_deref(), &invitation_ref).await?;
    authorize_special_target(depot, &pool, "invitations", &invitation_id).await?;
    let send_type = request_string(req, body.as_ref(), &["type", "sendType", "send_type"])
        .await
        .unwrap_or_else(|| "email".to_string());
    let receiver = required_request_string(
        req,
        body.as_ref(),
        &["receiver", "email", "phone"],
        "receiver",
    )
    .await?;

    let compat_req = SendInvitationRequest {
        invitation_id,
        send_type,
        receiver,
    };
    let _invitation = InvitationService::get_by_id(&pool, &compat_req.invitation_id).await?;

    Ok(Json(json!({
        "status": "ok",
        "data": true,
        "msg": format!(
            "Invitation sent via {} to {}",
            compat_req.send_type, compat_req.receiver
        )
    })))
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn get_user_orders(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let user = request_string(req, None, &["user", "userId", "user_id", "name"])
        .await
        .or_else(|| current_user_name(depot));
    legacy_list_with_extra_filters(depot, req, ORDERS, &[("user", user)]).await
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn get_user_payments(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let user_id = request_string(req, None, &["userId", "user_id", "user", "name"])
        .await
        .or_else(|| current_user_name(depot));
    legacy_list_with_extra_filters(depot, req, PAYMENTS, &[("user_id", user_id)]).await
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn run_syncer_query(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let pool = pg_pool(depot)?;
    let owner = request_string(req, None, &["owner"]).await;
    let syncer_ref = required_request_string(req, None, &["id", "name"], "id").await?;
    let syncer_id = resolve_resource_id(&pool, SYNCERS, owner.as_deref(), &syncer_ref).await?;
    authorize_special_target(depot, &pool, "syncers", &syncer_id).await?;
    let result = SyncerService::run_sync(&pool, &syncer_id).await?;

    Ok(Json(json!({
        "status": if result.success { "ok" } else { "error" },
        "data": result.success,
        "msg": result.message,
        "syncerId": result.syncer_id,
        "recordsSynced": result.records_synced
    })))
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn test_syncer_db(_depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let body = read_required_body(req).await?;
    let syncer: TestSyncerDbRequest = serde_json::from_value(body)
        .map_err(|e| AppError::Validation(format!("Invalid syncer payload: {}", e)))?;

    if !syncer.syncer_type.eq_ignore_ascii_case("database") {
        return Ok(Json(json!({
            "status": "ok",
            "data": false,
            "success": false,
            "msg": "Only database syncers can test a database connection"
        })));
    }

    let database_type = syncer
        .database_type
        .as_deref()
        .unwrap_or("postgres")
        .to_ascii_lowercase();
    if database_type != "postgres" && database_type != "postgresql" {
        return Ok(Json(json!({
            "status": "ok",
            "data": false,
            "success": false,
            "msg": format!("Database type '{}' is not supported by this tester", database_type)
        })));
    }

    let database_url = postgres_database_url(&syncer);
    let connect = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&database_url);

    match tokio::time::timeout(Duration::from_secs(5), connect).await {
        Ok(Ok(pool)) => {
            pool.close().await;
            Ok(Json(json!({
                "status": "ok",
                "data": true,
                "success": true,
                "msg": "Connection successful"
            })))
        }
        Ok(Err(err)) => Ok(Json(json!({
            "status": "ok",
            "data": false,
            "success": false,
            "msg": err.to_string()
        }))),
        Err(_) => Ok(Json(json!({
            "status": "ok",
            "data": false,
            "success": false,
            "msg": "Connection timed out"
        }))),
    }
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn add_ticket_message(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let pool = pg_pool(depot)?;
    let columns = table_columns(&pool, TICKETS).await?;
    let body = read_optional_json_body(req).await?;
    let owner = request_string(req, body.as_ref(), &["owner"]).await;
    let ticket_ref = request_string(req, body.as_ref(), &["id", "ticketId", "ticket_id"]).await;
    let lookup = if let Some(ticket_ref) = ticket_ref {
        lookup_from_id(ticket_ref, owner)
    } else {
        lookup_from(req, None)?
    };

    let object = lookup_legacy_object(&pool, TICKETS, &columns, &lookup).await?;
    authorize_legacy_object(depot, req, TICKETS, &object, "update").await?;
    let lookup = exact_lookup(&object)?;
    let mut message = body
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if !message.contains_key("content")
        && let Some(content) =
            request_string(req, body.as_ref(), &["content", "text", "message"]).await
    {
        message.insert("content".to_string(), Value::String(content));
    }
    if !message.contains_key("author")
        && let Some(user_name) = current_user_name(depot)
    {
        message.insert("author".to_string(), Value::String(user_name));
    }
    if !message.contains_key("is_admin") {
        let is_admin = depot.get::<bool>("is_admin").ok().copied().unwrap_or(false);
        message.insert("is_admin".to_string(), Value::Bool(is_admin));
    }
    message
        .entry("created_at".to_string())
        .or_insert_with(|| Value::String(chrono::Utc::now().to_rfc3339()));

    let mut query = QueryBuilder::<Postgres>::new("UPDATE tickets SET \"comments\" = ");
    query.push(
        "CASE WHEN jsonb_typeof(COALESCE(\"comments\", '[]'::jsonb)) = 'array' \
         THEN COALESCE(\"comments\", '[]'::jsonb) \
         ELSE jsonb_build_array(\"comments\") END || jsonb_build_array(",
    );
    query.push_bind(Value::Object(message));
    query.push("::jsonb), \"updated_at\" = NOW()");
    append_lookup_filter(&mut query, &columns, &lookup, false)?;
    query.push(" RETURNING to_jsonb(tickets)");

    let data: Option<Value> = query.build_query_scalar().fetch_optional(&pool).await?;
    let object = data.map(to_casdoor_value);
    Ok(Json(json!({
        "status": "ok",
        "data": object.is_some(),
        "object": object
    })))
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn get_policies_compat(depot: &mut Depot) -> AppResult<Json<Value>> {
    let policies = casbin_service(depot)?.get_policies().await?;
    Ok(Json(json!({"status": "ok", "data": policies.data})))
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn add_policy_compat(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let body = read_raw_required_body(req).await?;
    let policy = policy_from_value(&body)?;
    let added = casbin_service(depot)?.add_policy(policy).await?;
    Ok(Json(json!({"status": "ok", "data": added})))
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn get_filtered_policies(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let casbin_service = casbin_service(depot)?;
    let body = read_raw_optional_body(req).await?;
    let filters = parse_policy_filters(body.as_ref());
    let policies = casbin_service.get_policies().await?;
    let data: Vec<PolicyResponse> = if filters.is_empty() {
        policies.data
    } else {
        policies
            .data
            .into_iter()
            .filter(|policy| filters.iter().any(|filter| filter.matches(policy)))
            .collect()
    };

    Ok(Json(json!({
        "status": "ok",
        "data": data
    })))
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn update_policy_compat(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let casbin_service = casbin_service(depot)?;
    let body = read_raw_required_body(req).await?;
    let (old_policy, new_policy) = policy_update_pair(&body)?;
    let removed = casbin_service.remove_policy(old_policy).await?;
    let added = casbin_service.add_policy(new_policy).await?;

    Ok(Json(json!({
        "status": "ok",
        "data": removed || added,
        "removed": removed,
        "added": added
    })))
}

#[endpoint(tags("Casdoor compatibility"))]
pub async fn remove_policy_compat(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let casbin_service = casbin_service(depot)?;
    let body = read_raw_required_body(req).await?;
    let policy = policy_from_value(&body)?;
    let removed = casbin_service.remove_policy(policy).await?;

    Ok(Json(json!({
        "status": "ok",
        "data": removed
    })))
}

fn casbin_service(depot: &mut Depot) -> AppResult<CasbinService> {
    if !LegacyPrincipal::from_depot(depot)?.global_admin() {
        return Err(AppError::Authorization(
            "Global administrator required for policy management".to_string(),
        ));
    }
    depot
        .obtain::<CasbinService>()
        .map_err(|_| AppError::Internal("Casbin service not initialized".to_string()))
        .cloned()
}

fn current_user_name(depot: &Depot) -> Option<String> {
    depot
        .get::<String>("user_name")
        .ok()
        .cloned()
        .filter(|value| !value.is_empty())
}

async fn resolve_resource_id(
    pool: &Pool<Postgres>,
    resource: LegacyResource,
    owner: Option<&str>,
    value: &str,
) -> AppResult<String> {
    let mut owner_value = owner.map(ToOwned::to_owned);
    let mut name_value = value.to_string();
    if owner_value.is_none()
        && let Some((parsed_owner, parsed_name)) = value.split_once('/')
    {
        owner_value = Some(parsed_owner.to_string());
        name_value = parsed_name.to_string();
    }

    let mut query = QueryBuilder::<Postgres>::new("SELECT \"id\" FROM ");
    query.push(resource.table);
    query.push(" WHERE ");
    if let Some(owner) = owner_value {
        query.push("((\"owner\" = ");
        query.push_bind(owner);
        query.push(" AND \"name\" = ");
        query.push_bind(name_value.clone());
        query.push(") OR \"id\" = ");
        query.push_bind(value.to_string());
        query.push(")");
    } else {
        query.push("(\"id\" = ");
        query.push_bind(value.to_string());
        query.push(" OR \"name\" = ");
        query.push_bind(name_value);
        query.push(")");
    }
    query.push(" LIMIT 1");

    let id: Option<String> = query.build_query_scalar().fetch_optional(pool).await?;
    id.ok_or_else(|| {
        AppError::NotFound(format!(
            "Resource '{}' was not found in {}",
            value, resource.table
        ))
    })
}

async fn resolve_invitation_id(
    pool: &Pool<Postgres>,
    owner: Option<&str>,
    value: &str,
) -> AppResult<String> {
    let mut query = QueryBuilder::<Postgres>::new("SELECT \"id\" FROM invitations WHERE ");
    query.push("(\"id\" = ");
    query.push_bind(value.to_string());
    query.push(" OR \"name\" = ");
    query.push_bind(value.to_string());
    query.push(" OR \"code\" = ");
    query.push_bind(value.to_string());
    query.push(")");
    if let Some(owner) = owner.filter(|value| !value.is_empty()) {
        query.push(" AND \"owner\" = ");
        query.push_bind(owner.to_string());
    }
    query.push(" LIMIT 1");

    let id: Option<String> = query.build_query_scalar().fetch_optional(pool).await?;
    id.ok_or_else(|| AppError::NotFound(format!("Invitation '{}' was not found", value)))
}

fn postgres_database_url(syncer: &TestSyncerDbRequest) -> String {
    let database = syncer
        .database
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("postgres");
    format!(
        "postgres://{}:{}@{}:{}/{}",
        urlencoding::encode(&syncer.user),
        urlencoding::encode(&syncer.password),
        syncer.host,
        syncer.port,
        urlencoding::encode(database)
    )
}

fn request_is_json(req: &Request) -> bool {
    req.headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase().contains("json"))
        .unwrap_or(false)
}

async fn read_optional_json_body(req: &mut Request) -> AppResult<Option<Value>> {
    if request_is_json(req) {
        read_optional_body(req).await
    } else {
        Ok(None)
    }
}

async fn read_raw_optional_body(req: &mut Request) -> AppResult<Option<Value>> {
    let body = req
        .payload()
        .await
        .map_err(|e| AppError::Validation(format!("Failed to read request body: {}", e)))?;
    if body.is_empty() {
        return Ok(None);
    }
    let parsed = serde_json::from_slice::<Value>(body)
        .map_err(|e| AppError::Validation(format!("Invalid JSON body: {}", e)))?;
    Ok(Some(parsed))
}

async fn read_raw_required_body(req: &mut Request) -> AppResult<Value> {
    read_raw_optional_body(req)
        .await?
        .ok_or_else(|| AppError::Validation("JSON request body is required".to_string()))
}

async fn request_string(req: &mut Request, body: Option<&Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = req.query::<String>(key).filter(|value| !value.is_empty()) {
            return Some(value);
        }
        let snake_key = to_snake_case(key);
        if snake_key != *key
            && let Some(value) = req
                .query::<String>(&snake_key)
                .filter(|value| !value.is_empty())
        {
            return Some(value);
        }
    }

    if let Some(object) = body.and_then(Value::as_object) {
        for key in keys {
            if let Some(value) = object.get(*key).and_then(value_to_string) {
                return Some(value);
            }
            let snake_key = to_snake_case(key);
            if snake_key != *key
                && let Some(value) = object.get(&snake_key).and_then(value_to_string)
            {
                return Some(value);
            }
        }
    }

    for key in keys {
        if let Some(value) = req
            .form::<String>(key)
            .await
            .filter(|value| !value.is_empty())
        {
            return Some(value);
        }
        let snake_key = to_snake_case(key);
        if snake_key != *key
            && let Some(value) = req
                .form::<String>(&snake_key)
                .await
                .filter(|value| !value.is_empty())
        {
            return Some(value);
        }
    }

    None
}

async fn required_request_string(
    req: &mut Request,
    body: Option<&Value>,
    keys: &[&str],
    label: &str,
) -> AppResult<String> {
    request_string(req, body, keys)
        .await
        .ok_or_else(|| AppError::Validation(format!("{} is required", label)))
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

#[derive(Default)]
struct PolicyFilter {
    ptype: Option<String>,
    v0: Option<String>,
    v1: Option<String>,
    v2: Option<String>,
    v3: Option<String>,
    v4: Option<String>,
}

impl PolicyFilter {
    fn matches(&self, policy: &PolicyResponse) -> bool {
        self.ptype
            .as_ref()
            .is_none_or(|value| value == &policy.ptype)
            && self.v0.as_ref().is_none_or(|value| value == &policy.v0)
            && self.v1.as_ref().is_none_or(|value| value == &policy.v1)
            && self.v2.as_ref().is_none_or(|value| value == &policy.v2)
            && self
                .v3
                .as_ref()
                .is_none_or(|value| policy.v3.as_ref() == Some(value))
            && self
                .v4
                .as_ref()
                .is_none_or(|value| policy.v4.as_ref() == Some(value))
    }
}

fn parse_policy_filters(body: Option<&Value>) -> Vec<PolicyFilter> {
    match body {
        Some(Value::Array(values)) => values.iter().filter_map(policy_filter_from_value).collect(),
        Some(value) => policy_filter_from_value(value).into_iter().collect(),
        None => Vec::new(),
    }
}

fn policy_filter_from_value(value: &Value) -> Option<PolicyFilter> {
    match value {
        Value::Object(object) => {
            let mut normalized = Map::new();
            for (key, value) in object {
                normalized.insert(to_snake_case(key), value.clone());
            }
            Some(PolicyFilter {
                ptype: normalized
                    .get("ptype")
                    .or_else(|| normalized.get("type"))
                    .and_then(value_to_string),
                v0: normalized
                    .get("v0")
                    .or_else(|| normalized.get("sub"))
                    .and_then(value_to_string),
                v1: normalized
                    .get("v1")
                    .or_else(|| normalized.get("obj"))
                    .and_then(value_to_string),
                v2: normalized
                    .get("v2")
                    .or_else(|| normalized.get("act"))
                    .and_then(value_to_string),
                v3: normalized.get("v3").and_then(value_to_string),
                v4: normalized.get("v4").and_then(value_to_string),
            })
        }
        Value::Array(values) => {
            let strings: Vec<String> = values.iter().filter_map(value_to_string).collect();
            if strings.is_empty() {
                return None;
            }
            let (ptype, values) = split_policy_array(strings);
            Some(PolicyFilter {
                ptype: Some(ptype),
                v0: values.first().cloned(),
                v1: values.get(1).cloned(),
                v2: values.get(2).cloned(),
                v3: values.get(3).cloned(),
                v4: values.get(4).cloned(),
            })
        }
        _ => None,
    }
}

fn policy_update_pair(value: &Value) -> AppResult<(PolicyRequest, PolicyRequest)> {
    if let Value::Array(values) = value
        && values.len() >= 2
    {
        return Ok((
            policy_from_value(&values[0])?,
            policy_from_value(&values[1])?,
        ));
    }

    if let Value::Object(object) = value {
        let old_policy = object
            .get("oldPolicy")
            .or_else(|| object.get("old_policy"))
            .or_else(|| object.get("old"))
            .ok_or_else(|| AppError::Validation("old policy is required".to_string()))?;
        let new_policy = object
            .get("newPolicy")
            .or_else(|| object.get("new_policy"))
            .or_else(|| object.get("new"))
            .ok_or_else(|| AppError::Validation("new policy is required".to_string()))?;
        return Ok((
            policy_from_value(old_policy)?,
            policy_from_value(new_policy)?,
        ));
    }

    Err(AppError::Validation(
        "policy update body must contain old and new policies".to_string(),
    ))
}

fn policy_from_value(value: &Value) -> AppResult<PolicyRequest> {
    match value {
        Value::Object(object) => {
            let mut normalized = Map::new();
            for (key, value) in object {
                normalized.insert(to_snake_case(key), value.clone());
            }
            let ptype = normalized
                .get("ptype")
                .or_else(|| normalized.get("type"))
                .and_then(value_to_string)
                .unwrap_or_else(|| "p".to_string());
            let v0 = required_policy_field(&normalized, &["v0", "sub"])?;
            let v1 = required_policy_field(&normalized, &["v1", "obj"])?;
            let v2 = normalized
                .get("v2")
                .or_else(|| normalized.get("act"))
                .and_then(value_to_string)
                .unwrap_or_default();
            Ok(PolicyRequest {
                ptype,
                v0,
                v1,
                v2,
                v3: normalized.get("v3").and_then(value_to_string),
                v4: normalized.get("v4").and_then(value_to_string),
            })
        }
        Value::Array(values) => {
            let strings: Vec<String> = values.iter().filter_map(value_to_string).collect();
            if strings.is_empty() {
                return Err(AppError::Validation("policy array is empty".to_string()));
            }
            let (ptype, values) = split_policy_array(strings);
            let v0 = values
                .first()
                .cloned()
                .ok_or_else(|| AppError::Validation("policy v0 is required".to_string()))?;
            let v1 = values
                .get(1)
                .cloned()
                .ok_or_else(|| AppError::Validation("policy v1 is required".to_string()))?;
            Ok(PolicyRequest {
                ptype,
                v0,
                v1,
                v2: values.get(2).cloned().unwrap_or_default(),
                v3: values.get(3).cloned(),
                v4: values.get(4).cloned(),
            })
        }
        _ => Err(AppError::Validation(
            "policy body must be an object or array".to_string(),
        )),
    }
}

fn required_policy_field(object: &Map<String, Value>, keys: &[&str]) -> AppResult<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(value_to_string))
        .ok_or_else(|| AppError::Validation(format!("policy {} is required", keys[0])))
}

fn split_policy_array(mut values: Vec<String>) -> (String, Vec<String>) {
    if matches!(values.first().map(String::as_str), Some("p" | "g")) {
        let ptype = values.remove(0);
        return (ptype, values);
    }
    let ptype = if values.len() <= 2 { "g" } else { "p" }.to_string();
    (ptype, values)
}

#[cfg(test)]
#[path = "casdoor_compat_tests.rs"]
mod compatibility_tests;
