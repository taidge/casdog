use salvo::oapi::endpoint;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::hoops::auth::validate_session_claims;
use crate::hoops::authz::{Principal, validate_references};
use crate::services::TokenService;

#[derive(Debug, Deserialize)]
struct McpRequest {
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[endpoint(tags("MCP"), summary = "Handle MCP JSON-RPC request")]
pub async fn handle_mcp(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let body = req
        .payload()
        .await
        .map_err(|e| AppError::Validation(format!("Failed to read MCP body: {}", e)))?;
    let request: McpRequest = serde_json::from_slice(body)
        .map_err(|e| AppError::Validation(format!("Invalid MCP JSON-RPC body: {}", e)))?;

    let id = request.id.clone().unwrap_or(Value::Null);
    let result = match request.method.as_str() {
        "initialize" => mcp_ok(
            id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": true}},
                "serverInfo": {"name": "Casdog MCP Server", "version": env!("CARGO_PKG_VERSION")}
            }),
        ),
        "notifications/initialized" => mcp_ok(Value::Null, Value::Null),
        "ping" => mcp_ok(id, json!({})),
        "tools/list" => mcp_ok(id, json!({ "tools": mcp_tools() })),
        "tools/call" => handle_tool_call(depot, req, id, request.params).await?,
        method => mcp_error(
            id,
            -32601,
            "Method not found",
            Some(json!(format!("Method '{}' not found", method))),
        ),
    };

    Ok(Json(result))
}

async fn handle_tool_call(
    depot: &mut Depot,
    req: &Request,
    id: Value,
    params: Option<Value>,
) -> AppResult<Value> {
    let Some(token) = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return Ok(mcp_error(id, -32001, "insufficient_scope", None));
    };
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".into()))?
        .clone();
    let claims = match validate_session_claims(&pool, token).await {
        Ok(claims) => claims,
        Err(_) => return Ok(mcp_error(id, -32001, "insufficient_scope", None)),
    };
    let principal = Principal {
        id: claims.sub,
        owner: claims.owner,
        name: claims.name,
        admin: claims.is_admin,
    };
    if !principal.admin {
        return Ok(mcp_error(id, -32001, "insufficient_scope", None));
    }
    let params = params.unwrap_or_else(|| json!({}));
    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("MCP tool name is required".to_string()))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let text = match tool_name {
        "get_applications" => {
            let owner = arguments
                .get("owner")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::Validation("owner is required".to_string()))?;
            if !principal.global_admin() && owner != principal.owner {
                return Err(AppError::Authorization(
                    "Cannot access another tenant".into(),
                ));
            }
            let data: Value = sqlx::query_scalar(
                r#"
                SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb)
                FROM (
                    SELECT * FROM applications
                    WHERE owner = $1 AND is_deleted = false
                    ORDER BY name ASC
                ) AS t
                "#,
            )
            .bind(owner)
            .fetch_one(&pool)
            .await?;
            serde_json::to_string_pretty(&camelize_value(data)).unwrap_or_else(|_| "[]".into())
        }
        "get_application" => {
            let id_arg = arguments
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::Validation("id is required".to_string()))?;
            let data = authorized_application(&pool, &principal, id_arg).await?;
            serde_json::to_string_pretty(&camelize_value(data)).unwrap_or_else(|_| "null".into())
        }
        "add_application" => {
            let app = arguments
                .get("application")
                .and_then(Value::as_object)
                .ok_or_else(|| AppError::Validation("application is required".to_string()))?;
            let normalized = Value::Object(normalized_object(app));
            validate_references(&pool, &principal, &normalized).await?;
            if !principal.global_admin()
                && normalized.get("owner").and_then(Value::as_str) != Some(principal.owner.as_str())
            {
                return Err(AppError::Authorization(
                    "Cannot create for another tenant".into(),
                ));
            }
            add_application(&pool, app).await?;
            "Successfully added application".to_string()
        }
        "update_application" => {
            let id_arg = arguments
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::Validation("id is required".to_string()))?;
            let app = arguments
                .get("application")
                .and_then(Value::as_object)
                .ok_or_else(|| AppError::Validation("application is required".to_string()))?;
            let existing = authorized_application(&pool, &principal, id_arg).await?;
            validate_references(&pool, &principal, &Value::Object(normalized_object(app))).await?;
            let exact = format!(
                "{}/{}",
                existing["owner"].as_str().unwrap_or_default(),
                existing["name"].as_str().unwrap_or_default()
            );
            update_application(&pool, &exact, app).await?;
            "Successfully updated application".to_string()
        }
        "delete_application" => {
            let app = arguments
                .get("application")
                .and_then(Value::as_object)
                .ok_or_else(|| AppError::Validation("application is required".to_string()))?;
            let normalized = normalized_object(app);
            let reference = match (
                string_field(&normalized, "owner"),
                string_field(&normalized, "name"),
            ) {
                (Some(owner), Some(name)) => format!("{owner}/{name}"),
                _ => required_field(&normalized, "id")?,
            };
            let existing = authorized_application(&pool, &principal, &reference).await?;
            delete_application(
                &pool,
                existing
                    .as_object()
                    .ok_or_else(|| AppError::Validation("Invalid application".into()))?,
            )
            .await?;
            "Successfully deleted application".to_string()
        }
        _ => {
            return Ok(mcp_error(
                id,
                -32602,
                "Invalid tool name",
                Some(json!(format!("Tool '{}' not found", tool_name))),
            ));
        }
    };

    Ok(mcp_ok(
        id,
        json!({
            "content": [{"type": "text", "text": text}]
        }),
    ))
}

async fn add_application(pool: &Pool<Postgres>, app: &Map<String, Value>) -> AppResult<()> {
    let normalized = normalized_object(app);
    let id = string_field(&normalized, "id").unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let owner = required_field(&normalized, "owner")?;
    let name = required_field(&normalized, "name")?;
    let organization = string_field(&normalized, "organization").unwrap_or_else(|| owner.clone());
    let display_name = string_field(&normalized, "display_name").unwrap_or_else(|| name.clone());
    let client_id =
        string_field(&normalized, "client_id").unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let client_secret =
        string_field(&normalized, "client_secret").unwrap_or_else(TokenService::generate_token);
    let redirect_uris =
        string_field(&normalized, "redirect_uris").unwrap_or_else(|| "[]".to_string());
    let token_format =
        string_field(&normalized, "token_format").unwrap_or_else(|| "JWT".to_string());
    let expire_in_hours = normalized
        .get("expire_in_hours")
        .and_then(Value::as_i64)
        .unwrap_or(24) as i32;

    sqlx::query(
        r#"
        INSERT INTO applications (
            id, owner, name, display_name, organization, client_id, client_secret,
            redirect_uris, token_format, expire_in_hours, is_deleted
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false)
        "#,
    )
    .bind(id)
    .bind(owner)
    .bind(name)
    .bind(display_name)
    .bind(organization)
    .bind(client_id)
    .bind(client_secret)
    .bind(redirect_uris)
    .bind(token_format)
    .bind(expire_in_hours)
    .execute(pool)
    .await?;
    Ok(())
}

async fn update_application(
    pool: &Pool<Postgres>,
    id_arg: &str,
    app: &Map<String, Value>,
) -> AppResult<()> {
    let normalized = normalized_object(app);
    let (owner, name) = owner_name_from_id(id_arg);
    let display_name = string_field(&normalized, "display_name");
    let homepage_url = string_field(&normalized, "homepage_url");
    let description = string_field(&normalized, "description");
    let redirect_uris = string_field(&normalized, "redirect_uris");

    let result = if let Some(owner) = owner {
        sqlx::query(
            r#"
            UPDATE applications
            SET display_name = COALESCE($3, display_name),
                homepage_url = COALESCE($4, homepage_url),
                description = COALESCE($5, description),
                redirect_uris = COALESCE($6, redirect_uris),
                updated_at = NOW()
            WHERE owner = $1 AND name = $2 AND is_deleted = false
            "#,
        )
        .bind(owner)
        .bind(name)
        .bind(display_name)
        .bind(homepage_url)
        .bind(description)
        .bind(redirect_uris)
        .execute(pool)
        .await?
    } else {
        sqlx::query(
            r#"
            UPDATE applications
            SET display_name = COALESCE($2, display_name),
                homepage_url = COALESCE($3, homepage_url),
                description = COALESCE($4, description),
                redirect_uris = COALESCE($5, redirect_uris),
                updated_at = NOW()
            WHERE (id = $1 OR name = $1) AND is_deleted = false
            "#,
        )
        .bind(name)
        .bind(display_name)
        .bind(homepage_url)
        .bind(description)
        .bind(redirect_uris)
        .execute(pool)
        .await?
    };

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "Application '{}' not found",
            id_arg
        )));
    }
    Ok(())
}

async fn delete_application(pool: &Pool<Postgres>, app: &Map<String, Value>) -> AppResult<()> {
    let normalized = normalized_object(app);
    let id = string_field(&normalized, "id");
    let owner = string_field(&normalized, "owner");
    let name = string_field(&normalized, "name");

    let result = if let (Some(owner), Some(name)) = (owner, name) {
        sqlx::query(
            r#"UPDATE applications SET is_deleted = true, updated_at = NOW()
               WHERE owner = $1 AND name = $2"#,
        )
        .bind(owner)
        .bind(name)
        .execute(pool)
        .await?
    } else {
        let id =
            id.ok_or_else(|| AppError::Validation("application id is required".to_string()))?;
        sqlx::query(
            r#"UPDATE applications SET is_deleted = true, updated_at = NOW()
               WHERE id = $1 OR name = $1"#,
        )
        .bind(id)
        .execute(pool)
        .await?
    };

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Application not found".to_string()));
    }
    Ok(())
}

async fn authorized_application(
    pool: &Pool<Postgres>,
    principal: &Principal,
    reference: &str,
) -> AppResult<Value> {
    let result: Option<Value> = if let Some((owner, name)) = reference.split_once('/') {
        sqlx::query_scalar("SELECT to_jsonb(t) FROM applications t WHERE owner=$1 AND name=$2 AND is_deleted=false")
            .bind(owner).bind(name).fetch_optional(pool).await?
    } else {
        // Bare names are scoped, and a UUID never selects more than one row.
        sqlx::query_scalar("SELECT to_jsonb(t) FROM applications t WHERE (id=$1 OR (name=$1 AND owner=$2)) AND is_deleted=false ORDER BY (id=$1) DESC LIMIT 1")
            .bind(reference).bind(&principal.owner).fetch_optional(pool).await?
    };
    let object = result.ok_or_else(|| AppError::NotFound("Application not found".into()))?;
    principal.check_owner(&object, "applications")?;
    Ok(object)
}

fn mcp_ok(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn mcp_error(id: Value, code: i32, message: &str, data: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
            "data": data
        }
    })
}

fn mcp_tools() -> Value {
    json!([
        {
            "name": "get_applications",
            "description": "Get all applications for a specific owner",
            "inputSchema": {"type": "object", "properties": {"owner": {"type": "string"}}, "required": ["owner"]}
        },
        {
            "name": "get_application",
            "description": "Get the detail of a specific application",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}
        },
        {
            "name": "add_application",
            "description": "Add a new application",
            "inputSchema": {"type": "object", "properties": {"application": {"type": "object"}}, "required": ["application"]}
        },
        {
            "name": "update_application",
            "description": "Update an existing application",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}, "application": {"type": "object"}}, "required": ["id", "application"]}
        },
        {
            "name": "delete_application",
            "description": "Delete an application",
            "inputSchema": {"type": "object", "properties": {"application": {"type": "object"}}, "required": ["application"]}
        }
    ])
}

fn normalized_object(object: &Map<String, Value>) -> Map<String, Value> {
    object
        .iter()
        .map(|(key, value)| (to_snake_case(key), value.clone()))
        .collect()
}

fn required_field(object: &Map<String, Value>, key: &str) -> AppResult<String> {
    string_field(object, key).ok_or_else(|| AppError::Validation(format!("{} is required", key)))
}

fn string_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    match object.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
        Some(Value::Array(_) | Value::Object(_)) => object.get(key).map(Value::to_string),
        Some(Value::Number(value)) => Some(value.to_string()),
        Some(Value::Bool(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn owner_name_from_id(id: &str) -> (Option<String>, String) {
    if let Some((owner, name)) = id.split_once('/') {
        return (Some(owner.to_string()), name.to_string());
    }
    (None, id.to_string())
}

fn camelize_value(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    let value = if matches!(key.as_str(), "client_secret" | "clientSecret") {
                        json!("***")
                    } else {
                        camelize_value(value)
                    };
                    (to_camel_case(&key), value)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(camelize_value).collect()),
        value => value,
    }
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
