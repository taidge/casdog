use super::service::{authorize, identity, random_secret, text};
use crate::error::{AppError, AppResult};
use crate::hoops::authz::Principal;
use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::Duration;

const DEFAULT_MARKETPLACE: &str = "https://cdn.jsdelivr.net/gh/casdoor/casdoor-integrations@dist";
pub fn base_url() -> String {
    std::env::var("CASDOG_MARKETPLACE_URL")
        .unwrap_or_else(|_| DEFAULT_MARKETPLACE.into())
        .trim_end_matches('/')
        .to_string()
}

pub async fn fetch(url: &str) -> AppResult<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AppError::Internal("HTTP client unavailable".into()))?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| AppError::Validation(format!("Remote catalog unavailable: {e}")))?;
    if !response.status().is_success() {
        return Err(AppError::Validation(format!(
            "Remote catalog returned {}",
            response.status()
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AppError::Validation("Cannot read remote response".into()))?
    {
        if bytes.len() + chunk.len() > 10 * 1024 * 1024 {
            return Err(AppError::Validation("Remote catalog exceeds 10 MiB".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub async fn index(base: &str) -> AppResult<Value> {
    let mut data: Value = serde_json::from_slice(&fetch(&format!("{base}/index.json")).await?)
        .map_err(|_| AppError::Validation("Invalid marketplace index".into()))?;
    if !data.get("integrations").is_some_and(Value::is_array) {
        return Err(AppError::Validation(
            "Marketplace integrations array missing".into(),
        ));
    }
    data["baseUrl"] = json!(base);
    for item in data["integrations"].as_array_mut().unwrap() {
        if let Some(logo) = item
            .get("logo")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty() && !v.starts_with("https://") && !v.starts_with("http://"))
        {
            item["logo"] = json!(format!("{base}/{}", logo.trim_start_matches('/')));
        }
        if let Some(screenshots) = item.get_mut("screenshots").and_then(Value::as_array_mut) {
            for image in screenshots {
                if let Some(path) = image
                    .as_str()
                    .filter(|v| !v.starts_with("https://") && !v.starts_with("http://"))
                {
                    *image = json!(format!("{base}/{}", path.trim_start_matches('/')));
                }
            }
        }
    }
    Ok(data)
}
pub fn validate_bundle(
    index: &Value,
    id: &str,
    version: &str,
    bytes: &[u8],
) -> AppResult<(Value, Value)> {
    let item = index["integrations"]
        .as_array()
        .and_then(|items| items.iter().find(|item| text(item, "id") == id))
        .ok_or_else(|| AppError::NotFound("Integration not in marketplace".into()))?;
    let version = if version.is_empty() {
        text(item, "latest")
    } else {
        version
    };
    if index["revoked"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|v| text(v, "id") == id && text(v, "version") == version)
    }) {
        return Err(AppError::Validation(
            "Integration version was withdrawn".into(),
        ));
    }
    let release = item["versions"]
        .as_array()
        .and_then(|items| items.iter().find(|v| text(v, "version") == version))
        .ok_or_else(|| AppError::NotFound("Integration version not found".into()))?;
    if !hex::encode(Sha256::digest(bytes)).eq_ignore_ascii_case(text(release, "sha256")) {
        return Err(AppError::Validation(
            "Marketplace bundle checksum mismatch".into(),
        ));
    }
    let bundle: Value = serde_json::from_slice(bytes)
        .map_err(|_| AppError::Validation("Invalid marketplace bundle JSON".into()))?;
    if text(&bundle["manifest"], "id") != id
        || text(&bundle["manifest"], "version") != version
        || text(&bundle["manifest"], "type") != text(item, "type")
        || !bundle["files"].is_object()
    {
        return Err(AppError::Validation(
            "Bundle manifest does not match catalog".into(),
        ));
    }
    Ok((item.clone(), bundle))
}
pub async fn bundle(base: &str, id: &str, version: &str) -> AppResult<(Value, Value)> {
    let index = index(base).await?;
    let item = index["integrations"]
        .as_array()
        .and_then(|items| items.iter().find(|item| text(item, "id") == id))
        .ok_or_else(|| AppError::NotFound("Integration not in marketplace".into()))?;
    let version = if version.is_empty() {
        text(item, "latest")
    } else {
        version
    };
    let release = item["versions"]
        .as_array()
        .and_then(|items| items.iter().find(|v| text(v, "version") == version))
        .ok_or_else(|| AppError::NotFound("Integration version not found".into()))?;
    let root = reqwest::Url::parse(&format!("{base}/"))
        .map_err(|_| AppError::Validation("Invalid marketplace base URL".into()))?;
    let url = root
        .join(text(release, "url"))
        .map_err(|_| AppError::Validation("Invalid bundle URL".into()))?;
    if url.origin() != root.origin() || !url.path().starts_with(root.path()) {
        return Err(AppError::Validation(
            "Bundle URL must stay inside the configured marketplace".into(),
        ));
    }
    let bytes = fetch(url.as_str()).await?;
    validate_bundle(&index, id, version, &bytes)
}

pub fn render(bundle: &Value, request: &Value, file: &str) -> AppResult<Value> {
    let mut variables = serde_json::Map::new();
    if let Some(fields) = bundle["manifest"]["variables"].as_array() {
        for field in fields {
            let key = text(field, "name");
            let mut value = text(&request["variables"], key).trim().to_string();
            if field["required"] == true && value.is_empty() {
                return Err(AppError::Validation(format!("Variable {key} is required")));
            }
            if !value.is_empty() {
                match text(field, "type") {
                    "url" => {
                        let url = reqwest::Url::parse(&value).map_err(|_| {
                            AppError::Validation(format!("Invalid URL variable {key}"))
                        })?;
                        if !matches!(url.scheme(), "https" | "http")
                            || url.host_str().is_none()
                            || value.chars().any(|c| {
                                c.is_whitespace() || ['\"', '\'', '<', '>', '`'].contains(&c)
                            })
                        {
                            return Err(AppError::Validation(format!(
                                "Invalid URL variable {key}"
                            )));
                        }
                        value = value.trim_end_matches('/').into();
                    }
                    "color" => {
                        if value.len() != 7
                            || !value.starts_with('#')
                            || !value[1..].bytes().all(|b| b.is_ascii_hexdigit())
                        {
                            return Err(AppError::Validation(format!(
                                "Invalid color variable {key}"
                            )));
                        }
                    }
                    _ => {
                        if value.len() > 500 {
                            return Err(AppError::Validation(format!("Variable {key} too long")));
                        }
                    }
                }
            }
            variables.insert(key.into(), json!(value));
        }
    }
    let mut data = bundle["files"]
        .get(file)
        .cloned()
        .ok_or_else(|| AppError::Validation(format!("Bundle has no {file}")))?;
    if data.is_string() {
        data = serde_json::from_str(data.as_str().unwrap())
            .map_err(|_| AppError::Validation("Invalid template JSON".into()))?;
    }
    fn replace(value: &mut Value, variables: &serde_json::Map<String, Value>) {
        match value {
            Value::String(s) => {
                let re = regex::Regex::new(r"\{\{\s*([a-zA-Z][a-zA-Z0-9]*)\s*\}\}").unwrap();
                *s = re
                    .replace_all(s, |caps: &regex::Captures| {
                        variables
                            .get(&caps[1])
                            .and_then(Value::as_str)
                            .unwrap_or(&caps[0])
                            .to_string()
                    })
                    .into_owned();
            }
            Value::Object(map) => {
                for value in map.values_mut() {
                    replace(value, variables)
                }
            }
            Value::Array(array) => {
                for value in array {
                    replace(value, variables)
                }
            }
            _ => {}
        }
    }
    replace(&mut data, &variables);
    Ok(data)
}

pub async fn install(
    pool: &PgPool,
    principal: &Principal,
    request: &Value,
    item: &Value,
    bundle: &Value,
) -> AppResult<Value> {
    let owner = text(request, "owner");
    let name = text(request, "name");
    authorize(principal, owner)?;
    identity(owner, name)?;
    if item["requiresGlobalAdmin"] == true && !principal.global_admin() {
        return Err(super::service::denied());
    }
    let kind = text(&bundle["manifest"], "type");
    if !["app", "provider"].contains(&kind) {
        return Err(AppError::Validation("Only application and provider integrations are currently supported; theme installation is not implemented".into()));
    }
    let template = render(
        bundle,
        request,
        if kind == "app" {
            "application.json"
        } else {
            "provider.json"
        },
    )?;
    let display = item["name"]["en"].as_str().unwrap_or(name);
    let resource_id = uuid::Uuid::new_v4().to_string();
    let mut document = json!({"owner":owner,"name":name,"displayName":display,"createdTime":Utc::now().to_rfc3339(),"updatedTime":Utc::now().to_rfc3339(),"integrationId":text(&bundle["manifest"],"id"),"type":kind,"version":text(&bundle["manifest"],"version"),"logo":text(item,"logo"),"variables":request.get("variables").cloned().unwrap_or_else(||json!({})),"bundle":bundle.to_string(),"resourceId":resource_id});
    let mut tx = pool.begin().await?;
    // The envelope is inserted in the same transaction as its resource and application linkage.
    sqlx::query(
        "INSERT INTO casdoor_objects(kind,owner,name,document) VALUES('integration',$1,$2,$3)",
    )
    .bind(owner)
    .bind(name)
    .bind(&document)
    .execute(&mut *tx)
    .await?;
    if kind == "app" {
        let redirects = template
            .get("redirectUris")
            .cloned()
            .unwrap_or_else(|| json!([]));
        if !redirects
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string))
        {
            return Err(AppError::Validation(
                "redirectUris must be string array".into(),
            ));
        }
        for redirect in redirects.as_array().unwrap() {
            let url = reqwest::Url::parse(redirect.as_str().unwrap())
                .map_err(|_| AppError::Validation("Invalid redirect URI".into()))?;
            if !matches!(url.scheme(), "http" | "https") || url.fragment().is_some() {
                return Err(AppError::Validation("Invalid redirect URI".into()));
            }
        }
        let grants = template
            .get("grantTypes")
            .cloned()
            .unwrap_or_else(|| json!(["authorization_code", "refresh_token"]));
        if !grants.as_array().is_some_and(|values| {
            values.iter().all(|v| {
                v.as_str().is_some_and(|s| {
                    [
                        "authorization_code",
                        "refresh_token",
                        "client_credentials",
                        "password",
                        "urn:ietf:params:oauth:grant-type:device_code",
                    ]
                    .contains(&s)
                })
            })
        }) {
            return Err(AppError::Validation("Invalid grantTypes".into()));
        }
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,logo,homepage_url,organization,client_id,client_secret,redirect_uris,grant_types,token_format) VALUES($1,$2,$3,$4,$5,$6,$2,$7,$8,$9,$10,$11)")
            .bind(&resource_id).bind(owner).bind(name).bind(display).bind(text(item,"logo")).bind(text(&request["variables"],"appUrl")).bind(random_secret()).bind(random_secret()).bind(redirects.to_string()).bind(grants).bind(template.get("tokenFormat").and_then(Value::as_str).filter(|s|!s.is_empty()).unwrap_or("JWT")).execute(&mut *tx).await?;
        document["application"] = json!(name);
    } else {
        if text(request, "clientId").is_empty() || text(request, "clientSecret").is_empty() {
            return Err(AppError::Validation(
                "clientId and clientSecret are required".into(),
            ));
        }
        if text(&template, "category").is_empty() || text(&template, "type").is_empty() {
            return Err(AppError::Validation(
                "Provider category and type are required".into(),
            ));
        }
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,method,client_id,client_secret,scopes,custom_auth_url,custom_token_url,custom_user_info_url,issuer_url,provider_url,custom_logo) VALUES($1,$2,$3,$4,$5,$6,'Normal',$7,$8,$9,$10,$11,$12,$13,$14,$15)")
            .bind(&resource_id).bind(owner).bind(name).bind(display).bind(text(&template,"category")).bind(text(&template,"type")).bind(text(request,"clientId")).bind(text(request,"clientSecret")).bind(text(&template,"scopes")).bind(text(&template,"customAuthUrl")).bind(text(&template,"customTokenUrl")).bind(text(&template,"customUserInfoUrl")).bind(text(&template,"issuerUrl")).bind(text(&template,"providerUrl")).bind(text(item,"logo")).execute(&mut *tx).await?;
        document["provider"] = json!(name);
        let app = text(request, "application");
        if !app.is_empty() {
            let app_name = app.split_once('/').map(|(_, n)| n).unwrap_or(app);
            let app_id:Option<String>=sqlx::query_scalar("SELECT id FROM applications WHERE organization=$1 AND name=$2 AND NOT is_deleted FOR UPDATE").bind(owner).bind(app_name).fetch_optional(&mut *tx).await?;
            let app_id = app_id.ok_or_else(|| {
                AppError::Validation("Application does not belong to this organization".into())
            })?;
            let entry = json!([{"owner":owner,"name":name,"canSignUp":true,"canSignIn":true,"canUnlink":true,"rule":"None"}]);
            sqlx::query("UPDATE applications SET providers=COALESCE(providers,'[]'::jsonb)||$2::jsonb,updated_at=NOW() WHERE id=$1").bind(app_id).bind(entry).execute(&mut *tx).await?;
            document["application"] = json!(app_name);
        }
    }
    sqlx::query(
        "UPDATE casdoor_objects SET document=$3 WHERE kind='integration' AND owner=$1 AND name=$2",
    )
    .bind(owner)
    .bind(name)
    .bind(&document)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(super::service::masked(
        super::service::Kind::Integration,
        document,
        false,
    ))
}

pub async fn uninstall(
    pool: &PgPool,
    principal: &Principal,
    owner: &str,
    name: &str,
) -> AppResult<bool> {
    authorize(principal, owner)?;
    let mut tx = pool.begin().await?;
    let document:Option<Value>=sqlx::query_scalar("SELECT document FROM casdoor_objects WHERE kind='integration' AND owner=$1 AND name=$2 FOR UPDATE").bind(owner).bind(name).fetch_optional(&mut *tx).await?;
    let Some(document) = document else {
        return Ok(false);
    };
    let resource = text(&document, "resourceId");
    match text(&document, "type") {
        "app" => {
            sqlx::query("DELETE FROM tokens WHERE owner=$1 AND application=$2")
                .bind(owner)
                .bind(text(&document, "application"))
                .execute(&mut *tx)
                .await?;
            // Installation creates a new resource; remove that exact resource so
            // its unique owner/name becomes available for a later reinstall.
            sqlx::query("DELETE FROM applications WHERE id=$1 AND organization=$2")
                .bind(resource)
                .bind(owner)
                .execute(&mut *tx)
                .await?;
        }
        "provider" => {
            sqlx::query("UPDATE applications SET providers=(SELECT COALESCE(jsonb_agg(p),'[]'::jsonb) FROM jsonb_array_elements(COALESCE(providers,'[]'::jsonb)) p WHERE NOT(p->>'owner'=$2 AND p->>'name'=$3)),updated_at=NOW() WHERE organization=$1")
                .bind(owner).bind(owner).bind(text(&document,"provider")).execute(&mut *tx).await?;
            sqlx::query("DELETE FROM providers WHERE id=$1 AND owner=$2")
                .bind(resource)
                .bind(owner)
                .execute(&mut *tx)
                .await?;
        }
        _ => {
            return Err(AppError::Validation(
                "Unsupported installed integration type".into(),
            ));
        }
    }
    sqlx::query("DELETE FROM casdoor_objects WHERE kind='integration' AND owner=$1 AND name=$2")
        .bind(owner)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}
