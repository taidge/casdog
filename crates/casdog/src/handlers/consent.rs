use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::{Application, ConsentGrantResponse, ConsentRequest};
use crate::services::{AppService, ConsentService, TokenService};

fn normalize_scopes(req: &ConsentRequest) -> Vec<String> {
    let mut scopes = req.granted_scopes.clone();
    if scopes.is_empty() {
        scopes.extend(
            req.scope
                .as_deref()
                .unwrap_or_default()
                .split_whitespace()
                .filter(|scope| !scope.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    scopes.sort();
    scopes.dedup();
    scopes
}

fn redirect_uri_allowed(allowed_uris: &str, redirect_uri: &str) -> bool {
    allowed_uris
        .split(|c| c == ',' || c == '\n' || c == ' ')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .any(|value| value == redirect_uri)
}

fn application_matches(application: &Application, identifier: &str) -> bool {
    identifier == application.id
        || identifier == application.name
        || identifier == format!("{}/{}", application.owner, application.name)
}

async fn resolve_application(pool: &DieselPool, req: &ConsentRequest) -> AppResult<Application> {
    let app_service = AppService::new(pool.clone());

    let application = if let Some(client_id) = req.client_id.as_deref() {
        app_service.get_by_client_id(client_id).await?
    } else if req.application.contains('/') {
        let mut parts = req.application.splitn(2, '/');
        let owner = parts.next().unwrap_or("admin");
        let name = parts.next().unwrap_or_default();
        app_service.get_by_name(owner, name).await?
    } else {
        match app_service.get_internal_by_id(&req.application).await {
            Ok(application) => application,
            Err(_) => app_service.get_by_name("admin", &req.application).await?,
        }
    };

    if !req.application.is_empty() && !application_matches(&application, &req.application) {
        return Err(AppError::Validation("Invalid application".to_string()));
    }

    Ok(application)
}

#[endpoint(tags("consent"), summary = "Grant consent")]
pub async fn grant_consent(
    depot: &mut Depot,
    body: JsonBody<ConsentRequest>,
) -> AppResult<Json<ConsentGrantResponse>> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let req = body.into_inner();
    let scopes = normalize_scopes(&req);
    if scopes.is_empty() {
        return Err(AppError::Validation(
            "Granted scopes cannot be empty".to_string(),
        ));
    }

    let application = resolve_application(&pool, &req).await?;
    if let Some(redirect_uri) = req.redirect_uri.as_deref() {
        if !application.redirect_uris.is_empty()
            && !redirect_uri_allowed(&application.redirect_uris, redirect_uri)
        {
            return Err(AppError::Authentication(
                "Redirect URI mismatch".to_string(),
            ));
        }
    }

    ConsentService::grant(&pg_pool, &user_id, &application.id, &scopes).await?;

    let scope_text = if let Some(scope) = req.scope.as_deref() {
        scope.to_string()
    } else {
        scopes.join(" ")
    };

    let code = match (
        req.client_id.as_deref(),
        req.response_type.as_deref().unwrap_or("code"),
        req.redirect_uri.as_deref(),
    ) {
        (Some(_), "code", Some(redirect_uri)) => Some(
            TokenService::create_authorization_code(
                &pool,
                &application,
                &user_id,
                &scope_text,
                req.nonce.as_deref(),
                redirect_uri,
                req.challenge.as_deref(),
                req.code_challenge_method.as_deref(),
            )
            .await?,
        ),
        _ => None,
    };

    Ok(Json(ConsentGrantResponse {
        code,
        redirect_uri: req.redirect_uri,
        state: req.state,
        application: application.id,
        granted_scopes: scopes,
    }))
}

#[endpoint(tags("consent"), summary = "Revoke consent")]
pub async fn revoke_consent(
    depot: &mut Depot,
    body: JsonBody<ConsentRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let req = body.into_inner();
    let scopes = normalize_scopes(&req);
    if scopes.is_empty() {
        return Err(AppError::Validation(
            "Granted scopes cannot be empty".to_string(),
        ));
    }

    let application = resolve_application(&pool, &req).await?;
    let remaining = ConsentService::revoke(&pg_pool, &user_id, &application.id, &scopes).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Consent revoked",
        "application": application.id,
        "grantedScopes": remaining,
    })))
}
