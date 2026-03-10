use base64::Engine;
use salvo::http::header::{HeaderName, HeaderValue};
use salvo::oapi::endpoint;
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{Application, UserResponse};
use crate::services::auth_service::{AuthService, LoginResponse};
use crate::services::{AppService, TokenService, UserService};

async fn resolve_application(pool: &Pool<Postgres>, identifier: &str) -> AppResult<Application> {
    let app_service = AppService::new(pool.clone());
    if identifier.contains('/') {
        let mut parts = identifier.splitn(2, '/');
        let owner = parts.next().unwrap_or("admin");
        let name = parts.next().unwrap_or_default();
        app_service.get_by_name(owner, name).await
    } else {
        match app_service.get_internal_by_id(identifier).await {
            Ok(application) => Ok(application),
            Err(_) => app_service.get_by_name("admin", identifier).await,
        }
    }
}

fn user_has_face_data(user: &crate::models::User) -> bool {
    let sources = [user.properties.as_ref(), user.custom.as_ref()];
    for source in sources.into_iter().flatten() {
        if source
            .get("faceIds")
            .and_then(serde_json::Value::as_array)
            .map(|items| !items.is_empty())
            .unwrap_or(false)
        {
            return true;
        }
        if source
            .get("face_id")
            .and_then(serde_json::Value::as_str)
            .map(|value| !value.is_empty())
            .unwrap_or(false)
        {
            return true;
        }
    }

    user.provider_ids
        .as_ref()
        .and_then(|value| value.get("faceid"))
        .and_then(serde_json::Value::as_str)
        .map(|value| !value.is_empty())
        .unwrap_or(false)
}

fn extract_negotiate_token(req: &Request) -> Option<String> {
    req.header::<String>("Authorization")
        .and_then(|value| value.strip_prefix("Negotiate ").map(ToOwned::to_owned))
}

fn extract_kerberos_username(req: &Request) -> Option<String> {
    if let Some(username) = req.header::<String>("X-Kerberos-User") {
        if !username.is_empty() {
            return Some(username);
        }
    }

    if let Some(username) = req.query::<String>("username") {
        if !username.is_empty() {
            return Some(username);
        }
    }

    let token = extract_negotiate_token(req)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token.as_bytes())
        .ok()?;
    let username = String::from_utf8(decoded).ok()?;
    let username = username.trim().to_string();
    if username.is_empty() {
        None
    } else {
        Some(username)
    }
}

fn build_login_response(
    auth_service: &AuthService,
    user: UserResponse,
    code: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
) -> AppResult<LoginResponse> {
    let token = auth_service.generate_token(&user)?;
    Ok(LoginResponse {
        token,
        token_type: "Bearer".to_string(),
        expires_in: 24 * 3600,
        user,
        redirect_uri,
        code,
        state,
        mfa_required: None,
        mfa_types: None,
        password_expired: None,
    })
}

#[endpoint(tags("authentication"), summary = "Kerberos login compatibility")]
pub async fn kerberos_login(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    application: QueryParam<String, true>,
    client_id: QueryParam<String, false>,
    response_type: QueryParam<String, false>,
    redirect_uri: QueryParam<String, false>,
    scope: QueryParam<String, false>,
    state: QueryParam<String, false>,
    nonce: QueryParam<String, false>,
    code_challenge: QueryParam<String, false>,
    code_challenge_method: QueryParam<String, false>,
) -> AppResult<()> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    if extract_negotiate_token(req).is_none() {
        res.status_code(StatusCode::UNAUTHORIZED);
        res.headers_mut().insert(
            HeaderName::from_static("www-authenticate"),
            HeaderValue::from_static("Negotiate"),
        );
        return Ok(());
    }

    let application = resolve_application(&pool, application.as_str()).await?;
    let username = extract_kerberos_username(req).ok_or_else(|| {
        AppError::Authentication(
            "Kerberos credential parsing is not configured; provide X-Kerberos-User or username"
                .to_string(),
        )
    })?;

    let user_service = UserService::new(pool.clone());
    let user = match user_service
        .get_by_name(&application.organization, &username)
        .await
    {
        Ok(user) => user,
        Err(_) => user_service.get_by_name("admin", &username).await?,
    };
    let user_response: UserResponse = user.into();
    let auth_service = AuthService::new(user_service);

    let code = match (
        client_id.as_deref(),
        response_type.as_deref().unwrap_or("code"),
        redirect_uri.as_deref(),
    ) {
        (Some(cid), "code", Some(uri)) if cid == application.client_id => Some(
            TokenService::create_authorization_code(
                &pool,
                &application,
                &user_response.id,
                scope.as_deref().unwrap_or("openid profile"),
                nonce.as_deref(),
                uri,
                code_challenge.as_deref(),
                code_challenge_method.as_deref(),
            )
            .await?,
        ),
        _ => None,
    };

    let login = build_login_response(
        &auth_service,
        user_response,
        code,
        redirect_uri.into_inner(),
        state.into_inner(),
    )?;
    res.render(Json(login));
    Ok(())
}

#[endpoint(tags("authentication"), summary = "FaceID sign-in compatibility")]
pub async fn faceid_signin_begin(
    depot: &mut Depot,
    owner: QueryParam<String, true>,
    name: QueryParam<String, true>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user = UserService::new(pool)
        .get_by_name(owner.as_str(), name.as_str())
        .await?;
    if !user_has_face_data(&user) {
        return Err(AppError::Validation(
            "Face data does not exist, cannot log in".to_string(),
        ));
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Face data is available",
        "user": format!("{}/{}", user.owner, user.name),
        "application": user.signup_application,
    })))
}
