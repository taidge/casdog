use salvo::http::header::{HeaderName, HeaderValue};
use salvo::oapi::endpoint;
use salvo::oapi::extract::*;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::{Application, UserResponse};
use crate::services::auth_service::{AuthService, LoginResponse};
use crate::services::face_service::{FaceService, FaceVerifyRequest};
use crate::services::spnego_service::SpnegoService;
use crate::services::{AppService, TokenService, UserService};

async fn resolve_application(pool: &DieselPool, identifier: &str) -> AppResult<Application> {
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

fn extract_negotiate_token(req: &Request) -> Option<String> {
    req.header::<String>("Authorization")
        .and_then(|value| value.strip_prefix("Negotiate ").map(ToOwned::to_owned))
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

/// Kerberos login with real SPNEGO / Negotiate token validation.
///
/// Parses the GSSAPI SPNEGO token from the `Authorization: Negotiate` header
/// to extract the Kerberos principal. Falls back to trusted proxy headers
/// (`X-Kerberos-User`, `REMOTE_USER`) and the `username` query parameter.
#[endpoint(tags("authentication"), summary = "Kerberos login via SPNEGO")]
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
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    // If no Negotiate token is present, send a 401 with the WWW-Authenticate
    // challenge to initiate the SPNEGO handshake.
    if extract_negotiate_token(req).is_none() {
        res.status_code(StatusCode::UNAUTHORIZED);
        res.headers_mut().insert(
            HeaderName::from_static("www-authenticate"),
            HeaderValue::from_static("Negotiate"),
        );
        return Ok(());
    }

    let application = resolve_application(&pool, application.as_str()).await?;

    // Extract identity using the real SPNEGO parser with fallback chain:
    // 1. Parse the Negotiate token (GSSAPI → SPNEGO → Kerberos AP-REQ)
    // 2. Trusted proxy header (X-Kerberos-User / REMOTE_USER)
    // 3. Query parameter (username)
    let negotiate_token = extract_negotiate_token(req);
    let proxy_header = req
        .header::<String>("X-Kerberos-User")
        .or_else(|| req.header::<String>("REMOTE_USER"));
    let query_username = req.query::<String>("username");

    let username = SpnegoService::extract_identity(
        negotiate_token.as_deref(),
        proxy_header.as_deref(),
        query_username.as_deref(),
    )?;

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

/// Begin a FaceID sign-in challenge.
///
/// Generates a one-time nonce for the face-verification ceremony. The client
/// must call `faceid_signin_finish` with the captured face embedding and this
/// nonce to complete authentication.
#[endpoint(tags("authentication"), summary = "Begin FaceID sign-in challenge")]
pub async fn faceid_signin_begin(
    depot: &mut Depot,
    owner: QueryParam<String, true>,
    name: QueryParam<String, true>,
    application: QueryParam<String, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let face_service = FaceService::new(pool);
    let challenge = face_service
        .begin(owner.as_str(), name.as_str(), application.as_deref())
        .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Face challenge issued",
        "challenge": challenge.challenge,
        "expires_at": challenge.expires_at,
        "user": challenge.user,
        "application": challenge.application,
    })))
}

/// Complete a FaceID sign-in by verifying the face embedding.
///
/// Accepts a face embedding vector and the challenge nonce from `begin`.
/// Compares the embedding against stored face data using cosine similarity
/// and authenticates the user if the match exceeds the threshold.
#[endpoint(tags("authentication"), summary = "Finish FaceID sign-in verification")]
pub async fn faceid_signin_finish(
    depot: &mut Depot,
    owner: QueryParam<String, true>,
    name: QueryParam<String, true>,
    body: JsonBody<FaceVerifyRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let face_service = FaceService::new(pg_pool);
    let result = face_service
        .finish(owner.as_str(), name.as_str(), &body)
        .await?;

    if !result.matched {
        return Err(AppError::Authentication(format!(
            "Face verification failed: similarity {:.4} below threshold {:.4}",
            result.similarity, result.threshold,
        )));
    }

    // Face matched — issue a login token.
    let user_service = UserService::new(pool);
    let user = user_service
        .get_by_name(owner.as_str(), name.as_str())
        .await?;
    let user_response: UserResponse = user.into();
    let auth_service = AuthService::new(user_service);
    let token = auth_service.generate_token(&user_response)?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Face verification succeeded",
        "similarity": result.similarity,
        "threshold": result.threshold,
        "token": token,
        "token_type": "Bearer",
        "user": format!("{}/{}", owner.as_str(), name.as_str()),
    })))
}
