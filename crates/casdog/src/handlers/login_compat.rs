use salvo::http::header::{HeaderName, HeaderValue};
use salvo::oapi::endpoint;
use salvo::oapi::extract::*;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::UserResponse;
use crate::services::UserService;
use crate::services::auth_service::AuthService;
use crate::services::face_service::{FaceService, FaceVerifyRequest};
use crate::services::spnego_service::SpnegoService;

fn extract_negotiate_token(req: &Request) -> Option<String> {
    req.header::<String>("Authorization")
        .and_then(|value| value.strip_prefix("Negotiate ").map(ToOwned::to_owned))
}

/// Issue the Negotiate challenge, but never authenticate unverified ticket metadata.
/// Full Kerberos login requires a cryptographic GSSAPI/keytab verifier.
#[endpoint(
    tags("authentication"),
    summary = "Kerberos negotiation (verification unavailable)"
)]
pub async fn kerberos_login(req: &mut Request, res: &mut Response) -> AppResult<()> {
    let token = extract_negotiate_token(req);
    res.headers_mut().insert(
        HeaderName::from_static("www-authenticate"),
        HeaderValue::from_static("Negotiate"),
    );
    if token.is_none() {
        res.status_code(StatusCode::UNAUTHORIZED);
        return Ok(());
    }
    SpnegoService::extract_identity(token.as_deref(), None, None)?;
    Err(AppError::Authentication(
        "Kerberos ticket verification is not configured".to_string(),
    ))
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
