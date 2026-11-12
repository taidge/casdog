use salvo::http::header::{HeaderName, HeaderValue};
use salvo::oapi::endpoint;
use salvo::oapi::extract::*;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{Organization, User};
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
    req: &mut Request,
    res: &mut Response,
    owner: QueryParam<String, true>,
    name: QueryParam<String, true>,
    body: JsonBody<FaceVerifyRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let mut tx = pg_pool.begin().await?;
    let result = FaceService::finish_conn(&mut tx, owner.as_str(), name.as_str(), &body).await?;

    if !result.matched {
        // Consume a failed biometric attempt too; retry requires a new nonce.
        tx.commit().await?;
        return Err(AppError::Authentication(format!(
            "Face verification failed: similarity {:.4} below threshold {:.4}",
            result.similarity, result.threshold,
        )));
    }

    let user: User = sqlx::query_as("SELECT * FROM users WHERE owner=$1 AND name=$2")
        .bind(owner.as_str())
        .bind(name.as_str())
        .fetch_one(&mut *tx)
        .await?;
    let org: Organization = sqlx::query_as(
        "SELECT * FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin",
    )
    .bind(&user.owner)
    .fetch_one(&mut *tx)
    .await?;
    let app = match result.application.as_deref() {
        Some(id) => Some(super::social_login::application_conn(&mut tx, id).await?),
        None => None,
    };
    let created = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let context = serde_json::json!({
        "primary_factor":"face",
        "face_stamp":FaceService::credential_stamp(user.properties.as_ref(), user.custom.as_ref()),
        "master_stamp":crate::services::social_state_service::proof_hash(org.master_password.as_deref().unwrap_or_default())
    });
    let additional: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_mfa WHERE user_id=$1 AND is_enabled)")
            .bind(&user.id)
            .fetch_one(&mut *tx)
            .await?;
    let mut response =
        if user.mfa_enabled || user.mfa_email_enabled || user.mfa_phone_enabled || additional {
            let origin = super::social_login::public_origin()?;
            if req.header::<String>("origin").as_deref() != Some(origin.as_str()) {
                return Err(AppError::Authentication("Invalid login origin".into()));
            }
            let (secret, methods) = super::password_mfa::create_primary_factor_challenge(
                &mut tx,
                &user,
                created,
                app.as_ref().map(|a| a.id.clone()),
                context,
            )
            .await?;
            super::social_login::set_cookie(
                res,
                "casdog_password_mfa",
                &secret,
                300,
                origin.starts_with("https://"),
            );
            serde_json::json!({"mfa_required":true,"mfa_types":methods,"token":"","expires_in":0})
        } else {
            let value = super::password_mfa::primary_login_result(
                depot,
                &mut tx,
                &user,
                &org,
                app.as_ref(),
                created,
                &context,
            )
            .await?;
            super::social_login::set_cookie(
                res,
                "casdog_password_mfa",
                "",
                0,
                super::social_login::public_origin()?.starts_with("https://"),
            );
            value
        };
    tx.commit().await?;
    // Keep the legacy FaceID receipt fields while using the common JWT/MFA flow.
    let receipt = serde_json::json!({
        "status": "ok",
        "msg": "Face verification succeeded",
        "similarity": result.similarity,
        "threshold": result.threshold,
        "token_type": "Bearer",
        "user": format!("{}/{}", owner.as_str(), name.as_str()),
    });
    response
        .as_object_mut()
        .unwrap()
        .extend(receipt.as_object().unwrap().clone());
    Ok(Json(response))
}
