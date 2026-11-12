use salvo::http::header::{HeaderName, HeaderValue};
use salvo::oapi::endpoint;
use salvo::oapi::extract::*;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{Organization, User};
use crate::services::face_service::{FaceService, FaceVerifyRequest};
use crate::services::{CheckService, kerberos_service::KerberosService};

fn extract_negotiate_token(req: &Request) -> Option<String> {
    req.header::<String>("Authorization")
        .and_then(|value| value.strip_prefix("Negotiate ").map(ToOwned::to_owned))
}

/// Authenticate an actual service ticket before entering the shared MFA/JWT flow.
#[endpoint(tags("authentication"), summary = "Kerberos/SPNEGO sign-in")]
pub async fn kerberos_login(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<()> {
    static VERIFIERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);
    let token = extract_negotiate_token(req);
    res.headers_mut().insert(
        HeaderName::from_static("www-authenticate"),
        HeaderValue::from_static("Negotiate"),
    );
    if token.is_none() {
        res.status_code(StatusCode::UNAUTHORIZED);
        return Ok(());
    }
    // Reject malformed authentication material before application metadata or
    // database access. This checks bounded framing only; it proves no identity.
    crate::services::spnego_service::SpnegoService::authentication_token(
        token.as_deref().unwrap(),
    )?;
    let reference = req
        .query::<String>("application")
        .filter(|s| !s.is_empty() && s.len() <= 400)
        .ok_or_else(|| AppError::Validation("Missing application".into()))?;
    let origin = super::social_login::public_origin()?;
    if req.header::<String>("origin").is_some_and(|v| v != origin)
        || req
            .header::<String>("sec-fetch-site")
            .is_some_and(|v| !matches!(v.as_str(), "same-origin" | "none"))
    {
        return Err(AppError::Authentication("Invalid login origin".into()));
    }
    let pool = super::social_login::pg_pool(depot)?;
    let app = super::social_login::application(&pool, &reference).await?;
    let org: Organization = sqlx::query_as(
        "SELECT * FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin",
    )
    .bind(&app.organization)
    .fetch_optional(&pool)
    .await?
    .ok_or_else(|| AppError::Authentication("Organization unavailable".into()))?;
    let _permit = VERIFIERS
        .try_acquire()
        .map_err(|_| AppError::Validation("Retry Kerberos sign-in shortly".into()))?;
    let proof = tokio::task::spawn_blocking(move || {
        KerberosService::verify(&org, token.as_deref().unwrap())
    })
    .await
    .map_err(|_| AppError::Authentication("Kerberos authentication failed".into()))??;
    let mut tx = pool.begin().await?;
    let user:User=sqlx::query_as("SELECT * FROM users WHERE owner=$1 AND name=$2 AND NOT is_deleted AND NOT is_forbidden FOR UPDATE")
        .bind(&app.organization).bind(&proof.username).fetch_optional(&mut *tx).await?
        .ok_or_else(||AppError::Authentication("Kerberos account unavailable".into()))?;
    let org:Organization=sqlx::query_as("SELECT * FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin FOR SHARE")
        .bind(&user.owner).fetch_optional(&mut *tx).await?.ok_or_else(||AppError::Authentication("Organization unavailable".into()))?;
    let app: crate::models::Application = sqlx::query_as(
        "SELECT * FROM applications WHERE id=$1 AND organization=$2 AND NOT is_deleted FOR SHARE",
    )
    .bind(&app.id)
    .bind(&user.owner)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::Authentication("Application unavailable".into()))?;
    CheckService::check_signin_lockout(
        user.signin_wrong_times,
        user.last_signin_wrong_time.as_deref(),
        None,
        None,
    )?;
    CheckService::check_login_permission_conn(&mut tx, &user.id, &app.id).await?;
    KerberosService::consume(&mut tx, &org, &proof).await?;
    let created = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let mut context = serde_json::json!({"primary_factor":"kerberos","kerberos_stamp":KerberosService::configuration_stamp(&org),"kerberos_username":user.name,
        "master_stamp":crate::services::social_state_service::proof_hash(org.master_password.as_deref().unwrap_or_default()),"client_id":app.client_id});
    for key in [
        "response_type",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    ] {
        if let Some(value) = req.query::<String>(key) {
            if value.len() > 4096 {
                return Err(AppError::Validation("Invalid login parameter".into()));
            }
            context[key] = serde_json::json!(value);
        }
    }
    if req
        .query::<String>("client_id")
        .is_some_and(|v| v != app.client_id)
    {
        return Err(AppError::Authentication(
            "Application client mismatch".into(),
        ));
    }
    let additional: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_mfa WHERE user_id=$1 AND is_enabled)")
            .bind(&user.id)
            .fetch_one(&mut *tx)
            .await?;
    let (result, cookie) = if user.mfa_enabled
        || user.mfa_email_enabled
        || user.mfa_phone_enabled
        || additional
    {
        let (secret, methods) = super::password_mfa::create_primary_factor_challenge(
            &mut tx,
            &user,
            created,
            Some(app.id.clone()),
            context,
        )
        .await?;
        (
            serde_json::json!({"mfa_required":true,"mfa_types":methods,"token":"","expires_in":0}),
            Some(secret),
        )
    } else {
        (
            super::password_mfa::primary_login_result(
                depot,
                &mut tx,
                &user,
                &org,
                Some(&app),
                created,
                &context,
            )
            .await?,
            None,
        )
    };
    tx.commit().await?;
    super::social_login::set_cookie(
        res,
        "casdog_password_mfa",
        cookie.as_deref().unwrap_or_default(),
        if cookie.is_some() { 300 } else { 0 },
        origin.starts_with("https://"),
    );
    if !proof.response_token.is_empty() {
        res.headers_mut().insert(
            "www-authenticate",
            format!("Negotiate {}", proof.response_token)
                .parse()
                .map_err(|_| AppError::Internal("Invalid Kerberos response".into()))?,
        );
    }
    res.render(Json(result));
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
