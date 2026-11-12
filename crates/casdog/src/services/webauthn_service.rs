use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::*;

use crate::error::{AppError, AppResult};
use crate::hoops::auth::session_fingerprint;
use crate::services::auth_service::Claims;

pub struct WebauthnService {
    webauthn: Arc<Webauthn>,
}

impl WebauthnService {
    pub fn new(
        rp_id: &str,
        rp_origin: &webauthn_rs::prelude::Url,
        rp_name: &str,
    ) -> AppResult<Self> {
        let builder = WebauthnBuilder::new(rp_id, rp_origin)
            .map_err(|e| AppError::Internal(format!("WebAuthn builder error: {}", e)))?
            .rp_name(rp_name);

        let webauthn = Arc::new(
            builder
                .build()
                .map_err(|e| AppError::Internal(format!("WebAuthn build error: {}", e)))?,
        );

        Ok(Self { webauthn })
    }

    /// Begin registration - returns creation challenge and registration state
    pub fn start_registration(
        &self,
        user_id: &[u8],
        user_name: &str,
        user_display_name: &str,
        existing_credentials: Option<Vec<CredentialID>>,
    ) -> AppResult<(CreationChallengeResponse, PasskeyRegistration)> {
        let digest = Sha256::digest(user_id);
        let uuid = uuid::Uuid::from_bytes(digest[..16].try_into().unwrap());

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(uuid, user_name, user_display_name, existing_credentials)
            .map_err(|e| AppError::Internal(format!("WebAuthn registration start error: {}", e)))?;

        Ok((ccr, reg_state))
    }

    /// Finish registration - verify the response and return the credential
    pub fn finish_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> AppResult<Passkey> {
        let cred = self
            .webauthn
            .finish_passkey_registration(reg, state)
            .map_err(|e| {
                AppError::Validation(format!(
                    "WebAuthn registration could not be verified: {}",
                    e
                ))
            })?;

        Ok(cred)
    }

    /// Begin authentication
    pub fn start_authentication(
        &self,
        credentials: &[Passkey],
    ) -> AppResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(credentials)
            .map_err(|e| {
                AppError::Internal(format!("WebAuthn authentication start error: {}", e))
            })?;

        Ok((rcr, auth_state))
    }

    /// Finish authentication
    pub fn finish_authentication(
        &self,
        auth: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> AppResult<AuthenticationResult> {
        let result = self
            .webauthn
            .finish_passkey_authentication(auth, state)
            .map_err(|e| {
                AppError::Authentication(format!(
                    "WebAuthn authentication could not be verified: {}",
                    e
                ))
            })?;

        Ok(result)
    }

    /// Store a WebAuthn credential in the database
    pub async fn save_credential(
        pool: &PgPool,
        user_id: &str,
        credential: &Passkey,
        name: &str,
    ) -> AppResult<()> {
        let mut transaction = pool.begin().await?;
        Self::save_credential_conn(&mut transaction, user_id, credential, name).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn save_credential_conn(
        connection: &mut PgConnection,
        user_id: &str,
        credential: &Passkey,
        name: &str,
    ) -> AppResult<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let cred_json = serde_json::to_string(credential)
            .map_err(|e| AppError::Internal(format!("Credential serialization error: {}", e)))?;
        let encoded_id = serde_json::to_value(credential)
            .map_err(|e| AppError::Internal(e.to_string()))?["cred"]["cred_id"]
            .as_str()
            .ok_or_else(|| AppError::Internal("Credential ID missing".into()))?
            .to_string();
        // The lock also covers credentials imported before this migration.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("webauthn:{encoded_id}"))
            .execute(&mut *connection)
            .await?;
        let duplicate: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_webauthn_credentials WHERE credential_data::jsonb #>> '{cred,cred_id}'=$1)")
            .bind(&encoded_id).fetch_one(&mut *connection).await?;
        if duplicate {
            return Err(AppError::Conflict(
                "This passkey is already registered".into(),
            ));
        }

        sqlx::query(
            r#"INSERT INTO user_webauthn_credentials (id, user_id, name, credential_data, created_at)
            VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(name)
        .bind(&cred_json)
        .bind(now)
        .execute(&mut *connection)
        .await?;

        Ok(())
    }

    /// Store a registration challenge under the authenticated account lock.
    pub async fn begin_registration_state(
        pool: &PgPool,
        claims: &Claims,
        token: &str,
        origin: &str,
        state: &PasskeyRegistration,
    ) -> AppResult<String> {
        let mut transaction = pool.begin().await?;
        Self::validate_registration_session(&mut transaction, claims, token).await?;
        sqlx::query("DELETE FROM webauthn_challenges WHERE expires_at<=clock_timestamp()")
            .execute(&mut *transaction)
            .await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM webauthn_challenges WHERE user_id=$1 AND purpose='registration'",
        )
        .bind(&claims.sub)
        .fetch_one(&mut *transaction)
        .await?;
        if count >= 20 {
            return Err(AppError::Validation(
                "Too many pending passkey registrations. Try again in five minutes.".into(),
            ));
        }
        let request_id = uuid::Uuid::new_v4().to_string();
        let state = serde_json::to_value(state).map_err(|e| AppError::Internal(e.to_string()))?;
        sqlx::query("INSERT INTO webauthn_challenges(request_id,user_id,owner,purpose,origin,session_hash,state) VALUES($1,$2,$3,'registration',$4,$5,$6)")
            .bind(&request_id).bind(&claims.sub).bind(&claims.owner).bind(origin)
            .bind(session_fingerprint(token)).bind(state).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(request_id)
    }

    /// Consume and persist in one transaction. Invalid attestation also retires
    /// its challenge, while an unrelated account cannot consume another's state.
    pub async fn complete_registration(
        &self,
        pool: &PgPool,
        claims: &Claims,
        token: &str,
        origin: &str,
        request_id: &str,
        credential: Value,
        name: &str,
    ) -> AppResult<()> {
        let mut transaction = pool.begin().await?;
        Self::validate_registration_session(&mut transaction, claims, token).await?;
        let state: Option<Value> = sqlx::query_scalar("DELETE FROM webauthn_challenges WHERE request_id=$1 AND user_id=$2 AND owner=$3 AND purpose='registration' AND origin=$4 AND session_hash=$5 AND expires_at>clock_timestamp() RETURNING state")
            .bind(request_id).bind(&claims.sub).bind(&claims.owner).bind(origin)
            .bind(session_fingerprint(token)).fetch_optional(&mut *transaction).await?;
        let state = state.ok_or_else(|| {
            AppError::Validation("Unknown or expired registration request".into())
        })?;
        let verify = || -> AppResult<Passkey> {
            let state: PasskeyRegistration = serde_json::from_value(state)
                .map_err(|e| AppError::Internal(format!("Invalid stored WebAuthn state: {e}")))?;
            let credential = serde_json::from_value(credential)
                .map_err(|e| AppError::Validation(format!("Invalid registration payload: {e}")))?;
            self.finish_registration(&credential, &state)
        };
        let passkey = match verify() {
            Ok(passkey) => passkey,
            Err(error) => {
                transaction.commit().await?;
                return Err(error);
            }
        };
        Self::save_credential_conn(&mut transaction, &claims.sub, &passkey, name).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn validate_registration_session(
        connection: &mut PgConnection,
        claims: &Claims,
        token: &str,
    ) -> AppResult<()> {
        let denied =
            || AppError::Authentication("Sign in again before registering a passkey".into());
        let row: Option<(Option<String>,)> = sqlx::query_as("SELECT last_change_password_time FROM users WHERE id=$1 AND owner=$2 AND NOT is_deleted AND NOT is_forbidden FOR UPDATE")
            .bind(&claims.sub).bind(&claims.owner).fetch_optional(&mut *connection).await?;
        let (changed,) = row.ok_or_else(denied)?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *connection)
            .await?;
        let issued = claims.issued_at_ms.unwrap_or(claims.iat * 1000);
        if claims.impersonator_user_id.is_some()
            || claims.exp <= now.timestamp()
            || issued > now.timestamp_millis()
            || now.timestamp_millis() - issued > 300_000
        {
            return Err(denied());
        }
        if let Some(changed) = changed.filter(|value| !value.is_empty()) {
            let changed = DateTime::parse_from_rfc3339(&changed).map_err(|_| denied())?;
            if issued <= changed.timestamp_millis() {
                return Err(denied());
            }
        }
        let valid: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM revoked_session_tokens WHERE token_hash=$1 AND expires_at>clock_timestamp()) AND NOT EXISTS(SELECT 1 FROM user_session_epochs WHERE user_id=$2 AND invalid_before>=to_timestamp($3::double precision/1000)) AND EXISTS(SELECT 1 FROM organizations WHERE name=$4 AND NOT is_deleted AND NOT disable_signin)")
            .bind(session_fingerprint(token)).bind(&claims.sub).bind(issued as f64).bind(&claims.owner)
            .fetch_one(&mut *connection).await?;
        if !valid {
            return Err(denied());
        }
        Ok(())
    }

    /// Get all WebAuthn credentials for a user
    pub async fn get_credentials(pool: &PgPool, user_id: &str) -> AppResult<Vec<Passkey>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT credential_data FROM user_webauthn_credentials WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;

        let credentials: Vec<Passkey> = rows
            .iter()
            .filter_map(|(json,)| serde_json::from_str(json).ok())
            .collect();

        Ok(credentials)
    }

    /// Delete a WebAuthn credential
    pub async fn delete_credential(pool: &PgPool, id: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM user_webauthn_credentials WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }
}
