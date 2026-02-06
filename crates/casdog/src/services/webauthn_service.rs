use crate::error::{AppError, AppResult};
use sqlx::PgPool;
use std::sync::Arc;
use webauthn_rs::prelude::*;
use webauthn_rs::Webauthn;

pub struct WebauthnService {
    webauthn: Arc<Webauthn>,
}

impl WebauthnService {
    pub fn new(rp_id: &str, rp_origin: &webauthn_rs::prelude::Url, rp_name: &str) -> AppResult<Self> {
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
        let uuid = uuid::Uuid::from_slice(
            &{
                let mut buf = [0u8; 16];
                let len = user_id.len().min(16);
                buf[..len].copy_from_slice(&user_id[..len]);
                buf
            }
        ).unwrap_or_else(|_| uuid::Uuid::new_v4());

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(
                uuid,
                user_name,
                user_display_name,
                existing_credentials,
            )
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
            .map_err(|e| AppError::Internal(format!("WebAuthn registration finish error: {}", e)))?;

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
            .map_err(|e| AppError::Internal(format!("WebAuthn authentication start error: {}", e)))?;

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
            .map_err(|e| AppError::Internal(format!("WebAuthn authentication finish error: {}", e)))?;

        Ok(result)
    }

    /// Store a WebAuthn credential in the database
    pub async fn save_credential(
        pool: &PgPool,
        user_id: &str,
        credential: &Passkey,
        name: &str,
    ) -> AppResult<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let cred_json = serde_json::to_string(credential)
            .map_err(|e| AppError::Internal(format!("Credential serialization error: {}", e)))?;

        sqlx::query(
            r#"INSERT INTO user_webauthn_credentials (id, user_id, name, credential_data, created_at)
            VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(name)
        .bind(&cred_json)
        .bind(now)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get all WebAuthn credentials for a user
    pub async fn get_credentials(pool: &PgPool, user_id: &str) -> AppResult<Vec<Passkey>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT credential_data FROM user_webauthn_credentials WHERE user_id = $1"
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
