use chrono::Utc;
use rand::Rng;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::{
    Application, CreateTokenRequest, IntrospectResponse, OAuthTokenResponse, Token, TokenResponse,
    UpdateTokenRequest,
};
use crate::services::UserService;
use crate::services::id_token_service::IdTokenService;

pub struct TokenService;

impl TokenService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<TokenResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let (tokens, total): (Vec<Token>, i64) = if let Some(owner) = owner {
            let tokens = sqlx::query_as::<_, Token>(
                r#"SELECT * FROM tokens WHERE owner = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"#
            )
            .bind(owner)
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tokens WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?;

            (tokens, total.0)
        } else {
            let tokens = sqlx::query_as::<_, Token>(
                r#"SELECT * FROM tokens ORDER BY created_at DESC LIMIT $1 OFFSET $2"#,
            )
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tokens")
                .fetch_one(pool)
                .await?;

            (tokens, total.0)
        };

        Ok((tokens.into_iter().map(Into::into).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<TokenResponse> {
        let token = sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await?;
        Ok(token.into())
    }

    pub async fn get_by_access_token(pool: &PgPool, access_token: &str) -> AppResult<Token> {
        let token = sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE access_token = $1")
            .bind(access_token)
            .fetch_one(pool)
            .await?;
        Ok(token)
    }

    pub async fn get_by_refresh_token(pool: &PgPool, refresh_token: &str) -> AppResult<Token> {
        let token = sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE refresh_token = $1")
            .bind(refresh_token)
            .fetch_one(pool)
            .await?;
        Ok(token)
    }

    pub async fn get_by_code(pool: &PgPool, code: &str) -> AppResult<Token> {
        let token = sqlx::query_as::<_, Token>(
            "SELECT * FROM tokens WHERE code = $1 AND code_is_used = false",
        )
        .bind(code)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| {
            AppError::Authentication("Invalid or expired authorization code".to_string())
        })?;
        Ok(token)
    }

    pub async fn create(pool: &PgPool, req: CreateTokenRequest) -> AppResult<TokenResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let access_token = Self::generate_token();
        let refresh_token = Self::generate_token();
        let expires_in = req.expires_in.unwrap_or(3600 * 24); // Default 24 hours
        let scope = req.scope.unwrap_or_else(|| "openid profile".to_string());

        let token = sqlx::query_as::<_, Token>(
            r#"INSERT INTO tokens (
                id, owner, name, created_at, application, organization, user_id,
                access_token, refresh_token, expires_in, scope, token_type, code_is_used
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'Bearer', false)
            RETURNING *"#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(now)
        .bind(&req.application)
        .bind(&req.organization)
        .bind(&req.user)
        .bind(&access_token)
        .bind(&refresh_token)
        .bind(expires_in)
        .bind(&scope)
        .fetch_one(pool)
        .await?;

        Ok(token.into())
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateTokenRequest,
    ) -> AppResult<TokenResponse> {
        let token = sqlx::query_as::<_, Token>(
            r#"UPDATE tokens SET
                scope = COALESCE($2, scope),
                expires_in = COALESCE($3, expires_in)
            WHERE id = $1 RETURNING *"#,
        )
        .bind(id)
        .bind(&req.scope)
        .bind(&req.expires_in)
        .fetch_one(pool)
        .await?;

        Ok(token.into())
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM tokens WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn delete_by_access_token(pool: &PgPool, access_token: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM tokens WHERE access_token = $1")
            .bind(access_token)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn persist_issued_access_token(
        pool: &PgPool,
        owner: &str,
        name: &str,
        application: &str,
        organization: &str,
        user_id: &str,
        access_token: &str,
        expires_in: i64,
        scope: Option<&str>,
    ) -> AppResult<TokenResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let scope = scope.unwrap_or("openid profile");

        let token = sqlx::query_as::<_, Token>(
            r#"INSERT INTO tokens (
                id, owner, name, created_at, application, organization, user_id,
                access_token, expires_in, scope, token_type, code_is_used
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'Bearer', false)
            RETURNING *"#,
        )
        .bind(&id)
        .bind(owner)
        .bind(name)
        .bind(now)
        .bind(application)
        .bind(organization)
        .bind(user_id)
        .bind(access_token)
        .bind(expires_in)
        .bind(scope)
        .fetch_one(pool)
        .await?;

        Ok(token.into())
    }

    pub async fn delete_by_user(pool: &PgPool, user_id: &str) -> AppResult<u64> {
        let result = sqlx::query("DELETE FROM tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Create an authorization code for the OAuth code flow
    pub async fn create_authorization_code(
        pool: &PgPool,
        application: &Application,
        user_id: &str,
        scope: &str,
        nonce: Option<&str>,
        redirect_uri: &str,
        code_challenge: Option<&str>,
        code_challenge_method: Option<&str>,
    ) -> AppResult<String> {
        let id = Uuid::new_v4().to_string();
        let code = Self::generate_token();
        let now = Utc::now();

        sqlx::query(
            r#"INSERT INTO tokens (
                id, owner, name, created_at, application, organization, user_id,
                code, access_token, expires_in, scope, token_type,
                code_challenge, code_challenge_method, code_is_used, code_expire_in,
                nonce, redirect_uri
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '', 0, $9, 'Bearer',
                      $10, $11, false, 300, $12, $13)"#,
        )
        .bind(&id)
        .bind(&application.owner)
        .bind(&format!("code_{}", id))
        .bind(now)
        .bind(&application.name)
        .bind(&application.organization)
        .bind(user_id)
        .bind(&code)
        .bind(scope)
        .bind(code_challenge)
        .bind(code_challenge_method)
        .bind(nonce)
        .bind(redirect_uri)
        .execute(pool)
        .await?;

        Ok(code)
    }

    /// Exchange an authorization code for tokens
    pub async fn exchange_authorization_code(
        pool: &PgPool,
        application: &Application,
        code: &str,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
    ) -> AppResult<OAuthTokenResponse> {
        let token = Self::get_by_code(pool, code).await?;

        // Verify the code belongs to this application
        if token.application != application.name {
            return Err(AppError::Authentication(
                "Code does not match application".to_string(),
            ));
        }

        // Verify redirect_uri matches
        if let Some(uri) = redirect_uri {
            if let Some(ref stored_uri) = token.redirect_uri {
                if uri != stored_uri {
                    return Err(AppError::Authentication(
                        "Redirect URI mismatch".to_string(),
                    ));
                }
            }
        }

        // Verify PKCE code_challenge
        if let Some(ref challenge) = token.code_challenge {
            let verifier = code_verifier
                .ok_or_else(|| AppError::Authentication("Missing code_verifier".to_string()))?;

            let method = token.code_challenge_method.as_deref().unwrap_or("plain");
            let computed = match method {
                "S256" => {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(verifier.as_bytes());
                    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash)
                }
                _ => verifier.to_string(), // plain
            };

            if &computed != challenge {
                return Err(AppError::Authentication(
                    "PKCE verification failed".to_string(),
                ));
            }
        }

        // Check code expiration
        if let Some(code_expire) = token.code_expire_in {
            let created = token.created_at.timestamp();
            let now = Utc::now().timestamp();
            if now - created > code_expire {
                return Err(AppError::Authentication(
                    "Authorization code expired".to_string(),
                ));
            }
        }

        // Mark code as used (prevents replay attacks)
        Self::mark_code_used(pool, code).await?;

        // Generate new access_token and refresh_token
        let access_token = Self::generate_token();
        let refresh_token = Self::generate_token();
        let expires_in = application.expire_in_hours as i64 * 3600;

        sqlx::query(
            "UPDATE tokens SET access_token = $1, refresh_token = $2, expires_in = $3 WHERE id = $4",
        )
        .bind(&access_token)
        .bind(&refresh_token)
        .bind(expires_in)
        .bind(&token.id)
        .execute(pool)
        .await?;

        // Generate ID token if scope includes openid
        let id_token = if token.scope.contains("openid") {
            let id_token = IdTokenService::generate_id_token(
                pool,
                &token.user,
                &token.user,
                &application.client_id,
                token.nonce.as_deref(),
                Some(&access_token),
                application.cert.as_deref(),
            )
            .await?;
            Some(id_token)
        } else {
            None
        };

        Ok(OAuthTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: Some(refresh_token),
            scope: Some(token.scope),
            id_token,
        })
    }

    /// Refresh an access token
    pub async fn refresh_access_token(
        pool: &PgPool,
        application: &Application,
        refresh_token_str: &str,
    ) -> AppResult<OAuthTokenResponse> {
        let token = Self::get_by_refresh_token(pool, refresh_token_str)
            .await
            .map_err(|_| AppError::Authentication("Invalid refresh token".to_string()))?;

        if token.application != application.name {
            return Err(AppError::Authentication(
                "Refresh token does not match application".to_string(),
            ));
        }

        let new_access_token = Self::generate_token();
        let new_refresh_token = Self::generate_token();
        let expires_in = application.expire_in_hours as i64 * 3600;

        sqlx::query(
            "UPDATE tokens SET access_token = $1, refresh_token = $2, expires_in = $3, created_at = $4 WHERE id = $5",
        )
        .bind(&new_access_token)
        .bind(&new_refresh_token)
        .bind(expires_in)
        .bind(Utc::now())
        .bind(&token.id)
        .execute(pool)
        .await?;

        // Generate ID token if scope includes openid
        let id_token = if token.scope.contains("openid") {
            let id_token = IdTokenService::generate_id_token(
                pool,
                &token.user,
                &token.user,
                &application.client_id,
                None,
                Some(&new_access_token),
                application.cert.as_deref(),
            )
            .await?;
            Some(id_token)
        } else {
            None
        };

        Ok(OAuthTokenResponse {
            access_token: new_access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: Some(new_refresh_token),
            scope: Some(token.scope),
            id_token,
        })
    }

    /// Client credentials grant - creates a token for the application itself
    pub async fn exchange_client_credentials(
        pool: &PgPool,
        application: &Application,
        scope: Option<&str>,
    ) -> AppResult<OAuthTokenResponse> {
        let id = Uuid::new_v4().to_string();
        let access_token = Self::generate_token();
        let expires_in = application.expire_in_hours as i64 * 3600;
        let scope = scope.unwrap_or("openid profile");
        let now = Utc::now();

        sqlx::query(
            r#"INSERT INTO tokens (
                id, owner, name, created_at, application, organization, user_id,
                access_token, expires_in, scope, token_type, code_is_used
            ) VALUES ($1, $2, $3, $4, $5, $6, '', $7, $8, $9, 'Bearer', false)"#,
        )
        .bind(&id)
        .bind(&application.owner)
        .bind(&format!("client_cred_{}", id))
        .bind(now)
        .bind(&application.name)
        .bind(&application.organization)
        .bind(&access_token)
        .bind(expires_in)
        .bind(scope)
        .execute(pool)
        .await?;

        Ok(OAuthTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: None,
            scope: Some(scope.to_string()),
            id_token: None,
        })
    }

    /// Password grant - authenticates user and creates tokens
    pub async fn exchange_password(
        pool: &PgPool,
        application: &Application,
        username: &str,
        password: &str,
        scope: Option<&str>,
    ) -> AppResult<OAuthTokenResponse> {
        // Find and verify user
        let user = sqlx::query_as::<_, (String, String, String)>(
            "SELECT id, name, password_hash FROM users WHERE name = $1 AND owner = $2 AND is_deleted = FALSE"
        )
        .bind(username)
        .bind(&application.organization)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::Authentication("Invalid credentials".to_string()))?;

        let (user_id, user_name, password_hash) = user;

        if !UserService::verify_password(password, &password_hash)? {
            return Err(AppError::Authentication("Invalid credentials".to_string()));
        }

        let id = Uuid::new_v4().to_string();
        let access_token = Self::generate_token();
        let refresh_token = Self::generate_token();
        let expires_in = application.expire_in_hours as i64 * 3600;
        let scope = scope.unwrap_or("openid profile");
        let now = Utc::now();

        sqlx::query(
            r#"INSERT INTO tokens (
                id, owner, name, created_at, application, organization, user_id,
                access_token, refresh_token, expires_in, scope, token_type, code_is_used
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'Bearer', false)"#,
        )
        .bind(&id)
        .bind(&application.owner)
        .bind(&format!("password_{}", id))
        .bind(now)
        .bind(&application.name)
        .bind(&application.organization)
        .bind(&user_id)
        .bind(&access_token)
        .bind(&refresh_token)
        .bind(expires_in)
        .bind(scope)
        .execute(pool)
        .await?;

        // Generate ID token if scope includes openid
        let id_token = if scope.contains("openid") {
            let id_token = IdTokenService::generate_id_token(
                pool,
                &user_id,
                &user_name,
                &application.client_id,
                None,
                Some(&access_token),
                application.cert.as_deref(),
            )
            .await?;
            Some(id_token)
        } else {
            None
        };

        Ok(OAuthTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: Some(refresh_token),
            scope: Some(scope.to_string()),
            id_token,
        })
    }

    /// RFC 7662 Token Introspection
    pub async fn introspect_token(
        pool: &PgPool,
        token_str: &str,
        token_type_hint: Option<&str>,
    ) -> AppResult<IntrospectResponse> {
        let config = AppConfig::get();
        let issuer = format!("http://{}:{}", config.server.host, config.server.port);

        // Try to find by access_token first, then refresh_token
        let token = match token_type_hint {
            Some("refresh_token") => Self::get_by_refresh_token(pool, token_str).await.ok(),
            _ => {
                let t = Self::get_by_access_token(pool, token_str).await.ok();
                if t.is_none() {
                    Self::get_by_refresh_token(pool, token_str).await.ok()
                } else {
                    t
                }
            }
        };

        match token {
            Some(t) => {
                let created = t.created_at.timestamp();
                let exp = created + t.expires_in;
                let is_active = Utc::now().timestamp() < exp;

                Ok(IntrospectResponse {
                    active: is_active,
                    scope: Some(t.scope),
                    client_id: Some(t.application.clone()),
                    username: Some(t.user),
                    token_type: Some(t.token_type),
                    exp: Some(exp),
                    iat: Some(created),
                    sub: None,
                    aud: Some(t.application),
                    iss: Some(issuer),
                })
            }
            None => Ok(IntrospectResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                token_type: None,
                exp: None,
                iat: None,
                sub: None,
                aud: None,
                iss: None,
            }),
        }
    }

    /// Revoke a token
    pub async fn revoke_token(
        pool: &PgPool,
        token_str: &str,
        token_type_hint: Option<&str>,
    ) -> AppResult<()> {
        match token_type_hint {
            Some("refresh_token") => {
                sqlx::query("DELETE FROM tokens WHERE refresh_token = $1")
                    .bind(token_str)
                    .execute(pool)
                    .await?;
            }
            _ => {
                let result = sqlx::query("DELETE FROM tokens WHERE access_token = $1")
                    .bind(token_str)
                    .execute(pool)
                    .await?;
                if result.rows_affected() == 0 {
                    sqlx::query("DELETE FROM tokens WHERE refresh_token = $1")
                        .bind(token_str)
                        .execute(pool)
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// Mark an authorization code as used (prevents replay attacks)
    pub async fn mark_code_used(pool: &PgPool, code: &str) -> AppResult<()> {
        sqlx::query(
            "UPDATE tokens SET code_is_used = true WHERE code = $1 AND code_is_used = false",
        )
        .bind(code)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Expire/revoke all tokens for a specific user
    pub async fn expire_tokens_by_user(pool: &PgPool, user_id: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Expire/revoke all tokens for a specific application
    pub async fn expire_tokens_by_application(pool: &PgPool, app_name: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM tokens WHERE application = $1")
            .bind(app_name)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub fn generate_token() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
    }
}
