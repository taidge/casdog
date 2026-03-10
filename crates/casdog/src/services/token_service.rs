use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand::Rng;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::{
    Application, CreateTokenRequest, IntrospectResponse, OAuthTokenResponse, Token, TokenResponse,
    UpdateTokenRequest,
};
use crate::schema::tokens;
use crate::services::UserService;
use crate::services::id_token_service::IdTokenService;

pub struct TokenService;

impl TokenService {
    pub async fn list(
        pool: &DieselPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<TokenResponse>, i64)> {
        let offset = (page - 1) * page_size;
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let (token_list, total): (Vec<Token>, i64) = if let Some(owner) = owner {
            let token_list = tokens::table
                .filter(tokens::owner.eq(owner))
                .order(tokens::created_at.desc())
                .limit(page_size)
                .offset(offset)
                .select(Token::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let total: i64 = tokens::table
                .filter(tokens::owner.eq(owner))
                .count()
                .get_result(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            (token_list, total)
        } else {
            let token_list = tokens::table
                .order(tokens::created_at.desc())
                .limit(page_size)
                .offset(offset)
                .select(Token::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let total: i64 = tokens::table
                .count()
                .get_result(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            (token_list, total)
        };

        Ok((token_list.into_iter().map(Into::into).collect(), total))
    }

    pub async fn get_by_id(pool: &DieselPool, id: &str) -> AppResult<TokenResponse> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let token = tokens::table
            .filter(tokens::id.eq(id))
            .select(Token::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(token.into())
    }

    pub async fn get_by_access_token(pool: &DieselPool, access_token: &str) -> AppResult<Token> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let token = tokens::table
            .filter(tokens::access_token.eq(access_token))
            .select(Token::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(token)
    }

    pub async fn get_by_refresh_token(pool: &DieselPool, refresh_token: &str) -> AppResult<Token> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let token = tokens::table
            .filter(tokens::refresh_token.eq(refresh_token))
            .select(Token::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(token)
    }

    pub async fn get_by_code(pool: &DieselPool, code: &str) -> AppResult<Token> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let token = tokens::table
            .filter(tokens::code.eq(code))
            .filter(tokens::code_is_used.eq(false))
            .select(Token::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| {
                AppError::Authentication("Invalid or expired authorization code".to_string())
            })?;

        Ok(token)
    }

    pub async fn create(pool: &DieselPool, req: CreateTokenRequest) -> AppResult<TokenResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let access_token = Self::generate_token();
        let refresh_token = Self::generate_token();
        let expires_in = req.expires_in.unwrap_or(3600 * 24);
        let scope = req.scope.unwrap_or_else(|| "openid profile".to_string());

        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let token = diesel::insert_into(tokens::table)
            .values((
                tokens::id.eq(&id),
                tokens::owner.eq(&req.owner),
                tokens::name.eq(&req.name),
                tokens::created_at.eq(now),
                tokens::application.eq(&req.application),
                tokens::organization.eq(&req.organization),
                tokens::user_id.eq(&req.user),
                tokens::access_token.eq(&access_token),
                tokens::refresh_token.eq(&refresh_token),
                tokens::expires_in.eq(expires_in),
                tokens::scope.eq(&scope),
                tokens::token_type.eq("Bearer"),
                tokens::code_is_used.eq(false),
            ))
            .returning(Token::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(token.into())
    }

    pub async fn update(
        pool: &DieselPool,
        id: &str,
        req: UpdateTokenRequest,
    ) -> AppResult<TokenResponse> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        // Fetch current token, apply changes, write back
        let mut token = tokens::table
            .filter(tokens::id.eq(id))
            .select(Token::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        if let Some(ref scope) = req.scope {
            token.scope = scope.clone();
        }
        if let Some(expires_in) = req.expires_in {
            token.expires_in = expires_in;
        }

        let token = diesel::update(tokens::table.filter(tokens::id.eq(id)))
            .set((
                tokens::scope.eq(&token.scope),
                tokens::expires_in.eq(token.expires_in),
            ))
            .returning(Token::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(token.into())
    }

    pub async fn delete(pool: &DieselPool, id: &str) -> AppResult<()> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::delete(tokens::table.filter(tokens::id.eq(id)))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(())
    }

    pub async fn delete_by_access_token(pool: &DieselPool, access_token: &str) -> AppResult<()> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::delete(tokens::table.filter(tokens::access_token.eq(access_token)))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(())
    }

    pub async fn persist_issued_access_token(
        pool: &DieselPool,
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

        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let token = diesel::insert_into(tokens::table)
            .values((
                tokens::id.eq(&id),
                tokens::owner.eq(owner),
                tokens::name.eq(name),
                tokens::created_at.eq(now),
                tokens::application.eq(application),
                tokens::organization.eq(organization),
                tokens::user_id.eq(user_id),
                tokens::access_token.eq(access_token),
                tokens::expires_in.eq(expires_in),
                tokens::scope.eq(scope),
                tokens::token_type.eq("Bearer"),
                tokens::code_is_used.eq(false),
            ))
            .returning(Token::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(token.into())
    }

    pub async fn delete_by_user(pool: &DieselPool, user_id: &str) -> AppResult<u64> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let count = diesel::delete(tokens::table.filter(tokens::user_id.eq(user_id)))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(count as u64)
    }

    /// Create an authorization code for the OAuth code flow
    pub async fn create_authorization_code(
        pool: &DieselPool,
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

        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::insert_into(tokens::table)
            .values((
                tokens::id.eq(&id),
                tokens::owner.eq(&application.owner),
                tokens::name.eq(&format!("code_{}", id)),
                tokens::created_at.eq(now),
                tokens::application.eq(&application.name),
                tokens::organization.eq(&application.organization),
                tokens::user_id.eq(user_id),
                tokens::code.eq(&code),
                tokens::access_token.eq(""),
                tokens::expires_in.eq(0i64),
                tokens::scope.eq(scope),
                tokens::token_type.eq("Bearer"),
                tokens::code_challenge.eq(code_challenge),
                tokens::code_challenge_method.eq(code_challenge_method),
                tokens::code_is_used.eq(false),
                tokens::code_expire_in.eq(Some(300i64)),
                tokens::nonce.eq(nonce),
                tokens::redirect_uri.eq(Some(redirect_uri)),
            ))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(code)
    }

    /// Exchange an authorization code for tokens
    pub async fn exchange_authorization_code(
        pool: &DieselPool,
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

        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::update(tokens::table.filter(tokens::id.eq(&token.id)))
            .set((
                tokens::access_token.eq(&access_token),
                tokens::refresh_token.eq(&refresh_token),
                tokens::expires_in.eq(expires_in),
            ))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

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
        pool: &DieselPool,
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

        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::update(tokens::table.filter(tokens::id.eq(&token.id)))
            .set((
                tokens::access_token.eq(&new_access_token),
                tokens::refresh_token.eq(&new_refresh_token),
                tokens::expires_in.eq(expires_in),
                tokens::created_at.eq(Utc::now()),
            ))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

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
        pool: &DieselPool,
        application: &Application,
        scope: Option<&str>,
    ) -> AppResult<OAuthTokenResponse> {
        let id = Uuid::new_v4().to_string();
        let access_token = Self::generate_token();
        let expires_in = application.expire_in_hours as i64 * 3600;
        let scope = scope.unwrap_or("openid profile");
        let now = Utc::now();

        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::insert_into(tokens::table)
            .values((
                tokens::id.eq(&id),
                tokens::owner.eq(&application.owner),
                tokens::name.eq(&format!("client_cred_{}", id)),
                tokens::created_at.eq(now),
                tokens::application.eq(&application.name),
                tokens::organization.eq(&application.organization),
                tokens::user_id.eq(""),
                tokens::access_token.eq(&access_token),
                tokens::expires_in.eq(expires_in),
                tokens::scope.eq(scope),
                tokens::token_type.eq("Bearer"),
                tokens::code_is_used.eq(false),
            ))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

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
        pool: &DieselPool,
        application: &Application,
        username: &str,
        password: &str,
        scope: Option<&str>,
    ) -> AppResult<OAuthTokenResponse> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        // Find and verify user
        use crate::schema::users;
        let user_row: (String, String, String) = users::table
            .filter(users::name.eq(username))
            .filter(users::owner.eq(&application.organization))
            .filter(users::is_deleted.eq(false))
            .select((users::id, users::name, users::password_hash))
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::Authentication("Invalid credentials".to_string()))?;

        let (user_id, user_name, password_hash) = user_row;

        if !UserService::verify_password(password, &password_hash)? {
            return Err(AppError::Authentication("Invalid credentials".to_string()));
        }

        let id = Uuid::new_v4().to_string();
        let access_token = Self::generate_token();
        let refresh_token = Self::generate_token();
        let expires_in = application.expire_in_hours as i64 * 3600;
        let scope = scope.unwrap_or("openid profile");
        let now = Utc::now();

        diesel::insert_into(tokens::table)
            .values((
                tokens::id.eq(&id),
                tokens::owner.eq(&application.owner),
                tokens::name.eq(&format!("password_{}", id)),
                tokens::created_at.eq(now),
                tokens::application.eq(&application.name),
                tokens::organization.eq(&application.organization),
                tokens::user_id.eq(&user_id),
                tokens::access_token.eq(&access_token),
                tokens::refresh_token.eq(&refresh_token),
                tokens::expires_in.eq(expires_in),
                tokens::scope.eq(scope),
                tokens::token_type.eq("Bearer"),
                tokens::code_is_used.eq(false),
            ))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

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
        pool: &DieselPool,
        token_str: &str,
        token_type_hint: Option<&str>,
    ) -> AppResult<IntrospectResponse> {
        let config = AppConfig::get();
        let issuer = format!("http://{}:{}", config.server.host, config.server.port);

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
        pool: &DieselPool,
        token_str: &str,
        token_type_hint: Option<&str>,
    ) -> AppResult<()> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        match token_type_hint {
            Some("refresh_token") => {
                diesel::delete(tokens::table.filter(tokens::refresh_token.eq(token_str)))
                    .execute(&mut conn)
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;
            }
            _ => {
                let count =
                    diesel::delete(tokens::table.filter(tokens::access_token.eq(token_str)))
                        .execute(&mut conn)
                        .await
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                if count == 0 {
                    diesel::delete(tokens::table.filter(tokens::refresh_token.eq(token_str)))
                        .execute(&mut conn)
                        .await
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                }
            }
        }
        Ok(())
    }

    /// Mark an authorization code as used (prevents replay attacks)
    pub async fn mark_code_used(pool: &DieselPool, code: &str) -> AppResult<()> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::update(
            tokens::table
                .filter(tokens::code.eq(code))
                .filter(tokens::code_is_used.eq(false)),
        )
        .set(tokens::code_is_used.eq(true))
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Expire/revoke all tokens for a specific user
    pub async fn expire_tokens_by_user(pool: &DieselPool, user_id: &str) -> AppResult<()> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::delete(tokens::table.filter(tokens::user_id.eq(user_id)))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Expire/revoke all tokens for a specific application
    pub async fn expire_tokens_by_application(pool: &DieselPool, app_name: &str) -> AppResult<()> {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::delete(tokens::table.filter(tokens::application.eq(app_name)))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(())
    }

    pub fn generate_token() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
    }
}
