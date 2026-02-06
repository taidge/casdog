use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::UserResponse;
use crate::services::UserService;
use crate::services::TokenService;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct Claims {
    pub sub: String,
    pub owner: String,
    pub name: String,
    pub is_admin: bool,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub owner: String,
    pub name: String,
    pub password: String,
    // OAuth context fields
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SignupRequest {
    pub owner: String,
    pub name: String,
    pub password: String,
    pub display_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetPasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CheckPasswordRequest {
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CheckPasswordResponse {
    pub valid: bool,
}

#[derive(Clone)]
pub struct AuthService {
    user_service: UserService,
    jwt_secret: String,
    jwt_expiration_hours: i64,
    jwt_issuer: String,
}

impl AuthService {
    pub fn new(user_service: UserService) -> Self {
        let config = AppConfig::get();
        Self {
            user_service,
            jwt_secret: config.jwt.secret,
            jwt_expiration_hours: config.jwt.expiration_hours,
            jwt_issuer: config.jwt.issuer,
        }
    }

    pub async fn signup(&self, req: SignupRequest) -> AppResult<LoginResponse> {
        let create_req = crate::models::CreateUserRequest {
            owner: req.owner.clone(),
            name: req.name.clone(),
            password: req.password,
            display_name: req.display_name,
            email: req.email,
            phone: req.phone,
            avatar: None,
            is_admin: None,
        };

        let user = self.user_service.create(create_req).await?;
        let token = self.generate_token(&user)?;

        Ok(LoginResponse {
            token,
            token_type: "Bearer".to_string(),
            expires_in: self.jwt_expiration_hours * 3600,
            user,
            redirect_uri: None,
            code: None,
            state: None,
        })
    }

    pub async fn login(&self, pool: &PgPool, req: LoginRequest) -> AppResult<LoginResponse> {
        let user = self
            .user_service
            .get_by_name(&req.owner, &req.name)
            .await
            .map_err(|_| AppError::Authentication("Invalid credentials".to_string()))?;

        let is_valid = UserService::verify_password(&req.password, &user.password_hash)?;
        if !is_valid {
            return Err(AppError::Authentication("Invalid credentials".to_string()));
        }

        let user_response: UserResponse = user.into();
        let token = self.generate_token(&user_response)?;

        // If OAuth context is present, generate authorization code
        if let (Some(response_type), Some(client_id), Some(redirect_uri)) =
            (&req.response_type, &req.client_id, &req.redirect_uri)
        {
            if response_type == "code" {
                let app = crate::services::AppService::new(pool.clone());
                let application = app.get_by_client_id(client_id).await
                    .map_err(|_| AppError::Authentication("Invalid client_id".to_string()))?;

                let scope = req.scope.as_deref().unwrap_or("openid profile");

                let code = TokenService::create_authorization_code(
                    pool,
                    &application,
                    &user_response.id,
                    scope,
                    req.nonce.as_deref(),
                    redirect_uri,
                    req.code_challenge.as_deref(),
                    req.code_challenge_method.as_deref(),
                )
                .await?;

                return Ok(LoginResponse {
                    token,
                    token_type: "Bearer".to_string(),
                    expires_in: self.jwt_expiration_hours * 3600,
                    user: user_response,
                    redirect_uri: Some(redirect_uri.clone()),
                    code: Some(code),
                    state: req.state.clone(),
                });
            }
        }

        Ok(LoginResponse {
            token,
            token_type: "Bearer".to_string(),
            expires_in: self.jwt_expiration_hours * 3600,
            user: user_response,
            redirect_uri: None,
            code: None,
            state: None,
        })
    }

    pub fn generate_token(&self, user: &UserResponse) -> AppResult<String> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.jwt_expiration_hours);

        let claims = Claims {
            sub: user.id.clone(),
            owner: user.owner.clone(),
            name: user.name.clone(),
            is_admin: user.is_admin,
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: self.jwt_issuer.clone(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )?;

        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> AppResult<Claims> {
        let validation = Validation::default();
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )?;

        Ok(token_data.claims)
    }

    pub async fn get_account(&self, user_id: &str) -> AppResult<UserResponse> {
        self.user_service.get_by_id(user_id).await
    }

    pub async fn set_password(
        &self,
        user_id: &str,
        old_password: &str,
        new_password: &str,
    ) -> AppResult<()> {
        let user = self.user_service.get_by_id_internal(user_id).await?;

        let is_valid = UserService::verify_password(old_password, &user.password_hash)?;
        if !is_valid {
            return Err(AppError::Authentication("Invalid old password".to_string()));
        }

        let new_hash = UserService::hash_password(new_password)?;
        sqlx::query("UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3")
            .bind(&new_hash)
            .bind(Utc::now())
            .bind(user_id)
            .execute(self.user_service.pool())
            .await?;

        Ok(())
    }

    pub async fn check_password(
        &self,
        user_id: &str,
        password: &str,
    ) -> AppResult<bool> {
        let user = self.user_service.get_by_id_internal(user_id).await?;
        UserService::verify_password(password, &user.password_hash)
    }

    pub async fn sso_logout(pool: &PgPool, user_id: &str) -> AppResult<()> {
        // Delete all tokens for this user
        TokenService::delete_by_user(pool, user_id).await?;
        // Delete all sessions for this user
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await?;
        Ok(())
    }
}
