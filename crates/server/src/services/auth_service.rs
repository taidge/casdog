use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::UserResponse;
use crate::services::UserService;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

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
        })
    }

    pub async fn login(&self, req: LoginRequest) -> AppResult<LoginResponse> {
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

        Ok(LoginResponse {
            token,
            token_type: "Bearer".to_string(),
            expires_in: self.jwt_expiration_hours * 3600,
            user: user_response,
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
}
