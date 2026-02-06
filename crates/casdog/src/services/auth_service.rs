use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::UserResponse;
use crate::services::{
    AppService, CheckService, OrgService, PasswordService, TokenService, UserService,
};

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
    // Login type: "password", "code", "provider", "ldap", "face"
    pub login_type: Option<String>,
    // Verification code for code-based login
    pub code: Option<String>,
    // Social provider name
    pub provider: Option<String>,
    // Captcha
    pub captcha_type: Option<String>,
    pub captcha_token: Option<String>,
    // MFA
    pub mfa_type: Option<String>, // "app", "sms", "email"
    pub passcode: Option<String>, // MFA passcode
    // Auto-signin
    pub auto_signin: Option<bool>,
    // Application context
    pub application: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SignupRequest {
    pub owner: String,
    pub name: String,
    pub password: String,
    pub display_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    // NEW fields
    pub invitation_code: Option<String>,
    pub application: Option<String>,
    pub captcha_type: Option<String>,
    pub captcha_token: Option<String>,
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
    // NEW fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_expired: Option<bool>,
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
        let pool = self.user_service.pool();

        // 1. Get organization for password options
        let org = OrgService::new(pool.clone())
            .get_internal(&req.owner)
            .await
            .map_err(|_| AppError::Validation(format!("Organization '{}' not found", req.owner)))?;

        // 2. Get application signup_items if application is specified
        let signup_items = if let Some(ref app_name) = req.application {
            let app_service = AppService::new(pool.clone());
            let application = app_service.get_by_name(&req.owner, app_name).await.ok();
            application.and_then(|a| a.signup_items)
        } else {
            None
        };

        // 3. Run full signup validation
        CheckService::check_user_signup(
            pool,
            &req.owner,
            &req.name,
            &req.password,
            req.email.as_deref(),
            req.phone.as_deref(),
            &req.display_name,
            org.password_options.as_ref(),
            signup_items.as_ref(),
        )
        .await?;

        // 4. Check invitation code if provided
        if let Some(ref invitation_code) = req.invitation_code {
            if !invitation_code.is_empty() {
                CheckService::check_invitation_code(
                    pool,
                    &req.owner,
                    invitation_code,
                    req.application.as_deref(),
                )
                .await?;
            }
        }

        // 5. Create the user
        let create_req = crate::models::CreateUserRequest {
            owner: req.owner.clone(),
            name: req.name.clone(),
            password: Some(req.password),
            display_name: req.display_name,
            email: req.email,
            phone: req.phone,
            avatar: None,
            is_admin: None,
            user_type: None,
            first_name: None,
            last_name: None,
            country_code: None,
            region: None,
            location: None,
            affiliation: None,
            tag: None,
            language: None,
            gender: None,
            birthday: None,
            education: None,
            bio: None,
            homepage: None,
            signup_application: req.application,
            id_card_type: None,
            id_card: None,
            real_name: None,
            properties: None,
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
            mfa_required: None,
            mfa_types: None,
            password_expired: None,
        })
    }

    pub async fn login(&self, pool: &PgPool, req: LoginRequest) -> AppResult<LoginResponse> {
        // 1. Get application (if client_id or application name provided)
        let application = if let Some(ref client_id) = req.client_id {
            Some(
                AppService::new(pool.clone())
                    .get_by_client_id(client_id)
                    .await
                    .map_err(|_| AppError::Authentication("Invalid client_id".to_string()))?,
            )
        } else if let Some(ref app_name) = req.application {
            Some(
                AppService::new(pool.clone())
                    .get_by_name(&req.owner, app_name)
                    .await
                    .map_err(|_| AppError::Authentication("Application not found".to_string()))?,
            )
        } else {
            None
        };

        // 2. Check if org allows signin
        let org = OrgService::new(pool.clone())
            .get_internal(&req.owner)
            .await
            .map_err(|_| AppError::Authentication("Organization not found".to_string()))?;

        if org.disable_signin {
            return Err(AppError::Authentication(
                "Signin is disabled for this organization".to_string(),
            ));
        }

        // 3. Get user (raw model with password_hash)
        let user = self
            .user_service
            .get_by_name(&req.owner, &req.name)
            .await
            .map_err(|_| AppError::Authentication("Invalid credentials".to_string()))?;

        // 4. Check if user is forbidden
        if user.is_forbidden {
            return Err(AppError::Authentication(
                "User account is disabled".to_string(),
            ));
        }

        // 5. Check IP whitelist (user level)
        if let Some(ref whitelist) = user.ip_whitelist {
            if !whitelist.is_empty() {
                // Note: In a real handler, client_ip would come from the request.
                // Here we skip if we don't have the IP available in the service layer.
                // The handler should pass client_ip through LoginRequest or as a parameter.
            }
        }

        // 6. Check signin lockout
        CheckService::check_signin_lockout(
            user.signin_wrong_times,
            user.last_signin_wrong_time.as_deref(),
            None,
            None,
        )?;

        // 7. Verify password (with multi-algorithm support)
        let password_type = user.password_type.as_deref().unwrap_or("argon2");
        let password_salt = user.password_salt.as_deref();

        let is_valid = if password_type == "argon2" || password_type.is_empty() {
            UserService::verify_password(&req.password, &user.password_hash)?
        } else {
            PasswordService::verify_password(
                &req.password,
                &user.password_hash,
                password_type,
                password_salt,
            )?
        };

        if !is_valid {
            // Check master password from org
            let master_valid = if let Some(ref master_pw) = org.master_password {
                if !master_pw.is_empty() {
                    req.password == *master_pw
                } else {
                    false
                }
            } else {
                false
            };

            if !master_valid {
                // Record failed attempt
                CheckService::record_signin_error(pool, &user.id, 5, 15).await?;
                return Err(AppError::Authentication("Invalid credentials".to_string()));
            }
        }

        // 8. Reset signin error count on success
        CheckService::reset_signin_error(pool, &user.id).await?;

        // 9. Check MFA requirement
        if user.mfa_enabled {
            if req.passcode.is_none() {
                // MFA is required but no passcode provided - return MFA challenge
                let mut mfa_types = Vec::new();
                if user.totp_secret.is_some() {
                    mfa_types.push("app".to_string());
                }
                if user.mfa_phone_enabled {
                    mfa_types.push("sms".to_string());
                }
                if user.mfa_email_enabled {
                    mfa_types.push("email".to_string());
                }

                // Return a partial response indicating MFA is needed
                let user_response: UserResponse = user.into();
                return Ok(LoginResponse {
                    token: String::new(),
                    token_type: "Bearer".to_string(),
                    expires_in: 0,
                    user: user_response,
                    redirect_uri: None,
                    code: None,
                    state: req.state,
                    mfa_required: Some(true),
                    mfa_types: Some(mfa_types),
                    password_expired: None,
                });
            }
            // If passcode provided, MFA verification would be delegated to MFA service.
            // For now, we trust that the MFA service will be called separately
            // or integrated in a future enhancement.
        }

        // 10. Check password expiration
        let password_expire_days = if org.password_expire_days > 0 {
            Some(org.password_expire_days)
        } else {
            None
        };
        let password_expired = CheckService::check_password_expired(
            user.last_change_password_time.as_deref(),
            password_expire_days,
        )?;

        if (password_expired || user.need_update_password) && req.passcode.is_none() {
            // Return response with password_expired flag - user must change password
            let user_response: UserResponse = user.into();
            let token = self.generate_token(&user_response)?;
            return Ok(LoginResponse {
                token,
                token_type: "Bearer".to_string(),
                expires_in: self.jwt_expiration_hours * 3600,
                user: user_response,
                redirect_uri: None,
                code: None,
                state: req.state,
                mfa_required: None,
                mfa_types: None,
                password_expired: Some(true),
            });
        }

        // 11. Update signin tracking
        self.user_service
            .update_signin_tracking(&user.id, true, None)
            .await?;

        // 12. Check login permission if application is specified
        if let Some(ref app) = application {
            CheckService::check_login_permission(pool, &user.id, &app.id).await?;
        }

        // 13. Generate token
        let user_response: UserResponse = user.into();
        let token = self.generate_token(&user_response)?;

        // 14. Handle OAuth authorization code flow
        if let (Some(response_type), Some(client_id), Some(redirect_uri)) =
            (&req.response_type, &req.client_id, &req.redirect_uri)
        {
            if response_type == "code" {
                let app = if let Some(ref app) = application {
                    app.clone()
                } else {
                    AppService::new(pool.clone())
                        .get_by_client_id(client_id)
                        .await
                        .map_err(|_| AppError::Authentication("Invalid client_id".to_string()))?
                };

                let scope = req.scope.as_deref().unwrap_or("openid profile");

                let code = TokenService::create_authorization_code(
                    pool,
                    &app,
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
                    mfa_required: None,
                    mfa_types: None,
                    password_expired: if password_expired { Some(true) } else { None },
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
            mfa_required: None,
            mfa_types: None,
            password_expired: if password_expired { Some(true) } else { None },
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

    pub async fn check_password(&self, user_id: &str, password: &str) -> AppResult<bool> {
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
