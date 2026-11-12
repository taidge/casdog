use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::config::AppConfig;
use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::UserResponse;
use crate::services::mfa_service::MfaService;
use crate::services::{
    AppService, CheckService, OrgService, PasswordService, TokenService, UserService,
};

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct Claims {
    pub sub: String,
    pub owner: String,
    pub name: String,
    pub is_admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonator_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonator_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonator_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonation_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonation_application: Option<String>,
    pub exp: i64,
    pub iat: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    pub iss: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(try_from = "LoginRequestInput")]
pub struct LoginRequest {
    #[serde(alias = "organization")]
    pub owner: String,
    #[serde(alias = "username")]
    pub name: String,
    pub password: String,
    // OAuth context fields
    #[serde(alias = "responseType")]
    pub response_type: Option<String>,
    #[serde(alias = "clientId")]
    pub client_id: Option<String>,
    #[serde(alias = "redirectUri")]
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    #[serde(alias = "codeChallenge")]
    pub code_challenge: Option<String>,
    #[serde(alias = "codeChallengeMethod")]
    pub code_challenge_method: Option<String>,
    // Login type: "password", "code", "provider", "ldap", "face"
    #[serde(alias = "type")]
    pub login_type: Option<String>,
    // Verification code for code-based login
    pub code: Option<String>,
    #[serde(alias = "codeMethod")]
    pub code_method: Option<String>,
    // Social provider name
    pub provider: Option<String>,
    // Captcha
    #[serde(alias = "captchaType")]
    pub captcha_type: Option<String>,
    #[serde(alias = "captchaToken")]
    pub captcha_token: Option<String>,
    // MFA
    #[serde(alias = "mfaType")]
    pub mfa_type: Option<String>, // "app", "sms", "email"
    pub passcode: Option<String>, // MFA passcode
    // Auto-signin
    #[serde(alias = "autoSignin")]
    pub auto_signin: Option<bool>,
    // Application context
    pub application: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(try_from = "SignupRequestInput")]
pub struct SignupRequest {
    #[serde(alias = "organization")]
    pub owner: String,
    #[serde(alias = "username")]
    pub name: String,
    pub password: String,
    #[serde(alias = "displayName")]
    pub display_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    // NEW fields
    #[serde(alias = "invitationCode")]
    pub invitation_code: Option<String>,
    pub application: Option<String>,
    #[serde(alias = "captchaType")]
    pub captcha_type: Option<String>,
    #[serde(alias = "captchaToken")]
    pub captcha_token: Option<String>,
}

#[derive(Deserialize)]
struct LoginRequestInput {
    owner: Option<String>,
    organization: Option<String>,
    name: Option<String>,
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    // OAuth context fields
    #[serde(alias = "responseType")]
    response_type: Option<String>,
    #[serde(alias = "clientId")]
    client_id: Option<String>,
    #[serde(alias = "redirectUri")]
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    #[serde(alias = "codeChallenge")]
    code_challenge: Option<String>,
    #[serde(alias = "codeChallengeMethod")]
    code_challenge_method: Option<String>,
    // Login type: "password", "code", "provider", "ldap", "face"
    #[serde(alias = "type")]
    login_type: Option<String>,
    #[serde(alias = "signinMethod")]
    signin_method: Option<String>,
    // Verification code for code-based login
    code: Option<String>,
    #[serde(alias = "codeMethod")]
    code_method: Option<String>,
    // Social provider name
    provider: Option<String>,
    // Captcha
    #[serde(alias = "captchaType")]
    captcha_type: Option<String>,
    #[serde(alias = "captchaToken")]
    captcha_token: Option<String>,
    // MFA
    #[serde(alias = "mfaType")]
    mfa_type: Option<String>, // "app", "sms", "email"
    passcode: Option<String>, // MFA passcode
    // Auto-signin
    #[serde(alias = "autoSignin")]
    auto_signin: Option<bool>,
    // Application context
    application: Option<String>,
}

#[derive(Deserialize)]
struct SignupRequestInput {
    owner: Option<String>,
    organization: Option<String>,
    name: Option<String>,
    username: Option<String>,
    password: String,
    #[serde(alias = "displayName")]
    display_name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    // NEW fields
    #[serde(alias = "invitationCode")]
    invitation_code: Option<String>,
    application: Option<String>,
    #[serde(alias = "captchaType")]
    captcha_type: Option<String>,
    #[serde(alias = "captchaToken")]
    captcha_token: Option<String>,
}

// Casdoor's AuthForm sends both username (login ID) and name (display name).
// These are distinct inputs, not serde aliases of one field.
impl TryFrom<LoginRequestInput> for LoginRequest {
    type Error = &'static str;

    fn try_from(input: LoginRequestInput) -> Result<Self, Self::Error> {
        let requested = input.login_type.as_deref().unwrap_or("password");
        let requested = match requested {
            "" | "login" | "password" => "password",
            "code" => "code",
            "ldap" => "ldap",
            _ => return Err("unsupported login type"),
        };
        let method = match input.signin_method.as_deref() {
            None | Some("") => requested,
            Some("Password") => "password",
            Some("LDAP") => "ldap",
            Some("Verification code") => "code",
            _ => return Err("unsupported sign-in method"),
        };
        if !matches!(input.login_type.as_deref(), None | Some("" | "login")) && requested != method
        {
            return Err("conflicting login type and sign-in method");
        }
        if input
            .code_method
            .as_deref()
            .is_some_and(|method| !matches!(method, "email" | "sms"))
        {
            return Err("unsupported code sign-in method");
        }
        if method == "password" && input.password.is_none() {
            return Err("missing field `password`");
        }
        Ok(Self {
            owner: input
                .owner
                .or(input.organization)
                .ok_or("missing field `owner` or `organization`")?,
            name: input
                .username
                .or(input.name)
                .ok_or("missing field `name` or `username`")?,
            password: input.password.unwrap_or_default(),
            response_type: input.response_type,
            client_id: input.client_id,
            redirect_uri: input.redirect_uri,
            scope: input.scope,
            state: input.state,
            nonce: input.nonce,
            code_challenge: input.code_challenge,
            code_challenge_method: input.code_challenge_method,
            login_type: Some(method.to_owned()),
            code: input.code,
            code_method: input.code_method,
            provider: input.provider,
            captcha_type: input.captcha_type,
            captcha_token: input.captcha_token,
            mfa_type: input.mfa_type,
            passcode: input.passcode,
            auto_signin: input.auto_signin,
            application: input.application,
        })
    }
}

impl TryFrom<SignupRequestInput> for SignupRequest {
    type Error = &'static str;

    fn try_from(input: SignupRequestInput) -> Result<Self, Self::Error> {
        let display_name = input
            .display_name
            .or_else(|| input.username.as_ref().and(input.name.clone()))
            .ok_or("missing field `display_name` (or Casdoor `name` with `username`)")?;
        Ok(Self {
            owner: input
                .owner
                .or(input.organization)
                .ok_or("missing field `owner` or `organization`")?,
            name: input
                .username
                .or(input.name)
                .ok_or("missing field `name` or `username`")?,
            display_name,
            password: input.password,
            email: input.email,
            phone: input.phone,
            invitation_code: input.invitation_code,
            application: input.application,
            captcha_type: input.captcha_type,
            captcha_token: input.captcha_token,
        })
    }
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
    pg_pool: Option<PgPool>,
    jwt_secret: String,
    jwt_expiration_hours: i64,
    jwt_issuer: String,
}

impl AuthService {
    pub fn new(user_service: UserService) -> Self {
        let config = AppConfig::get();
        Self {
            user_service,
            pg_pool: None,
            jwt_secret: config.jwt.secret,
            jwt_expiration_hours: config.jwt.expiration_hours,
            jwt_issuer: config.jwt.issuer,
        }
    }

    pub fn with_pg_pool(mut self, pool: PgPool) -> Self {
        self.pg_pool = Some(pool);
        self
    }

    pub async fn signup(&self, req: SignupRequest) -> AppResult<LoginResponse> {
        let pool = self.user_service.pool();
        let pg_pool = self
            .pg_pool
            .as_ref()
            .ok_or_else(|| AppError::Internal("PgPool not available in AuthService".to_string()))?;

        // 1. Get organization for password options
        let org = OrgService::new(pool.clone())
            .get_internal(&req.owner)
            .await
            .map_err(|_| AppError::Validation(format!("Organization '{}' not found", req.owner)))?;

        // 2. Get application signup_items if application is specified
        let signup_items = if let Some(ref app_name) = req.application {
            let app_service = AppService::new(pool.clone());
            let (app_owner, name) = app_name.split_once('/').unwrap_or((&req.owner, app_name));
            let application = app_service.get_by_name(app_owner, name).await?;
            if application.is_deleted
                || application.organization != req.owner
                || !application.enable_internal_signup
            {
                return Err(AppError::Authorization(
                    "Signup is not enabled for this organization/application".into(),
                ));
            }
            application.signup_items
        } else {
            None
        };

        // 3. Run full signup validation
        CheckService::check_user_signup(
            pg_pool,
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
                    pg_pool,
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

    pub async fn login(&self, pool: &DieselPool, req: LoginRequest) -> AppResult<LoginResponse> {
        if !matches!(
            req.login_type.as_deref(),
            None | Some("" | "password" | "login")
        ) {
            return Err(AppError::Authentication(
                "Complete this first factor through the browser login endpoint".into(),
            ));
        }
        let pg_pool = self
            .pg_pool
            .as_ref()
            .ok_or_else(|| AppError::Internal("PgPool not available in AuthService".to_string()))?;

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
                    .get_by_name(
                        app_name.split_once('/').map(|x| x.0).unwrap_or(&req.owner),
                        app_name.split_once('/').map(|x| x.1).unwrap_or(app_name),
                    )
                    .await
                    .map_err(|_| AppError::Authentication("Application not found".to_string()))?,
            )
        } else {
            None
        };

        if let Some(app) = &application {
            if app.is_deleted
                || app.organization != req.owner
                || !crate::services::primary_auth_service::PrimaryAuthService::method_enabled(
                    app, "password",
                )
            {
                return Err(AppError::Authentication(
                    "Application organization mismatch".into(),
                ));
            }
        }
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
                CheckService::record_signin_error(pg_pool, &user.id, 5, 15).await?;
                return Err(AppError::Authentication("Invalid credentials".to_string()));
            }
        }

        // 9. Check MFA requirement
        let mfa_types = MfaService::login_methods(pg_pool, &user).await?;
        if user.mfa_enabled || !mfa_types.is_empty() {
            if req
                .passcode
                .as_deref()
                .is_none_or(|code| code.trim().is_empty())
            {
                // MFA is required but no passcode provided - return MFA challenge

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
            // Generic verification records are not proof of a password-bound
            // login ceremony. Email/SMS must use the browser challenge API.
            let method = req
                .mfa_type
                .as_deref()
                .or(user.preferred_mfa_type.as_deref())
                .unwrap_or("app");
            if matches!(method, "email" | "sms") {
                return Err(AppError::Authentication(
                    "Complete the password MFA challenge before signing in".into(),
                ));
            }
            if !MfaService::verify_login(
                pg_pool,
                &user,
                req.mfa_type.as_deref(),
                req.passcode.as_deref().unwrap_or_default(),
            )
            .await?
            {
                CheckService::record_signin_error(pg_pool, &user.id, 5, 15).await?;
                return Err(AppError::Authentication("Invalid MFA code".to_string()));
            }
        }
        // A correct password alone must not reset failed second-factor attempts.
        CheckService::reset_signin_error(pg_pool, &user.id).await?;

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

        if password_expired || user.need_update_password {
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
            CheckService::check_login_permission(pg_pool, &user.id, &app.id).await?;
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
        let claims = self.claims_for_user(user);
        self.generate_token_from_claims(&claims)
    }

    pub fn claims_for_user(&self, user: &UserResponse) -> Claims {
        let now = Utc::now();
        let exp = now + Duration::hours(self.jwt_expiration_hours);

        Claims {
            sub: user.id.clone(),
            owner: user.owner.clone(),
            name: user.name.clone(),
            is_admin: user.is_admin,
            impersonator_user_id: None,
            impersonator_owner: None,
            impersonator_name: None,
            impersonation_session_id: None,
            impersonation_application: None,
            exp: exp.timestamp(),
            iat: now.timestamp(),
            issued_at_ms: Some(now.timestamp_millis()),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            iss: self.jwt_issuer.clone(),
        }
    }

    pub fn generate_token_from_claims(&self, claims: &Claims) -> AppResult<String> {
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )?;

        Ok(token)
    }

    pub fn expires_in_seconds(&self) -> i64 {
        self.jwt_expiration_hours * 3600
    }

    pub fn expiration_hours(&self) -> i64 {
        self.jwt_expiration_hours
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

        let is_valid = PasswordService::verify_password(
            old_password,
            &user.password_hash,
            user.password_type.as_deref().unwrap_or("argon2"),
            user.password_salt.as_deref(),
        )?;
        if !is_valid {
            return Err(AppError::Authentication("Invalid old password".to_string()));
        }

        let org = OrgService::new(self.user_service.pool().clone())
            .get_internal(&user.owner)
            .await?;
        CheckService::check_password_complexity(new_password, org.password_options.as_ref())?;
        let new_hash = UserService::hash_password(new_password)?;
        let pg = self
            .pg_pool
            .as_ref()
            .ok_or_else(|| AppError::Internal("Password change database unavailable".into()))?;
        let mut tx = pg.begin().await?;
        let changed = sqlx::query("UPDATE users SET password_hash=$1,password_type='argon2',password_salt=NULL,last_change_password_time=$2,need_update_password=false,updated_at=NOW() WHERE id=$3 AND password_hash=$4 AND NOT is_deleted AND NOT is_forbidden")
            .bind(new_hash).bind(Utc::now().to_rfc3339()).bind(user_id).bind(&user.password_hash).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(AppError::Authentication(
                "Credentials changed; please sign in again".into(),
            ));
        }
        sqlx::query("DELETE FROM tokens WHERE user_id=$1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM sessions WHERE user_id=$1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        Ok(())
    }

    pub async fn check_password(&self, user_id: &str, password: &str) -> AppResult<bool> {
        let user = self.user_service.get_by_id_internal(user_id).await?;
        PasswordService::verify_password(
            password,
            &user.password_hash,
            user.password_type.as_deref().unwrap_or("argon2"),
            user.password_salt.as_deref(),
        )
    }

    pub async fn sso_logout(pool: &PgPool, user_id: &str) -> AppResult<()> {
        Self::logout_session(pool, user_id, None).await
    }

    /// Serialize revocation with social completion, account binding and credential changes.
    /// All session removal and the cutoff commit together after acquiring the user lock.
    pub async fn logout_session(
        pool: &PgPool,
        user_id: &str,
        token: Option<(&str, i64)>,
    ) -> AppResult<()> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::Authentication("User unavailable".into()))?;
        if let Some((fingerprint, expires_at)) = token {
            sqlx::query("INSERT INTO revoked_session_tokens(token_hash,user_id,expires_at) VALUES($1,$2,to_timestamp($3)) ON CONFLICT DO NOTHING")
                .bind(fingerprint).bind(user_id).bind(expires_at as f64).execute(&mut *tx).await?;
        }
        sqlx::query("DELETE FROM tokens WHERE user_id=$1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM sessions WHERE user_id=$1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO user_session_epochs(user_id,invalid_before) VALUES($1,clock_timestamp()) ON CONFLICT(user_id) DO UPDATE SET invalid_before=GREATEST(user_session_epochs.invalid_before,EXCLUDED.invalid_before)")
            .bind(user_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}
