use crate::error::{AppError, AppResult};
use crate::models::{CreateUserRequest, UpdateUserRequest, User, UserListResponse, UserQuery, UserResponse};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::Utc;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Clone)]
pub struct UserService {
    pool: Pool<Postgres>,
}

impl UserService {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &Pool<Postgres> {
        &self.pool
    }

    pub fn hash_password(password: &str) -> AppResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))?
            .to_string();
        Ok(password_hash)
    }

    pub fn verify_password(password: &str, password_hash: &str) -> AppResult<bool> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|e| AppError::Internal(format!("Invalid password hash: {}", e)))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    pub async fn create(&self, req: CreateUserRequest) -> AppResult<UserResponse> {
        let id = Uuid::new_v4().to_string();
        let password_hash = if let Some(ref pw) = req.password {
            Self::hash_password(pw)?
        } else {
            String::new()
        };
        let now = Utc::now();

        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (
                id, owner, name, password_hash, display_name, email, phone, avatar,
                is_admin, user_type, first_name, last_name, country_code, region,
                location, affiliation, tag, language, gender, birthday, education,
                bio, homepage, signup_application, id_card_type, id_card, real_name,
                properties, created_at, updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8,
                $9, $10, $11, $12, $13, $14,
                $15, $16, $17, $18, $19, $20, $21,
                $22, $23, $24, $25, $26, $27,
                $28, $29, $30
            )
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&password_hash)
        .bind(&req.display_name)
        .bind(&req.email)
        .bind(&req.phone)
        .bind(&req.avatar)
        .bind(req.is_admin.unwrap_or(false))
        .bind(&req.user_type)
        .bind(&req.first_name)
        .bind(&req.last_name)
        .bind(&req.country_code)
        .bind(&req.region)
        .bind(&req.location)
        .bind(&req.affiliation)
        .bind(&req.tag)
        .bind(&req.language)
        .bind(&req.gender)
        .bind(&req.birthday)
        .bind(&req.education)
        .bind(&req.bio)
        .bind(&req.homepage)
        .bind(&req.signup_application)
        .bind(&req.id_card_type)
        .bind(&req.id_card)
        .bind(&req.real_name)
        .bind(&req.properties)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
                AppError::Conflict(format!("User '{}' already exists in organization '{}'", req.name, req.owner))
            }
            _ => AppError::Database(e),
        })?;

        Ok(user.into())
    }

    pub async fn get_by_id(&self, id: &str) -> AppResult<UserResponse> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User with id '{}' not found", id)))?;

        Ok(user.into())
    }

    pub async fn get_by_id_internal(&self, id: &str) -> AppResult<User> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User with id '{}' not found", id)))?;

        Ok(user)
    }

    pub async fn get_by_name(&self, owner: &str, name: &str) -> AppResult<User> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE owner = $1 AND name = $2 AND is_deleted = FALSE",
        )
        .bind(owner)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User '{}/{}' not found", owner, name)))?;

        Ok(user)
    }

    pub async fn get_by_email(&self, email: &str) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE email = $1 AND is_deleted = FALSE",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_by_phone(&self, phone: &str) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE phone = $1 AND is_deleted = FALSE",
        )
        .bind(phone)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn list(&self, query: UserQuery) -> AppResult<UserListResponse> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).min(100);
        let offset = (page - 1) * page_size;

        let (users, total): (Vec<User>, i64) = if let Some(owner) = &query.owner {
            let users = sqlx::query_as::<_, User>(
                "SELECT * FROM users WHERE owner = $1 AND is_deleted = FALSE ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(owner)
            .bind(page_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

            let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM users WHERE owner = $1 AND is_deleted = FALSE",
            )
            .bind(owner)
            .fetch_one(&self.pool)
            .await?;

            (users, total.0)
        } else {
            let users = sqlx::query_as::<_, User>(
                "SELECT * FROM users WHERE is_deleted = FALSE ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            )
            .bind(page_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

            let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM users WHERE is_deleted = FALSE",
            )
            .fetch_one(&self.pool)
            .await?;

            (users, total.0)
        };

        Ok(UserListResponse {
            data: users.into_iter().map(|u| u.into()).collect(),
            total,
            page,
            page_size,
        })
    }

    pub async fn update(&self, id: &str, req: UpdateUserRequest) -> AppResult<UserResponse> {
        let mut user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User with id '{}' not found", id)))?;

        // Apply partial updates
        if let Some(v) = req.display_name { user.display_name = v; }
        if let Some(v) = req.email { user.email = Some(v); }
        if let Some(v) = req.phone { user.phone = Some(v); }
        if let Some(v) = req.avatar { user.avatar = Some(v); }
        if let Some(v) = req.is_admin { user.is_admin = v; }
        if let Some(v) = req.first_name { user.first_name = Some(v); }
        if let Some(v) = req.last_name { user.last_name = Some(v); }
        if let Some(v) = req.avatar_type { user.avatar_type = Some(v); }
        if let Some(v) = req.permanent_avatar { user.permanent_avatar = Some(v); }
        if let Some(v) = req.country_code { user.country_code = Some(v); }
        if let Some(v) = req.region { user.region = Some(v); }
        if let Some(v) = req.location { user.location = Some(v); }
        if let Some(v) = req.address { user.address = Some(v); }
        if let Some(v) = req.affiliation { user.affiliation = Some(v); }
        if let Some(v) = req.title { user.title = Some(v); }
        if let Some(v) = req.homepage { user.homepage = Some(v); }
        if let Some(v) = req.bio { user.bio = Some(v); }
        if let Some(v) = req.id_card_type { user.id_card_type = Some(v); }
        if let Some(v) = req.id_card { user.id_card = Some(v); }
        if let Some(v) = req.real_name { user.real_name = Some(v); }
        if let Some(v) = req.tag { user.tag = Some(v); }
        if let Some(v) = req.language { user.language = Some(v); }
        if let Some(v) = req.gender { user.gender = Some(v); }
        if let Some(v) = req.birthday { user.birthday = Some(v); }
        if let Some(v) = req.education { user.education = Some(v); }
        if let Some(v) = req.score { user.score = v; }
        if let Some(v) = req.karma { user.karma = v; }
        if let Some(v) = req.is_forbidden { user.is_forbidden = v; }
        if let Some(v) = req.is_verified { user.is_verified = v; }
        if let Some(v) = req.signup_application { user.signup_application = Some(v); }
        if let Some(v) = req.properties { user.properties = Some(v); }
        if let Some(v) = req.custom { user.custom = Some(v); }
        if let Some(v) = req.groups { user.groups = Some(v); }
        if let Some(v) = req.managed_accounts { user.managed_accounts = Some(v); }
        if let Some(v) = req.ip_whitelist { user.ip_whitelist = Some(v); }
        if let Some(v) = req.need_update_password { user.need_update_password = v; }
        if let Some(password) = req.password {
            user.password_hash = Self::hash_password(&password)?;
        }
        user.updated_at = Utc::now();

        let updated_user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users SET
                display_name = $1, email = $2, phone = $3, avatar = $4, is_admin = $5,
                password_hash = $6, first_name = $7, last_name = $8, avatar_type = $9,
                permanent_avatar = $10, country_code = $11, region = $12, location = $13,
                address = $14, affiliation = $15, title = $16, homepage = $17, bio = $18,
                id_card_type = $19, id_card = $20, real_name = $21, tag = $22, language = $23,
                gender = $24, birthday = $25, education = $26, score = $27, karma = $28,
                is_forbidden = $29, is_verified = $30, signup_application = $31,
                properties = $32, custom = $33, groups = $34, managed_accounts = $35,
                ip_whitelist = $36, need_update_password = $37, updated_at = $38
            WHERE id = $39
            RETURNING *
            "#,
        )
        .bind(&user.display_name)
        .bind(&user.email)
        .bind(&user.phone)
        .bind(&user.avatar)
        .bind(user.is_admin)
        .bind(&user.password_hash)
        .bind(&user.first_name)
        .bind(&user.last_name)
        .bind(&user.avatar_type)
        .bind(&user.permanent_avatar)
        .bind(&user.country_code)
        .bind(&user.region)
        .bind(&user.location)
        .bind(&user.address)
        .bind(&user.affiliation)
        .bind(&user.title)
        .bind(&user.homepage)
        .bind(&user.bio)
        .bind(&user.id_card_type)
        .bind(&user.id_card)
        .bind(&user.real_name)
        .bind(&user.tag)
        .bind(&user.language)
        .bind(&user.gender)
        .bind(&user.birthday)
        .bind(&user.education)
        .bind(user.score)
        .bind(user.karma)
        .bind(user.is_forbidden)
        .bind(user.is_verified)
        .bind(&user.signup_application)
        .bind(&user.properties)
        .bind(&user.custom)
        .bind(&user.groups)
        .bind(&user.managed_accounts)
        .bind(&user.ip_whitelist)
        .bind(user.need_update_password)
        .bind(user.updated_at)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        Ok(updated_user.into())
    }

    pub async fn delete(&self, id: &str) -> AppResult<()> {
        let result = sqlx::query(
            "UPDATE users SET is_deleted = TRUE, updated_at = $1 WHERE id = $2 AND is_deleted = FALSE",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("User with id '{}' not found", id)));
        }

        Ok(())
    }

    /// Update sign-in tracking fields after login attempt
    pub async fn update_signin_tracking(&self, id: &str, success: bool, ip: Option<&str>) -> AppResult<()> {
        let now = Utc::now().to_rfc3339();
        if success {
            sqlx::query(
                r#"
                UPDATE users SET
                    last_signin_time = $1, last_signin_ip = $2,
                    signin_wrong_times = 0, is_online = TRUE, updated_at = NOW()
                WHERE id = $3
                "#,
            )
            .bind(&now)
            .bind(ip)
            .bind(id)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                r#"
                UPDATE users SET
                    last_signin_wrong_time = $1,
                    signin_wrong_times = signin_wrong_times + 1,
                    updated_at = NOW()
                WHERE id = $2
                "#,
            )
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Set user online/offline status
    pub async fn set_online_status(&self, id: &str, online: bool) -> AppResult<()> {
        sqlx::query("UPDATE users SET is_online = $1, updated_at = NOW() WHERE id = $2")
            .bind(online)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Link a social provider to a user
    pub async fn link_provider(&self, id: &str, provider_name: &str, provider_user_id: &str) -> AppResult<()> {
        sqlx::query(
            r#"
            UPDATE users SET
                provider_ids = COALESCE(provider_ids, '{}'::jsonb) || jsonb_build_object($1::text, $2::text),
                updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(provider_name)
        .bind(provider_user_id)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Unlink a social provider from a user
    pub async fn unlink_provider(&self, id: &str, provider_name: &str) -> AppResult<()> {
        sqlx::query(
            r#"
            UPDATE users SET
                provider_ids = provider_ids - $1,
                updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(provider_name)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
