use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::{
    CreateUserRequest, UpdateUserRequest, User, UserListResponse, UserQuery, UserResponse,
};
use crate::schema::users;

#[derive(Clone)]
pub struct UserService {
    pool: DieselPool,
}

impl UserService {
    pub fn new(pool: DieselPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &DieselPool {
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
        let pw_hash = if let Some(ref pw) = req.password {
            Self::hash_password(pw)?
        } else {
            String::new()
        };
        let now = Utc::now();

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let user = diesel::insert_into(users::table)
            .values((
                users::id.eq(&id),
                users::owner.eq(&req.owner),
                users::name.eq(&req.name),
                users::password_hash.eq(&pw_hash),
                users::display_name.eq(&req.display_name),
                users::email.eq(&req.email),
                users::phone.eq(&req.phone),
                users::avatar.eq(&req.avatar),
                users::is_admin.eq(req.is_admin.unwrap_or(false)),
                users::user_type.eq(&req.user_type),
                users::first_name.eq(&req.first_name),
                users::last_name.eq(&req.last_name),
                users::country_code.eq(&req.country_code),
                users::region.eq(&req.region),
                users::location.eq(&req.location),
                users::affiliation.eq(&req.affiliation),
                users::tag.eq(&req.tag),
                users::language.eq(&req.language),
                users::gender.eq(&req.gender),
                users::birthday.eq(&req.birthday),
                users::education.eq(&req.education),
                users::bio.eq(&req.bio),
                users::homepage.eq(&req.homepage),
                users::signup_application.eq(&req.signup_application),
                users::id_card_type.eq(&req.id_card_type),
                users::id_card.eq(&req.id_card),
                users::real_name.eq(&req.real_name),
                users::properties.eq(&req.properties),
                users::created_at.eq(now),
                users::updated_at.eq(now),
            ))
            .returning(User::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                ) => AppError::Conflict(format!(
                    "User '{}' already exists in organization '{}'",
                    req.name, req.owner
                )),
                _ => AppError::Internal(e.to_string()),
            })?;

        Ok(user.into())
    }

    pub async fn get_by_id(&self, id: &str) -> AppResult<UserResponse> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let user = users::table
            .filter(users::id.eq(id))
            .filter(users::is_deleted.eq(false))
            .select(User::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("User with id '{}' not found", id)))?;

        Ok(user.into())
    }

    pub async fn get_by_id_internal(&self, id: &str) -> AppResult<User> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let user = users::table
            .filter(users::id.eq(id))
            .filter(users::is_deleted.eq(false))
            .select(User::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("User with id '{}' not found", id)))?;

        Ok(user)
    }

    pub async fn get_by_name(&self, owner: &str, name: &str) -> AppResult<User> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let user = users::table
            .filter(users::owner.eq(owner))
            .filter(users::name.eq(name))
            .filter(users::is_deleted.eq(false))
            .select(User::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("User '{}/{}' not found", owner, name)))?;

        Ok(user)
    }

    pub async fn get_by_email(&self, email: &str) -> AppResult<Option<User>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let user = users::table
            .filter(users::email.eq(email))
            .filter(users::is_deleted.eq(false))
            .select(User::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(user)
    }

    pub async fn get_by_phone(&self, phone: &str) -> AppResult<Option<User>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let user = users::table
            .filter(users::phone.eq(phone))
            .filter(users::is_deleted.eq(false))
            .select(User::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(user)
    }

    pub async fn list(&self, query: UserQuery) -> AppResult<UserListResponse> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).min(100);
        let offset = (page - 1) * page_size;

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let (user_list, total): (Vec<User>, i64) = if let Some(ref owner) = query.owner {
            let user_list = users::table
                .filter(users::owner.eq(owner))
                .filter(users::is_deleted.eq(false))
                .order(users::created_at.desc())
                .limit(page_size)
                .offset(offset)
                .select(User::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let total: i64 = users::table
                .filter(users::owner.eq(owner))
                .filter(users::is_deleted.eq(false))
                .count()
                .get_result(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            (user_list, total)
        } else {
            let user_list = users::table
                .filter(users::is_deleted.eq(false))
                .order(users::created_at.desc())
                .limit(page_size)
                .offset(offset)
                .select(User::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let total: i64 = users::table
                .filter(users::is_deleted.eq(false))
                .count()
                .get_result(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            (user_list, total)
        };

        Ok(UserListResponse {
            data: user_list.into_iter().map(|u| u.into()).collect(),
            total,
            page,
            page_size,
        })
    }

    pub async fn update(&self, id: &str, req: UpdateUserRequest) -> AppResult<UserResponse> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let mut user = users::table
            .filter(users::id.eq(id))
            .filter(users::is_deleted.eq(false))
            .select(User::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("User with id '{}' not found", id)))?;

        // Apply partial updates
        if let Some(v) = req.display_name {
            user.display_name = v;
        }
        if let Some(v) = req.email {
            user.email = Some(v);
        }
        if let Some(v) = req.phone {
            user.phone = Some(v);
        }
        if let Some(v) = req.avatar {
            user.avatar = Some(v);
        }
        if let Some(v) = req.is_admin {
            user.is_admin = v;
        }
        if let Some(v) = req.first_name {
            user.first_name = Some(v);
        }
        if let Some(v) = req.last_name {
            user.last_name = Some(v);
        }
        if let Some(v) = req.avatar_type {
            user.avatar_type = Some(v);
        }
        if let Some(v) = req.permanent_avatar {
            user.permanent_avatar = Some(v);
        }
        if let Some(v) = req.country_code {
            user.country_code = Some(v);
        }
        if let Some(v) = req.region {
            user.region = Some(v);
        }
        if let Some(v) = req.location {
            user.location = Some(v);
        }
        if let Some(v) = req.address {
            user.address = Some(v);
        }
        if let Some(v) = req.affiliation {
            user.affiliation = Some(v);
        }
        if let Some(v) = req.title {
            user.title = Some(v);
        }
        if let Some(v) = req.homepage {
            user.homepage = Some(v);
        }
        if let Some(v) = req.bio {
            user.bio = Some(v);
        }
        if let Some(v) = req.id_card_type {
            user.id_card_type = Some(v);
        }
        if let Some(v) = req.id_card {
            user.id_card = Some(v);
        }
        if let Some(v) = req.real_name {
            user.real_name = Some(v);
        }
        if let Some(v) = req.tag {
            user.tag = Some(v);
        }
        if let Some(v) = req.language {
            user.language = Some(v);
        }
        if let Some(v) = req.gender {
            user.gender = Some(v);
        }
        if let Some(v) = req.birthday {
            user.birthday = Some(v);
        }
        if let Some(v) = req.education {
            user.education = Some(v);
        }
        if let Some(v) = req.score {
            user.score = v;
        }
        if let Some(v) = req.karma {
            user.karma = v;
        }
        if let Some(v) = req.is_forbidden {
            user.is_forbidden = v;
        }
        if let Some(v) = req.is_verified {
            user.is_verified = v;
        }
        if let Some(v) = req.signup_application {
            user.signup_application = Some(v);
        }
        if let Some(v) = req.properties {
            user.properties = Some(v);
        }
        if let Some(v) = req.custom {
            user.custom = Some(v);
        }
        if let Some(v) = req.groups {
            user.groups = Some(v);
        }
        if let Some(v) = req.managed_accounts {
            user.managed_accounts = Some(v);
        }
        if let Some(v) = req.ip_whitelist {
            user.ip_whitelist = Some(v);
        }
        if let Some(v) = req.need_update_password {
            user.need_update_password = v;
        }
        if let Some(password) = req.password {
            user.password_hash = Self::hash_password(&password)?;
        }
        user.updated_at = Utc::now();

        let updated_user = diesel::update(users::table.filter(users::id.eq(id)))
            .set((
                users::display_name.eq(&user.display_name),
                users::email.eq(&user.email),
                users::phone.eq(&user.phone),
                users::avatar.eq(&user.avatar),
                users::is_admin.eq(user.is_admin),
                users::password_hash.eq(&user.password_hash),
                users::first_name.eq(&user.first_name),
                users::last_name.eq(&user.last_name),
                users::avatar_type.eq(&user.avatar_type),
                users::permanent_avatar.eq(&user.permanent_avatar),
                users::country_code.eq(&user.country_code),
                users::region.eq(&user.region),
                users::location.eq(&user.location),
                users::address.eq(&user.address),
                users::affiliation.eq(&user.affiliation),
                users::title.eq(&user.title),
                users::homepage.eq(&user.homepage),
                users::bio.eq(&user.bio),
                users::id_card_type.eq(&user.id_card_type),
                users::id_card.eq(&user.id_card),
                users::real_name.eq(&user.real_name),
                users::tag.eq(&user.tag),
                users::language.eq(&user.language),
                users::gender.eq(&user.gender),
                users::birthday.eq(&user.birthday),
                users::education.eq(&user.education),
                users::score.eq(user.score),
                users::karma.eq(user.karma),
                users::is_forbidden.eq(user.is_forbidden),
                users::is_verified.eq(user.is_verified),
                users::signup_application.eq(&user.signup_application),
                users::properties.eq(&user.properties),
                users::custom.eq(&user.custom),
                users::groups.eq(&user.groups),
                users::managed_accounts.eq(&user.managed_accounts),
                users::ip_whitelist.eq(&user.ip_whitelist),
                users::need_update_password.eq(user.need_update_password),
                users::updated_at.eq(user.updated_at),
            ))
            .returning(User::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(updated_user.into())
    }

    pub async fn delete(&self, id: &str) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let now = Utc::now();

        let count = diesel::update(
            users::table
                .filter(users::id.eq(id))
                .filter(users::is_deleted.eq(false)),
        )
        .set((users::is_deleted.eq(true), users::updated_at.eq(now)))
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        if count == 0 {
            return Err(AppError::NotFound(format!(
                "User with id '{}' not found",
                id
            )));
        }

        Ok(())
    }

    /// Update sign-in tracking fields after login attempt
    pub async fn update_signin_tracking(
        &self,
        id: &str,
        success: bool,
        ip: Option<&str>,
    ) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let now_str = Utc::now().to_rfc3339();
        let now = Utc::now();

        if success {
            diesel::update(users::table.filter(users::id.eq(id)))
                .set((
                    users::last_signin_time.eq(&now_str),
                    users::last_signin_ip.eq(ip),
                    users::signin_wrong_times.eq(0),
                    users::is_online.eq(true),
                    users::updated_at.eq(now),
                ))
                .execute(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;
        } else {
            // For incrementing signin_wrong_times we use a raw SQL expression
            diesel::sql_query(
                "UPDATE users SET last_signin_wrong_time = $1, signin_wrong_times = signin_wrong_times + 1, updated_at = NOW() WHERE id = $2"
            )
            .bind::<diesel::sql_types::Text, _>(&now_str)
            .bind::<diesel::sql_types::Text, _>(id)
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        }
        Ok(())
    }

    /// Set user online/offline status
    pub async fn set_online_status(&self, id: &str, online: bool) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::update(users::table.filter(users::id.eq(id)))
            .set((
                users::is_online.eq(online),
                users::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    /// Link a social provider to a user
    pub async fn link_provider(
        &self,
        id: &str,
        provider_name: &str,
        provider_user_id: &str,
    ) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        // JSONB operations require raw SQL
        diesel::sql_query(
            r#"
            UPDATE users SET
                provider_ids = COALESCE(provider_ids, '{}'::jsonb) || jsonb_build_object($1::text, $2::text),
                updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind::<diesel::sql_types::Text, _>(provider_name)
        .bind::<diesel::sql_types::Text, _>(provider_user_id)
        .bind::<diesel::sql_types::Text, _>(id)
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    /// Unlink a social provider from a user
    pub async fn unlink_provider(&self, id: &str, provider_name: &str) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::sql_query(
            r#"
            UPDATE users SET
                provider_ids = provider_ids - $1,
                updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind::<diesel::sql_types::Text, _>(provider_name)
        .bind::<diesel::sql_types::Text, _>(id)
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }
}
