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
        let password_hash = Self::hash_password(&req.password)?;
        let now = Utc::now();

        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (id, owner, name, password_hash, display_name, email, phone, avatar, is_admin, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
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

        if let Some(display_name) = req.display_name {
            user.display_name = display_name;
        }
        if let Some(email) = req.email {
            user.email = Some(email);
        }
        if let Some(phone) = req.phone {
            user.phone = Some(phone);
        }
        if let Some(avatar) = req.avatar {
            user.avatar = Some(avatar);
        }
        if let Some(is_admin) = req.is_admin {
            user.is_admin = is_admin;
        }
        if let Some(password) = req.password {
            user.password_hash = Self::hash_password(&password)?;
        }
        user.updated_at = Utc::now();

        let updated_user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET display_name = $1, email = $2, phone = $3, avatar = $4, is_admin = $5, password_hash = $6, updated_at = $7
            WHERE id = $8
            RETURNING *
            "#,
        )
        .bind(&user.display_name)
        .bind(&user.email)
        .bind(&user.phone)
        .bind(&user.avatar)
        .bind(user.is_admin)
        .bind(&user.password_hash)
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
}
