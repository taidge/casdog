use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppResult;
use crate::models::{CreateSessionRequest, Session, SessionResponse, UpdateSessionRequest};

pub struct SessionService;

impl SessionService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<SessionResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let (sessions, total): (Vec<Session>, i64) = if let Some(owner) = owner {
            let sessions = sqlx::query_as::<_, Session>(
                r#"SELECT * FROM sessions WHERE owner = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"#
            )
            .bind(owner)
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?;

            (sessions, total.0)
        } else {
            let sessions = sqlx::query_as::<_, Session>(
                r#"SELECT * FROM sessions ORDER BY created_at DESC LIMIT $1 OFFSET $2"#,
            )
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
                .fetch_one(pool)
                .await?;

            (sessions, total.0)
        };

        Ok((sessions.into_iter().map(Into::into).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<SessionResponse> {
        let session = sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await?;
        Ok(session.into())
    }

    pub async fn create(pool: &PgPool, req: CreateSessionRequest) -> AppResult<SessionResponse> {
        let id = Uuid::new_v4().to_string();
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let session = sqlx::query_as::<_, Session>(
            r#"INSERT INTO sessions (
                id, owner, name, application, created_at, user_id, session_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *"#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.application)
        .bind(now)
        .bind(&req.user_id)
        .bind(&session_id)
        .fetch_one(pool)
        .await?;

        Ok(session.into())
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateSessionRequest,
    ) -> AppResult<SessionResponse> {
        let session = sqlx::query_as::<_, Session>(
            r#"UPDATE sessions SET
                application = COALESCE($2, application)
            WHERE id = $1 RETURNING *"#,
        )
        .bind(id)
        .bind(&req.application)
        .fetch_one(pool)
        .await?;

        Ok(session.into())
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn delete_by_user(pool: &PgPool, user_id: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn is_session_duplicated(
        pool: &PgPool,
        user_id: &str,
        session_id: &str,
    ) -> AppResult<bool> {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND session_id != $2")
                .bind(user_id)
                .bind(session_id)
                .fetch_one(pool)
                .await?;

        Ok(count.0 > 0)
    }

    /// Delete all sessions for a user except the current one (exclusive signin)
    pub async fn delete_other_sessions(
        pool: &PgPool,
        user_id: &str,
        current_session_id: Option<&str>,
    ) -> AppResult<()> {
        if let Some(current_id) = current_session_id {
            sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND session_id != $2")
                .bind(user_id)
                .bind(current_id)
                .execute(pool)
                .await?;
        } else {
            sqlx::query("DELETE FROM sessions WHERE user_id = $1")
                .bind(user_id)
                .execute(pool)
                .await?;
        }
        Ok(())
    }

    /// Delete all sessions for a specific application
    pub async fn delete_by_application(pool: &PgPool, app_name: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM sessions WHERE application = $1")
            .bind(app_name)
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Check if a session is expired based on expiry time
    pub async fn is_session_expired(pool: &PgPool, session_id: &str) -> AppResult<bool> {
        let expired: Option<bool> = sqlx::query_scalar(
            "SELECT CASE WHEN expires_at IS NOT NULL AND expires_at < NOW() THEN true ELSE false END FROM sessions WHERE session_id = $1",
        )
        .bind(session_id)
        .fetch_optional(pool)
        .await?;

        // If no session found, treat as expired
        Ok(expired.unwrap_or(true))
    }

    /// Create a new session with proper expiry time
    pub async fn create_login_session(
        pool: &PgPool,
        user_id: &str,
        _user_name: &str,
        owner: &str,
        application: &str,
        _client_ip: Option<&str>,
        expire_hours: i64,
    ) -> AppResult<String> {
        let id = Uuid::new_v4().to_string();
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::hours(expire_hours);
        let name = format!("session_{}", &id[..8]);

        sqlx::query(
            r#"INSERT INTO sessions (id, owner, name, application, created_at, user_id, session_id, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(&id)
        .bind(owner)
        .bind(&name)
        .bind(application)
        .bind(now)
        .bind(user_id)
        .bind(&session_id)
        .bind(expires_at)
        .execute(pool)
        .await?;

        Ok(session_id)
    }
}
