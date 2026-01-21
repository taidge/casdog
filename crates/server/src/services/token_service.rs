use crate::error::AppResult;
use crate::models::{CreateTokenRequest, Token, TokenResponse, UpdateTokenRequest};
use chrono::Utc;
use rand::Rng;
use sqlx::PgPool;
use uuid::Uuid;

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
                r#"SELECT * FROM tokens ORDER BY created_at DESC LIMIT $1 OFFSET $2"#
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
        let token =
            sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE access_token = $1")
                .bind(access_token)
                .fetch_one(pool)
                .await?;
        Ok(token)
    }

    pub async fn get_by_refresh_token(pool: &PgPool, refresh_token: &str) -> AppResult<Token> {
        let token =
            sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE refresh_token = $1")
                .bind(refresh_token)
                .fetch_one(pool)
                .await?;
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

    pub async fn update(pool: &PgPool, id: &str, req: UpdateTokenRequest) -> AppResult<TokenResponse> {
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

    fn generate_token() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
    }
}
