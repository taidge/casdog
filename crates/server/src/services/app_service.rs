use crate::error::{AppError, AppResult};
use crate::models::{
    Application, ApplicationListResponse, ApplicationQuery, ApplicationResponse,
    CreateApplicationRequest, UpdateApplicationRequest,
};
use chrono::Utc;
use rand::Rng;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppService {
    pool: Pool<Postgres>,
}

impl AppService {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    fn generate_client_id() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
    }

    fn generate_client_secret() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..48).map(|_| rng.gen()).collect();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
    }

    pub async fn create(&self, req: CreateApplicationRequest) -> AppResult<ApplicationResponse> {
        let id = Uuid::new_v4().to_string();
        let client_id = Self::generate_client_id();
        let client_secret = Self::generate_client_secret();
        let now = Utc::now();

        let app = sqlx::query_as::<_, Application>(
            r#"
            INSERT INTO applications (id, owner, name, display_name, logo, homepage_url, description, organization, client_id, client_secret, redirect_uris, token_format, expire_in_hours, cert, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.logo)
        .bind(&req.homepage_url)
        .bind(&req.description)
        .bind(&req.organization)
        .bind(&client_id)
        .bind(&client_secret)
        .bind(req.redirect_uris.unwrap_or_default())
        .bind(req.token_format.unwrap_or_else(|| "JWT".to_string()))
        .bind(req.expire_in_hours.unwrap_or(24))
        .bind(&req.cert)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
                AppError::Conflict(format!("Application '{}' already exists", req.name))
            }
            _ => AppError::Database(e),
        })?;

        Ok(app.into())
    }

    pub async fn get_by_id(&self, id: &str) -> AppResult<ApplicationResponse> {
        let app = sqlx::query_as::<_, Application>(
            "SELECT * FROM applications WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Application with id '{}' not found", id)))?;

        Ok(app.into())
    }

    pub async fn get_by_client_id(&self, client_id: &str) -> AppResult<Application> {
        let app = sqlx::query_as::<_, Application>(
            "SELECT * FROM applications WHERE client_id = $1 AND is_deleted = FALSE",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Application with client_id '{}' not found", client_id)))?;

        Ok(app)
    }

    pub async fn list(&self, query: ApplicationQuery) -> AppResult<ApplicationListResponse> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).min(100);
        let offset = (page - 1) * page_size;

        let (apps, total): (Vec<Application>, i64) = match (&query.owner, &query.organization) {
            (Some(owner), Some(org)) => {
                let apps = sqlx::query_as::<_, Application>(
                    "SELECT * FROM applications WHERE owner = $1 AND organization = $2 AND is_deleted = FALSE ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                )
                .bind(owner)
                .bind(org)
                .bind(page_size)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?;

                let total: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM applications WHERE owner = $1 AND organization = $2 AND is_deleted = FALSE",
                )
                .bind(owner)
                .bind(org)
                .fetch_one(&self.pool)
                .await?;

                (apps, total.0)
            }
            (Some(owner), None) => {
                let apps = sqlx::query_as::<_, Application>(
                    "SELECT * FROM applications WHERE owner = $1 AND is_deleted = FALSE ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                )
                .bind(owner)
                .bind(page_size)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?;

                let total: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM applications WHERE owner = $1 AND is_deleted = FALSE",
                )
                .bind(owner)
                .fetch_one(&self.pool)
                .await?;

                (apps, total.0)
            }
            (None, Some(org)) => {
                let apps = sqlx::query_as::<_, Application>(
                    "SELECT * FROM applications WHERE organization = $1 AND is_deleted = FALSE ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                )
                .bind(org)
                .bind(page_size)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?;

                let total: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM applications WHERE organization = $1 AND is_deleted = FALSE",
                )
                .bind(org)
                .fetch_one(&self.pool)
                .await?;

                (apps, total.0)
            }
            (None, None) => {
                let apps = sqlx::query_as::<_, Application>(
                    "SELECT * FROM applications WHERE is_deleted = FALSE ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                )
                .bind(page_size)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?;

                let total: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM applications WHERE is_deleted = FALSE",
                )
                .fetch_one(&self.pool)
                .await?;

                (apps, total.0)
            }
        };

        Ok(ApplicationListResponse {
            data: apps.into_iter().map(|a| a.into()).collect(),
            total,
            page,
            page_size,
        })
    }

    pub async fn update(&self, id: &str, req: UpdateApplicationRequest) -> AppResult<ApplicationResponse> {
        let mut app = sqlx::query_as::<_, Application>(
            "SELECT * FROM applications WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Application with id '{}' not found", id)))?;

        if let Some(display_name) = req.display_name {
            app.display_name = display_name;
        }
        if let Some(logo) = req.logo {
            app.logo = Some(logo);
        }
        if let Some(homepage_url) = req.homepage_url {
            app.homepage_url = Some(homepage_url);
        }
        if let Some(description) = req.description {
            app.description = Some(description);
        }
        if let Some(redirect_uris) = req.redirect_uris {
            app.redirect_uris = redirect_uris;
        }
        if let Some(token_format) = req.token_format {
            app.token_format = token_format;
        }
        if let Some(expire_in_hours) = req.expire_in_hours {
            app.expire_in_hours = expire_in_hours;
        }
        if let Some(cert) = req.cert {
            app.cert = Some(cert);
        }
        app.updated_at = Utc::now();

        let updated_app = sqlx::query_as::<_, Application>(
            r#"
            UPDATE applications
            SET display_name = $1, logo = $2, homepage_url = $3, description = $4, redirect_uris = $5, token_format = $6, expire_in_hours = $7, cert = $8, updated_at = $9
            WHERE id = $10
            RETURNING *
            "#,
        )
        .bind(&app.display_name)
        .bind(&app.logo)
        .bind(&app.homepage_url)
        .bind(&app.description)
        .bind(&app.redirect_uris)
        .bind(&app.token_format)
        .bind(app.expire_in_hours)
        .bind(&app.cert)
        .bind(app.updated_at)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        Ok(updated_app.into())
    }

    pub async fn delete(&self, id: &str) -> AppResult<()> {
        let result = sqlx::query(
            "UPDATE applications SET is_deleted = TRUE, updated_at = $1 WHERE id = $2 AND is_deleted = FALSE",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!(
                "Application with id '{}' not found",
                id
            )));
        }

        Ok(())
    }
}
