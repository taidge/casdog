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
            INSERT INTO applications (
                id, owner, name, display_name, logo, homepage_url, description, organization,
                client_id, client_secret, redirect_uris, token_format, expire_in_hours, cert,
                signup_items, signin_items, signin_methods, grant_types, providers,
                enable_password, enable_signin_session, enable_code_signin, enable_web_authn,
                enable_internal_signup, enable_idp_signup, created_at, updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8,
                $9, $10, $11, $12, $13, $14,
                $15, $16, $17, $18, $19,
                $20, $21, $22, $23,
                $24, $25, $26, $27
            )
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
        .bind(&req.signup_items)
        .bind(&req.signin_items)
        .bind(&req.signin_methods)
        .bind(&req.grant_types)
        .bind(&req.providers)
        .bind(req.enable_password.unwrap_or(true))
        .bind(req.enable_signin_session.unwrap_or(false))
        .bind(req.enable_code_signin.unwrap_or(false))
        .bind(req.enable_web_authn.unwrap_or(false))
        .bind(req.enable_internal_signup.unwrap_or(true))
        .bind(req.enable_idp_signup.unwrap_or(true))
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

    pub async fn get_by_name(&self, owner: &str, name: &str) -> AppResult<Application> {
        let app = sqlx::query_as::<_, Application>(
            "SELECT * FROM applications WHERE owner = $1 AND name = $2 AND is_deleted = FALSE",
        )
        .bind(owner)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Application '{}/{}' not found", owner, name)))?;

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

        if let Some(v) = req.display_name { app.display_name = v; }
        if let Some(v) = req.logo { app.logo = Some(v); }
        if let Some(v) = req.homepage_url { app.homepage_url = Some(v); }
        if let Some(v) = req.description { app.description = Some(v); }
        if let Some(v) = req.redirect_uris { app.redirect_uris = v; }
        if let Some(v) = req.token_format { app.token_format = v; }
        if let Some(v) = req.expire_in_hours { app.expire_in_hours = v; }
        if let Some(v) = req.refresh_expire_in_hours { app.refresh_expire_in_hours = v; }
        if let Some(v) = req.cert { app.cert = Some(v); }
        if let Some(v) = req.signup_url { app.signup_url = Some(v); }
        if let Some(v) = req.signin_url { app.signin_url = Some(v); }
        if let Some(v) = req.forget_url { app.forget_url = Some(v); }
        if let Some(v) = req.terms_of_use { app.terms_of_use = Some(v); }
        if let Some(v) = req.signup_html { app.signup_html = Some(v); }
        if let Some(v) = req.signin_html { app.signin_html = Some(v); }
        if let Some(v) = req.signup_items { app.signup_items = Some(v); }
        if let Some(v) = req.signin_items { app.signin_items = Some(v); }
        if let Some(v) = req.signin_methods { app.signin_methods = Some(v); }
        if let Some(v) = req.grant_types { app.grant_types = Some(v); }
        if let Some(v) = req.providers { app.providers = Some(v); }
        if let Some(v) = req.saml_reply_url { app.saml_reply_url = Some(v); }
        if let Some(v) = req.enable_password { app.enable_password = v; }
        if let Some(v) = req.enable_signin_session { app.enable_signin_session = v; }
        if let Some(v) = req.enable_auto_signin { app.enable_auto_signin = v; }
        if let Some(v) = req.enable_code_signin { app.enable_code_signin = v; }
        if let Some(v) = req.enable_saml_compress { app.enable_saml_compress = v; }
        if let Some(v) = req.enable_web_authn { app.enable_web_authn = v; }
        if let Some(v) = req.enable_link_with_email { app.enable_link_with_email = v; }
        if let Some(v) = req.enable_internal_signup { app.enable_internal_signup = v; }
        if let Some(v) = req.enable_idp_signup { app.enable_idp_signup = v; }
        if let Some(v) = req.form_offset { app.form_offset = v; }
        if let Some(v) = req.form_side_html { app.form_side_html = Some(v); }
        if let Some(v) = req.form_background_url { app.form_background_url = Some(v); }
        if let Some(v) = req.form_css { app.form_css = Some(v); }
        if let Some(v) = req.tags { app.tags = Some(v); }
        if let Some(v) = req.footer_text { app.footer_text = Some(v); }
        if let Some(v) = req.logout_url { app.logout_url = Some(v); }
        if let Some(v) = req.logout_redirect_uris { app.logout_redirect_uris = Some(v); }
        app.updated_at = Utc::now();

        let updated_app = sqlx::query_as::<_, Application>(
            r#"
            UPDATE applications SET
                display_name = $1, logo = $2, homepage_url = $3, description = $4,
                redirect_uris = $5, token_format = $6, expire_in_hours = $7,
                refresh_expire_in_hours = $8, cert = $9, signup_url = $10, signin_url = $11,
                forget_url = $12, terms_of_use = $13, signup_html = $14, signin_html = $15,
                signup_items = $16, signin_items = $17, signin_methods = $18, grant_types = $19,
                providers = $20, saml_reply_url = $21, enable_password = $22,
                enable_signin_session = $23, enable_auto_signin = $24, enable_code_signin = $25,
                enable_saml_compress = $26, enable_web_authn = $27, enable_link_with_email = $28,
                enable_internal_signup = $29, enable_idp_signup = $30, form_offset = $31,
                form_side_html = $32, form_background_url = $33, form_css = $34,
                tags = $35, footer_text = $36, logout_url = $37,
                logout_redirect_uris = $38, updated_at = $39
            WHERE id = $40
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
        .bind(app.refresh_expire_in_hours)
        .bind(&app.cert)
        .bind(&app.signup_url)
        .bind(&app.signin_url)
        .bind(&app.forget_url)
        .bind(&app.terms_of_use)
        .bind(&app.signup_html)
        .bind(&app.signin_html)
        .bind(&app.signup_items)
        .bind(&app.signin_items)
        .bind(&app.signin_methods)
        .bind(&app.grant_types)
        .bind(&app.providers)
        .bind(&app.saml_reply_url)
        .bind(app.enable_password)
        .bind(app.enable_signin_session)
        .bind(app.enable_auto_signin)
        .bind(app.enable_code_signin)
        .bind(app.enable_saml_compress)
        .bind(app.enable_web_authn)
        .bind(app.enable_link_with_email)
        .bind(app.enable_internal_signup)
        .bind(app.enable_idp_signup)
        .bind(app.form_offset)
        .bind(&app.form_side_html)
        .bind(&app.form_background_url)
        .bind(&app.form_css)
        .bind(&app.tags)
        .bind(&app.footer_text)
        .bind(&app.logout_url)
        .bind(&app.logout_redirect_uris)
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
