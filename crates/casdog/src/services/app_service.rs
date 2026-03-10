use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand::Rng;
use uuid::Uuid;

use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::{
    Application, ApplicationListResponse, ApplicationQuery, ApplicationResponse,
    CreateApplicationRequest, UpdateApplicationRequest,
};
use crate::schema::applications;

#[derive(Clone)]
pub struct AppService {
    pool: DieselPool,
}

impl AppService {
    pub fn new(pool: DieselPool) -> Self {
        Self { pool }
    }

    fn generate_client_id() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
    }

    fn generate_client_secret() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..48).map(|_| rng.r#gen()).collect();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
    }

    pub async fn create(&self, req: CreateApplicationRequest) -> AppResult<ApplicationResponse> {
        let id = Uuid::new_v4().to_string();
        let client_id = Self::generate_client_id();
        let client_secret = Self::generate_client_secret();
        let now = Utc::now();

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let app = diesel::insert_into(applications::table)
            .values((
                applications::id.eq(&id),
                applications::owner.eq(&req.owner),
                applications::name.eq(&req.name),
                applications::display_name.eq(&req.display_name),
                applications::logo.eq(&req.logo),
                applications::homepage_url.eq(&req.homepage_url),
                applications::description.eq(&req.description),
                applications::organization.eq(&req.organization),
                applications::client_id.eq(&client_id),
                applications::client_secret.eq(&client_secret),
                applications::redirect_uris.eq(req.redirect_uris.as_deref().unwrap_or("")),
                applications::token_format.eq(req.token_format.as_deref().unwrap_or("JWT")),
                applications::expire_in_hours.eq(req.expire_in_hours.unwrap_or(24)),
                applications::cert.eq(&req.cert),
                applications::signup_items.eq(&req.signup_items),
                applications::signin_items.eq(&req.signin_items),
                applications::signin_methods.eq(&req.signin_methods),
                applications::grant_types.eq(&req.grant_types),
                applications::providers.eq(&req.providers),
                applications::enable_password.eq(req.enable_password.unwrap_or(true)),
                applications::enable_signin_session.eq(req.enable_signin_session.unwrap_or(false)),
                applications::enable_code_signin.eq(req.enable_code_signin.unwrap_or(false)),
                applications::enable_web_authn.eq(req.enable_web_authn.unwrap_or(false)),
                applications::enable_internal_signup.eq(req.enable_internal_signup.unwrap_or(true)),
                applications::enable_idp_signup.eq(req.enable_idp_signup.unwrap_or(true)),
                applications::created_at.eq(now),
                applications::updated_at.eq(now),
            ))
            .returning(Application::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                ) => AppError::Conflict(format!("Application '{}' already exists", req.name)),
                _ => AppError::Internal(e.to_string()),
            })?;

        Ok(app.into())
    }

    pub async fn get_by_id(&self, id: &str) -> AppResult<ApplicationResponse> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let app = applications::table
            .filter(applications::id.eq(id))
            .filter(applications::is_deleted.eq(false))
            .select(Application::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("Application with id '{}' not found", id)))?;

        Ok(app.into())
    }

    pub async fn get_internal_by_id(&self, id: &str) -> AppResult<Application> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let app = applications::table
            .filter(applications::id.eq(id))
            .filter(applications::is_deleted.eq(false))
            .select(Application::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("Application with id '{}' not found", id)))?;

        Ok(app)
    }

    pub async fn find_internal(
        &self,
        reference: &str,
        owner: Option<&str>,
    ) -> AppResult<Application> {
        if let Some((parsed_owner, name)) = reference.split_once('/') {
            return self.get_by_name(parsed_owner, name).await;
        }

        if let Some(owner) = owner {
            if let Ok(app) = self.get_by_name(owner, reference).await {
                return Ok(app);
            }
        }

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        // Try to find by id first, then by name
        let app = applications::table
            .filter(applications::id.eq(reference))
            .filter(applications::is_deleted.eq(false))
            .select(Application::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let app = if let Some(app) = app {
            app
        } else {
            applications::table
                .filter(applications::name.eq(reference))
                .filter(applications::is_deleted.eq(false))
                .order(applications::created_at.desc())
                .select(Application::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(|e| AppError::Internal(e.to_string()))?
                .ok_or_else(|| {
                    AppError::NotFound(format!("Application '{}' not found", reference))
                })?
        };

        Ok(app)
    }

    pub async fn get_by_client_id(&self, client_id: &str) -> AppResult<Application> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let app = applications::table
            .filter(applications::client_id.eq(client_id))
            .filter(applications::is_deleted.eq(false))
            .select(Application::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "Application with client_id '{}' not found",
                    client_id
                ))
            })?;

        Ok(app)
    }

    pub async fn get_by_name(&self, owner: &str, name: &str) -> AppResult<Application> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let app = applications::table
            .filter(applications::owner.eq(owner))
            .filter(applications::name.eq(name))
            .filter(applications::is_deleted.eq(false))
            .select(Application::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| {
                AppError::NotFound(format!("Application '{}/{}' not found", owner, name))
            })?;

        Ok(app)
    }

    pub async fn list(&self, query: ApplicationQuery) -> AppResult<ApplicationListResponse> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).min(100);
        let offset = (page - 1) * page_size;

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let (apps, total): (Vec<Application>, i64) = match (&query.owner, &query.organization) {
            (Some(owner), Some(org)) => {
                let apps = applications::table
                    .filter(applications::owner.eq(owner))
                    .filter(applications::organization.eq(org))
                    .filter(applications::is_deleted.eq(false))
                    .order(applications::created_at.desc())
                    .limit(page_size)
                    .offset(offset)
                    .select(Application::as_select())
                    .load(&mut conn)
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;

                let total: i64 = applications::table
                    .filter(applications::owner.eq(owner))
                    .filter(applications::organization.eq(org))
                    .filter(applications::is_deleted.eq(false))
                    .count()
                    .get_result(&mut conn)
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;

                (apps, total)
            }
            (Some(owner), None) => {
                let apps = applications::table
                    .filter(applications::owner.eq(owner))
                    .filter(applications::is_deleted.eq(false))
                    .order(applications::created_at.desc())
                    .limit(page_size)
                    .offset(offset)
                    .select(Application::as_select())
                    .load(&mut conn)
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;

                let total: i64 = applications::table
                    .filter(applications::owner.eq(owner))
                    .filter(applications::is_deleted.eq(false))
                    .count()
                    .get_result(&mut conn)
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;

                (apps, total)
            }
            (None, Some(org)) => {
                let apps = applications::table
                    .filter(applications::organization.eq(org))
                    .filter(applications::is_deleted.eq(false))
                    .order(applications::created_at.desc())
                    .limit(page_size)
                    .offset(offset)
                    .select(Application::as_select())
                    .load(&mut conn)
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;

                let total: i64 = applications::table
                    .filter(applications::organization.eq(org))
                    .filter(applications::is_deleted.eq(false))
                    .count()
                    .get_result(&mut conn)
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;

                (apps, total)
            }
            (None, None) => {
                let apps = applications::table
                    .filter(applications::is_deleted.eq(false))
                    .order(applications::created_at.desc())
                    .limit(page_size)
                    .offset(offset)
                    .select(Application::as_select())
                    .load(&mut conn)
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;

                let total: i64 = applications::table
                    .filter(applications::is_deleted.eq(false))
                    .count()
                    .get_result(&mut conn)
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;

                (apps, total)
            }
        };

        Ok(ApplicationListResponse {
            data: apps.into_iter().map(|a| a.into()).collect(),
            total,
            page,
            page_size,
        })
    }

    pub async fn update(
        &self,
        id: &str,
        req: UpdateApplicationRequest,
    ) -> AppResult<ApplicationResponse> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let mut app = applications::table
            .filter(applications::id.eq(id))
            .filter(applications::is_deleted.eq(false))
            .select(Application::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("Application with id '{}' not found", id)))?;

        if let Some(v) = req.display_name {
            app.display_name = v;
        }
        if let Some(v) = req.logo {
            app.logo = Some(v);
        }
        if let Some(v) = req.homepage_url {
            app.homepage_url = Some(v);
        }
        if let Some(v) = req.description {
            app.description = Some(v);
        }
        if let Some(v) = req.redirect_uris {
            app.redirect_uris = v;
        }
        if let Some(v) = req.token_format {
            app.token_format = v;
        }
        if let Some(v) = req.expire_in_hours {
            app.expire_in_hours = v;
        }
        if let Some(v) = req.refresh_expire_in_hours {
            app.refresh_expire_in_hours = v;
        }
        if let Some(v) = req.cert {
            app.cert = Some(v);
        }
        if let Some(v) = req.signup_url {
            app.signup_url = Some(v);
        }
        if let Some(v) = req.signin_url {
            app.signin_url = Some(v);
        }
        if let Some(v) = req.forget_url {
            app.forget_url = Some(v);
        }
        if let Some(v) = req.terms_of_use {
            app.terms_of_use = Some(v);
        }
        if let Some(v) = req.signup_html {
            app.signup_html = Some(v);
        }
        if let Some(v) = req.signin_html {
            app.signin_html = Some(v);
        }
        if let Some(v) = req.signup_items {
            app.signup_items = Some(v);
        }
        if let Some(v) = req.signin_items {
            app.signin_items = Some(v);
        }
        if let Some(v) = req.signin_methods {
            app.signin_methods = Some(v);
        }
        if let Some(v) = req.grant_types {
            app.grant_types = Some(v);
        }
        if let Some(v) = req.providers {
            app.providers = Some(v);
        }
        if let Some(v) = req.saml_reply_url {
            app.saml_reply_url = Some(v);
        }
        if let Some(v) = req.enable_password {
            app.enable_password = v;
        }
        if let Some(v) = req.enable_signin_session {
            app.enable_signin_session = v;
        }
        if let Some(v) = req.enable_auto_signin {
            app.enable_auto_signin = v;
        }
        if let Some(v) = req.enable_code_signin {
            app.enable_code_signin = v;
        }
        if let Some(v) = req.enable_saml_compress {
            app.enable_saml_compress = v;
        }
        if let Some(v) = req.enable_web_authn {
            app.enable_web_authn = v;
        }
        if let Some(v) = req.enable_link_with_email {
            app.enable_link_with_email = v;
        }
        if let Some(v) = req.enable_internal_signup {
            app.enable_internal_signup = v;
        }
        if let Some(v) = req.enable_idp_signup {
            app.enable_idp_signup = v;
        }
        if let Some(v) = req.form_offset {
            app.form_offset = v;
        }
        if let Some(v) = req.form_side_html {
            app.form_side_html = Some(v);
        }
        if let Some(v) = req.form_background_url {
            app.form_background_url = Some(v);
        }
        if let Some(v) = req.form_css {
            app.form_css = Some(v);
        }
        if let Some(v) = req.tags {
            app.tags = Some(v);
        }
        if let Some(v) = req.footer_text {
            app.footer_text = Some(v);
        }
        if let Some(v) = req.logout_url {
            app.logout_url = Some(v);
        }
        if let Some(v) = req.logout_redirect_uris {
            app.logout_redirect_uris = Some(v);
        }
        app.updated_at = Utc::now();

        let updated_app = diesel::update(applications::table.filter(applications::id.eq(id)))
            .set((
                applications::display_name.eq(&app.display_name),
                applications::logo.eq(&app.logo),
                applications::homepage_url.eq(&app.homepage_url),
                applications::description.eq(&app.description),
                applications::redirect_uris.eq(&app.redirect_uris),
                applications::token_format.eq(&app.token_format),
                applications::expire_in_hours.eq(app.expire_in_hours),
                applications::refresh_expire_in_hours.eq(app.refresh_expire_in_hours),
                applications::cert.eq(&app.cert),
                applications::signup_url.eq(&app.signup_url),
                applications::signin_url.eq(&app.signin_url),
                applications::forget_url.eq(&app.forget_url),
                applications::terms_of_use.eq(&app.terms_of_use),
                applications::signup_html.eq(&app.signup_html),
                applications::signin_html.eq(&app.signin_html),
                applications::signup_items.eq(&app.signup_items),
                applications::signin_items.eq(&app.signin_items),
                applications::signin_methods.eq(&app.signin_methods),
                applications::grant_types.eq(&app.grant_types),
                applications::providers.eq(&app.providers),
                applications::saml_reply_url.eq(&app.saml_reply_url),
                applications::enable_password.eq(app.enable_password),
                applications::enable_signin_session.eq(app.enable_signin_session),
                applications::enable_auto_signin.eq(app.enable_auto_signin),
                applications::enable_code_signin.eq(app.enable_code_signin),
                applications::enable_saml_compress.eq(app.enable_saml_compress),
                applications::enable_web_authn.eq(app.enable_web_authn),
                applications::enable_link_with_email.eq(app.enable_link_with_email),
                applications::enable_internal_signup.eq(app.enable_internal_signup),
                applications::enable_idp_signup.eq(app.enable_idp_signup),
                applications::form_offset.eq(app.form_offset),
                applications::form_side_html.eq(&app.form_side_html),
                applications::form_background_url.eq(&app.form_background_url),
                applications::form_css.eq(&app.form_css),
                applications::tags.eq(&app.tags),
                applications::footer_text.eq(&app.footer_text),
                applications::logout_url.eq(&app.logout_url),
                applications::logout_redirect_uris.eq(&app.logout_redirect_uris),
                applications::updated_at.eq(app.updated_at),
            ))
            .returning(Application::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(updated_app.into())
    }

    pub async fn delete(&self, id: &str) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let count = diesel::update(
            applications::table
                .filter(applications::id.eq(id))
                .filter(applications::is_deleted.eq(false)),
        )
        .set((
            applications::is_deleted.eq(true),
            applications::updated_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        if count == 0 {
            return Err(AppError::NotFound(format!(
                "Application with id '{}' not found",
                id
            )));
        }

        Ok(())
    }
}
