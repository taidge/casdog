use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::{
    CreateOrganizationRequest, Organization, OrganizationListResponse, OrganizationQuery,
    OrganizationResponse, UpdateOrganizationRequest,
};
use crate::schema::organizations;

#[derive(Clone)]
pub struct OrgService {
    pool: DieselPool,
}

impl OrgService {
    pub fn new(pool: DieselPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, req: CreateOrganizationRequest) -> AppResult<OrganizationResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let org = diesel::insert_into(organizations::table)
            .values((
                organizations::id.eq(&id),
                organizations::owner.eq(&req.owner),
                organizations::name.eq(&req.name),
                organizations::display_name.eq(&req.display_name),
                organizations::website_url.eq(&req.website_url),
                organizations::logo.eq(&req.logo),
                organizations::logo_dark.eq(&req.logo_dark),
                organizations::favicon.eq(&req.favicon),
                organizations::password_type
                    .eq(req.password_type.unwrap_or_else(|| "argon2".to_string())),
                organizations::default_avatar.eq(&req.default_avatar),
                organizations::default_application.eq(&req.default_application),
                organizations::country_codes.eq(&req.country_codes),
                organizations::languages.eq(&req.languages),
                organizations::tags.eq(&req.tags),
                organizations::init_score.eq(req.init_score.unwrap_or(0)),
                organizations::password_options.eq(&req.password_options),
                organizations::password_expire_days.eq(req.password_expire_days.unwrap_or(0)),
                organizations::default_password.eq(&req.default_password),
                organizations::account_items.eq(&req.account_items),
                organizations::mfa_items.eq(&req.mfa_items),
                organizations::created_at.eq(now),
                organizations::updated_at.eq(now),
            ))
            .returning(Organization::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                ) => AppError::Conflict(format!("Organization '{}' already exists", req.name)),
                _ => AppError::Internal(e.to_string()),
            })?;

        Ok(org.into())
    }

    pub async fn get_by_id(&self, id: &str) -> AppResult<OrganizationResponse> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let org = organizations::table
            .filter(organizations::id.eq(id))
            .filter(organizations::is_deleted.eq(false))
            .select(Organization::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| {
                AppError::NotFound(format!("Organization with id '{}' not found", id))
            })?;

        Ok(org.into())
    }

    pub async fn get_by_name(&self, name: &str) -> AppResult<OrganizationResponse> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let org = organizations::table
            .filter(organizations::name.eq(name))
            .filter(organizations::is_deleted.eq(false))
            .select(Organization::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("Organization '{}' not found", name)))?;

        Ok(org.into())
    }

    pub async fn get_internal(&self, name: &str) -> AppResult<Organization> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let org = organizations::table
            .filter(organizations::name.eq(name))
            .filter(organizations::is_deleted.eq(false))
            .select(Organization::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("Organization '{}' not found", name)))?;

        Ok(org)
    }

    pub async fn list(&self, query: OrganizationQuery) -> AppResult<OrganizationListResponse> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).min(100);
        let offset = (page - 1) * page_size;

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let (orgs, total): (Vec<Organization>, i64) = if let Some(ref owner) = query.owner {
            let orgs = organizations::table
                .filter(organizations::owner.eq(owner))
                .filter(organizations::is_deleted.eq(false))
                .order(organizations::created_at.desc())
                .limit(page_size)
                .offset(offset)
                .select(Organization::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let total: i64 = organizations::table
                .filter(organizations::owner.eq(owner))
                .filter(organizations::is_deleted.eq(false))
                .count()
                .get_result(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            (orgs, total)
        } else {
            let orgs = organizations::table
                .filter(organizations::is_deleted.eq(false))
                .order(organizations::created_at.desc())
                .limit(page_size)
                .offset(offset)
                .select(Organization::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let total: i64 = organizations::table
                .filter(organizations::is_deleted.eq(false))
                .count()
                .get_result(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            (orgs, total)
        };

        Ok(OrganizationListResponse {
            data: orgs.into_iter().map(|o| o.into()).collect(),
            total,
            page,
            page_size,
        })
    }

    pub async fn update(
        &self,
        id: &str,
        req: UpdateOrganizationRequest,
    ) -> AppResult<OrganizationResponse> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let mut org = organizations::table
            .filter(organizations::id.eq(id))
            .filter(organizations::is_deleted.eq(false))
            .select(Organization::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| {
                AppError::NotFound(format!("Organization with id '{}' not found", id))
            })?;

        if let Some(v) = req.display_name {
            org.display_name = v;
        }
        if let Some(v) = req.website_url {
            org.website_url = Some(v);
        }
        if let Some(v) = req.logo {
            org.logo = Some(v);
        }
        if let Some(v) = req.logo_dark {
            org.logo_dark = Some(v);
        }
        if let Some(v) = req.favicon {
            org.favicon = Some(v);
        }
        if let Some(v) = req.password_type {
            org.password_type = v;
        }
        if let Some(v) = req.default_avatar {
            org.default_avatar = Some(v);
        }
        if let Some(v) = req.password_salt {
            org.password_salt = Some(v);
        }
        if let Some(v) = req.password_options {
            org.password_options = Some(v);
        }
        if let Some(v) = req.password_obfuscator_type {
            org.password_obfuscator_type = Some(v);
        }
        if let Some(v) = req.password_obfuscator_key {
            org.password_obfuscator_key = Some(v);
        }
        if let Some(v) = req.password_expire_days {
            org.password_expire_days = v;
        }
        if let Some(v) = req.default_password {
            org.default_password = Some(v);
        }
        if let Some(v) = req.master_password {
            org.master_password = Some(v);
        }
        if let Some(v) = req.user_types {
            org.user_types = Some(v);
        }
        if let Some(v) = req.tags {
            org.tags = Some(v);
        }
        if let Some(v) = req.country_codes {
            org.country_codes = Some(v);
        }
        if let Some(v) = req.default_application {
            org.default_application = Some(v);
        }
        if let Some(v) = req.init_score {
            org.init_score = v;
        }
        if let Some(v) = req.languages {
            org.languages = Some(v);
        }
        if let Some(v) = req.theme_data {
            org.theme_data = Some(v);
        }
        if let Some(v) = req.account_menu {
            org.account_menu = Some(v);
        }
        if let Some(v) = req.enable_soft_deletion {
            org.enable_soft_deletion = v;
        }
        if let Some(v) = req.is_profile_public {
            org.is_profile_public = v;
        }
        if let Some(v) = req.use_email_as_username {
            org.use_email_as_username = v;
        }
        if let Some(v) = req.enable_tour {
            org.enable_tour = v;
        }
        if let Some(v) = req.disable_signin {
            org.disable_signin = v;
        }
        if let Some(v) = req.ip_restriction {
            org.ip_restriction = Some(v);
        }
        if let Some(v) = req.ip_whitelist {
            org.ip_whitelist = Some(v);
        }
        if let Some(v) = req.has_privilege_consent {
            org.has_privilege_consent = v;
        }
        if let Some(v) = req.account_items {
            org.account_items = Some(v);
        }
        if let Some(v) = req.nav_items {
            org.nav_items = Some(v);
        }
        if let Some(v) = req.mfa_items {
            org.mfa_items = Some(v);
        }
        if let Some(v) = req.mfa_remember_in_hours {
            org.mfa_remember_in_hours = v;
        }
        if let Some(v) = req.balance_currency {
            org.balance_currency = Some(v);
        }
        org.updated_at = Utc::now();

        let updated_org = diesel::update(organizations::table.filter(organizations::id.eq(id)))
            .set((
                organizations::display_name.eq(&org.display_name),
                organizations::website_url.eq(&org.website_url),
                organizations::logo.eq(&org.logo),
                organizations::logo_dark.eq(&org.logo_dark),
                organizations::favicon.eq(&org.favicon),
                organizations::password_type.eq(&org.password_type),
                organizations::default_avatar.eq(&org.default_avatar),
                organizations::password_salt.eq(&org.password_salt),
                organizations::password_options.eq(&org.password_options),
                organizations::password_obfuscator_type.eq(&org.password_obfuscator_type),
                organizations::password_obfuscator_key.eq(&org.password_obfuscator_key),
                organizations::password_expire_days.eq(org.password_expire_days),
                organizations::default_password.eq(&org.default_password),
                organizations::master_password.eq(&org.master_password),
                organizations::user_types.eq(&org.user_types),
                organizations::tags.eq(&org.tags),
                organizations::country_codes.eq(&org.country_codes),
                organizations::default_application.eq(&org.default_application),
                organizations::init_score.eq(org.init_score),
                organizations::languages.eq(&org.languages),
                organizations::theme_data.eq(&org.theme_data),
                organizations::account_menu.eq(&org.account_menu),
                organizations::enable_soft_deletion.eq(org.enable_soft_deletion),
                organizations::is_profile_public.eq(org.is_profile_public),
                organizations::use_email_as_username.eq(org.use_email_as_username),
                organizations::enable_tour.eq(org.enable_tour),
                organizations::disable_signin.eq(org.disable_signin),
                organizations::ip_restriction.eq(&org.ip_restriction),
                organizations::ip_whitelist.eq(&org.ip_whitelist),
                organizations::has_privilege_consent.eq(org.has_privilege_consent),
                organizations::account_items.eq(&org.account_items),
                organizations::nav_items.eq(&org.nav_items),
                organizations::mfa_items.eq(&org.mfa_items),
                organizations::mfa_remember_in_hours.eq(org.mfa_remember_in_hours),
                organizations::balance_currency.eq(&org.balance_currency),
                organizations::updated_at.eq(org.updated_at),
            ))
            .returning(Organization::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(updated_org.into())
    }

    pub async fn delete(&self, id: &str) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let count = diesel::update(
            organizations::table
                .filter(organizations::id.eq(id))
                .filter(organizations::is_deleted.eq(false)),
        )
        .set((
            organizations::is_deleted.eq(true),
            organizations::updated_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        if count == 0 {
            return Err(AppError::NotFound(format!(
                "Organization with id '{}' not found",
                id
            )));
        }

        Ok(())
    }
}
