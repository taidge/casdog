use crate::error::{AppError, AppResult};
use crate::models::{
    CreateOrganizationRequest, Organization, OrganizationListResponse, OrganizationQuery,
    OrganizationResponse, UpdateOrganizationRequest,
};
use chrono::Utc;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Clone)]
pub struct OrgService {
    pool: Pool<Postgres>,
}

impl OrgService {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub async fn create(&self, req: CreateOrganizationRequest) -> AppResult<OrganizationResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let org = sqlx::query_as::<_, Organization>(
            r#"
            INSERT INTO organizations (
                id, owner, name, display_name, website_url, logo, logo_dark, favicon,
                password_type, default_avatar, default_application, country_codes, languages,
                tags, init_score, password_options, password_expire_days, default_password,
                account_items, mfa_items, created_at, updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8,
                $9, $10, $11, $12, $13,
                $14, $15, $16, $17, $18,
                $19, $20, $21, $22
            )
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.website_url)
        .bind(&req.logo)
        .bind(&req.logo_dark)
        .bind(&req.favicon)
        .bind(req.password_type.unwrap_or_else(|| "argon2".to_string()))
        .bind(&req.default_avatar)
        .bind(&req.default_application)
        .bind(&req.country_codes)
        .bind(&req.languages)
        .bind(&req.tags)
        .bind(req.init_score.unwrap_or(0))
        .bind(&req.password_options)
        .bind(req.password_expire_days.unwrap_or(0))
        .bind(&req.default_password)
        .bind(&req.account_items)
        .bind(&req.mfa_items)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
                AppError::Conflict(format!("Organization '{}' already exists", req.name))
            }
            _ => AppError::Database(e),
        })?;

        Ok(org.into())
    }

    pub async fn get_by_id(&self, id: &str) -> AppResult<OrganizationResponse> {
        let org = sqlx::query_as::<_, Organization>(
            "SELECT * FROM organizations WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Organization with id '{}' not found", id)))?;

        Ok(org.into())
    }

    pub async fn get_by_name(&self, name: &str) -> AppResult<OrganizationResponse> {
        let org = sqlx::query_as::<_, Organization>(
            "SELECT * FROM organizations WHERE name = $1 AND is_deleted = FALSE",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Organization '{}' not found", name)))?;

        Ok(org.into())
    }

    pub async fn get_internal(&self, name: &str) -> AppResult<Organization> {
        let org = sqlx::query_as::<_, Organization>(
            "SELECT * FROM organizations WHERE name = $1 AND is_deleted = FALSE",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Organization '{}' not found", name)))?;

        Ok(org)
    }

    pub async fn list(&self, query: OrganizationQuery) -> AppResult<OrganizationListResponse> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).min(100);
        let offset = (page - 1) * page_size;

        let (orgs, total): (Vec<Organization>, i64) = if let Some(owner) = &query.owner {
            let orgs = sqlx::query_as::<_, Organization>(
                "SELECT * FROM organizations WHERE owner = $1 AND is_deleted = FALSE ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(owner)
            .bind(page_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

            let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM organizations WHERE owner = $1 AND is_deleted = FALSE",
            )
            .bind(owner)
            .fetch_one(&self.pool)
            .await?;

            (orgs, total.0)
        } else {
            let orgs = sqlx::query_as::<_, Organization>(
                "SELECT * FROM organizations WHERE is_deleted = FALSE ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            )
            .bind(page_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

            let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM organizations WHERE is_deleted = FALSE",
            )
            .fetch_one(&self.pool)
            .await?;

            (orgs, total.0)
        };

        Ok(OrganizationListResponse {
            data: orgs.into_iter().map(|o| o.into()).collect(),
            total,
            page,
            page_size,
        })
    }

    pub async fn update(&self, id: &str, req: UpdateOrganizationRequest) -> AppResult<OrganizationResponse> {
        let mut org = sqlx::query_as::<_, Organization>(
            "SELECT * FROM organizations WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Organization with id '{}' not found", id)))?;

        if let Some(v) = req.display_name { org.display_name = v; }
        if let Some(v) = req.website_url { org.website_url = Some(v); }
        if let Some(v) = req.logo { org.logo = Some(v); }
        if let Some(v) = req.logo_dark { org.logo_dark = Some(v); }
        if let Some(v) = req.favicon { org.favicon = Some(v); }
        if let Some(v) = req.password_type { org.password_type = v; }
        if let Some(v) = req.default_avatar { org.default_avatar = Some(v); }
        if let Some(v) = req.password_salt { org.password_salt = Some(v); }
        if let Some(v) = req.password_options { org.password_options = Some(v); }
        if let Some(v) = req.password_obfuscator_type { org.password_obfuscator_type = Some(v); }
        if let Some(v) = req.password_obfuscator_key { org.password_obfuscator_key = Some(v); }
        if let Some(v) = req.password_expire_days { org.password_expire_days = v; }
        if let Some(v) = req.default_password { org.default_password = Some(v); }
        if let Some(v) = req.master_password { org.master_password = Some(v); }
        if let Some(v) = req.user_types { org.user_types = Some(v); }
        if let Some(v) = req.tags { org.tags = Some(v); }
        if let Some(v) = req.country_codes { org.country_codes = Some(v); }
        if let Some(v) = req.default_application { org.default_application = Some(v); }
        if let Some(v) = req.init_score { org.init_score = v; }
        if let Some(v) = req.languages { org.languages = Some(v); }
        if let Some(v) = req.theme_data { org.theme_data = Some(v); }
        if let Some(v) = req.account_menu { org.account_menu = Some(v); }
        if let Some(v) = req.enable_soft_deletion { org.enable_soft_deletion = v; }
        if let Some(v) = req.is_profile_public { org.is_profile_public = v; }
        if let Some(v) = req.use_email_as_username { org.use_email_as_username = v; }
        if let Some(v) = req.enable_tour { org.enable_tour = v; }
        if let Some(v) = req.disable_signin { org.disable_signin = v; }
        if let Some(v) = req.ip_restriction { org.ip_restriction = Some(v); }
        if let Some(v) = req.ip_whitelist { org.ip_whitelist = Some(v); }
        if let Some(v) = req.has_privilege_consent { org.has_privilege_consent = v; }
        if let Some(v) = req.account_items { org.account_items = Some(v); }
        if let Some(v) = req.nav_items { org.nav_items = Some(v); }
        if let Some(v) = req.mfa_items { org.mfa_items = Some(v); }
        if let Some(v) = req.mfa_remember_in_hours { org.mfa_remember_in_hours = v; }
        if let Some(v) = req.balance_currency { org.balance_currency = Some(v); }
        org.updated_at = Utc::now();

        let updated_org = sqlx::query_as::<_, Organization>(
            r#"
            UPDATE organizations SET
                display_name = $1, website_url = $2, logo = $3, logo_dark = $4, favicon = $5,
                password_type = $6, default_avatar = $7, password_salt = $8, password_options = $9,
                password_obfuscator_type = $10, password_obfuscator_key = $11, password_expire_days = $12,
                default_password = $13, master_password = $14, user_types = $15, tags = $16,
                country_codes = $17, default_application = $18, init_score = $19, languages = $20,
                theme_data = $21, account_menu = $22, enable_soft_deletion = $23, is_profile_public = $24,
                use_email_as_username = $25, enable_tour = $26, disable_signin = $27,
                ip_restriction = $28, ip_whitelist = $29, has_privilege_consent = $30,
                account_items = $31, nav_items = $32, mfa_items = $33, mfa_remember_in_hours = $34,
                balance_currency = $35, updated_at = $36
            WHERE id = $37
            RETURNING *
            "#,
        )
        .bind(&org.display_name)
        .bind(&org.website_url)
        .bind(&org.logo)
        .bind(&org.logo_dark)
        .bind(&org.favicon)
        .bind(&org.password_type)
        .bind(&org.default_avatar)
        .bind(&org.password_salt)
        .bind(&org.password_options)
        .bind(&org.password_obfuscator_type)
        .bind(&org.password_obfuscator_key)
        .bind(org.password_expire_days)
        .bind(&org.default_password)
        .bind(&org.master_password)
        .bind(&org.user_types)
        .bind(&org.tags)
        .bind(&org.country_codes)
        .bind(&org.default_application)
        .bind(org.init_score)
        .bind(&org.languages)
        .bind(&org.theme_data)
        .bind(&org.account_menu)
        .bind(org.enable_soft_deletion)
        .bind(org.is_profile_public)
        .bind(org.use_email_as_username)
        .bind(org.enable_tour)
        .bind(org.disable_signin)
        .bind(&org.ip_restriction)
        .bind(&org.ip_whitelist)
        .bind(org.has_privilege_consent)
        .bind(&org.account_items)
        .bind(&org.nav_items)
        .bind(&org.mfa_items)
        .bind(org.mfa_remember_in_hours)
        .bind(&org.balance_currency)
        .bind(org.updated_at)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        Ok(updated_org.into())
    }

    pub async fn delete(&self, id: &str) -> AppResult<()> {
        let result = sqlx::query(
            "UPDATE organizations SET is_deleted = TRUE, updated_at = $1 WHERE id = $2 AND is_deleted = FALSE",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!(
                "Organization with id '{}' not found",
                id
            )));
        }

        Ok(())
    }
}
