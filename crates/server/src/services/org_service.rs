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
            INSERT INTO organizations (id, owner, name, display_name, website_url, favicon, password_type, default_avatar, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.website_url)
        .bind(&req.favicon)
        .bind(req.password_type.unwrap_or_else(|| "argon2".to_string()))
        .bind(&req.default_avatar)
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

        if let Some(display_name) = req.display_name {
            org.display_name = display_name;
        }
        if let Some(website_url) = req.website_url {
            org.website_url = Some(website_url);
        }
        if let Some(favicon) = req.favicon {
            org.favicon = Some(favicon);
        }
        if let Some(password_type) = req.password_type {
            org.password_type = password_type;
        }
        if let Some(default_avatar) = req.default_avatar {
            org.default_avatar = Some(default_avatar);
        }
        org.updated_at = Utc::now();

        let updated_org = sqlx::query_as::<_, Organization>(
            r#"
            UPDATE organizations
            SET display_name = $1, website_url = $2, favicon = $3, password_type = $4, default_avatar = $5, updated_at = $6
            WHERE id = $7
            RETURNING *
            "#,
        )
        .bind(&org.display_name)
        .bind(&org.website_url)
        .bind(&org.favicon)
        .bind(&org.password_type)
        .bind(&org.default_avatar)
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
