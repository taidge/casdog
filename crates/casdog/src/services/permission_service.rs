use crate::error::{AppError, AppResult};
use crate::models::{
    AssignPermissionRequest, CreatePermissionRequest, Permission, PermissionListResponse,
    PermissionQuery, PermissionResponse, UpdatePermissionRequest,
};
use chrono::Utc;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Clone)]
pub struct PermissionService {
    pool: Pool<Postgres>,
}

impl PermissionService {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub async fn create(&self, req: CreatePermissionRequest) -> AppResult<PermissionResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let permission = sqlx::query_as::<_, Permission>(
            r#"
            INSERT INTO permissions (id, owner, name, display_name, description, resource_type, resources, actions, effect, is_enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.resource_type)
        .bind(&req.resources)
        .bind(&req.actions)
        .bind(req.effect.unwrap_or_else(|| "allow".to_string()))
        .bind(req.is_enabled.unwrap_or(true))
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
                AppError::Conflict(format!("Permission '{}' already exists in '{}'", req.name, req.owner))
            }
            _ => AppError::Database(e),
        })?;

        Ok(permission.into())
    }

    pub async fn get_by_id(&self, id: &str) -> AppResult<PermissionResponse> {
        let permission = sqlx::query_as::<_, Permission>(
            "SELECT * FROM permissions WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Permission with id '{}' not found", id)))?;

        Ok(permission.into())
    }

    pub async fn list(&self, query: PermissionQuery) -> AppResult<PermissionListResponse> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).min(100);
        let offset = (page - 1) * page_size;

        let (permissions, total): (Vec<Permission>, i64) = if let Some(owner) = &query.owner {
            let permissions = sqlx::query_as::<_, Permission>(
                "SELECT * FROM permissions WHERE owner = $1 AND is_deleted = FALSE ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(owner)
            .bind(page_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

            let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM permissions WHERE owner = $1 AND is_deleted = FALSE",
            )
            .bind(owner)
            .fetch_one(&self.pool)
            .await?;

            (permissions, total.0)
        } else {
            let permissions = sqlx::query_as::<_, Permission>(
                "SELECT * FROM permissions WHERE is_deleted = FALSE ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            )
            .bind(page_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

            let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM permissions WHERE is_deleted = FALSE",
            )
            .fetch_one(&self.pool)
            .await?;

            (permissions, total.0)
        };

        Ok(PermissionListResponse {
            data: permissions.into_iter().map(|p| p.into()).collect(),
            total,
            page,
            page_size,
        })
    }

    pub async fn update(&self, id: &str, req: UpdatePermissionRequest) -> AppResult<PermissionResponse> {
        let mut permission = sqlx::query_as::<_, Permission>(
            "SELECT * FROM permissions WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Permission with id '{}' not found", id)))?;

        if let Some(display_name) = req.display_name {
            permission.display_name = display_name;
        }
        if let Some(description) = req.description {
            permission.description = Some(description);
        }
        if let Some(resource_type) = req.resource_type {
            permission.resource_type = resource_type;
        }
        if let Some(resources) = req.resources {
            permission.resources = resources;
        }
        if let Some(actions) = req.actions {
            permission.actions = actions;
        }
        if let Some(effect) = req.effect {
            permission.effect = effect;
        }
        if let Some(is_enabled) = req.is_enabled {
            permission.is_enabled = is_enabled;
        }
        permission.updated_at = Utc::now();

        let updated_permission = sqlx::query_as::<_, Permission>(
            r#"
            UPDATE permissions
            SET display_name = $1, description = $2, resource_type = $3, resources = $4, actions = $5, effect = $6, is_enabled = $7, updated_at = $8
            WHERE id = $9
            RETURNING *
            "#,
        )
        .bind(&permission.display_name)
        .bind(&permission.description)
        .bind(&permission.resource_type)
        .bind(&permission.resources)
        .bind(&permission.actions)
        .bind(&permission.effect)
        .bind(permission.is_enabled)
        .bind(permission.updated_at)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        Ok(updated_permission.into())
    }

    pub async fn delete(&self, id: &str) -> AppResult<()> {
        let result = sqlx::query(
            "UPDATE permissions SET is_deleted = TRUE, updated_at = $1 WHERE id = $2 AND is_deleted = FALSE",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!(
                "Permission with id '{}' not found",
                id
            )));
        }

        Ok(())
    }

    pub async fn assign_permission(&self, req: AssignPermissionRequest) -> AppResult<()> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO role_permissions (id, role_id, permission_id, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (role_id, permission_id) DO NOTHING
            "#,
        )
        .bind(&id)
        .bind(&req.role_id)
        .bind(&req.permission_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn remove_permission(&self, role_id: &str, permission_id: &str) -> AppResult<()> {
        let result =
            sqlx::query("DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2")
                .bind(role_id)
                .bind(permission_id)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!(
                "Permission assignment not found for role '{}' and permission '{}'",
                role_id, permission_id
            )));
        }

        Ok(())
    }

    pub async fn get_role_permissions(&self, role_id: &str) -> AppResult<Vec<PermissionResponse>> {
        let permissions = sqlx::query_as::<_, Permission>(
            r#"
            SELECT p.* FROM permissions p
            INNER JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = $1 AND p.is_deleted = FALSE
            "#,
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions.into_iter().map(|p| p.into()).collect())
    }
}
