use chrono::Utc;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{
    AssignRoleRequest, CreateRoleRequest, Role, RoleListResponse, RoleQuery, RoleResponse,
    UpdateRoleRequest,
};

#[derive(Clone)]
pub struct RoleService {
    pool: Pool<Postgres>,
}

impl RoleService {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub async fn create(&self, req: CreateRoleRequest) -> AppResult<RoleResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let role = sqlx::query_as::<_, Role>(
            r#"
            INSERT INTO roles (id, owner, name, display_name, description, is_enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(req.is_enabled.unwrap_or(true))
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
                AppError::Conflict(format!("Role '{}' already exists in '{}'", req.name, req.owner))
            }
            _ => AppError::Database(e),
        })?;

        Ok(role.into())
    }

    pub async fn get_by_id(&self, id: &str) -> AppResult<RoleResponse> {
        let role =
            sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = $1 AND is_deleted = FALSE")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| AppError::NotFound(format!("Role with id '{}' not found", id)))?;

        Ok(role.into())
    }

    pub async fn list(&self, query: RoleQuery) -> AppResult<RoleListResponse> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).min(100);
        let offset = (page - 1) * page_size;

        let (roles, total): (Vec<Role>, i64) = if let Some(owner) = &query.owner {
            let roles = sqlx::query_as::<_, Role>(
                "SELECT * FROM roles WHERE owner = $1 AND is_deleted = FALSE ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(owner)
            .bind(page_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

            let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM roles WHERE owner = $1 AND is_deleted = FALSE",
            )
            .bind(owner)
            .fetch_one(&self.pool)
            .await?;

            (roles, total.0)
        } else {
            let roles = sqlx::query_as::<_, Role>(
                "SELECT * FROM roles WHERE is_deleted = FALSE ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            )
            .bind(page_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

            let total: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM roles WHERE is_deleted = FALSE")
                    .fetch_one(&self.pool)
                    .await?;

            (roles, total.0)
        };

        Ok(RoleListResponse {
            data: roles.into_iter().map(|r| r.into()).collect(),
            total,
            page,
            page_size,
        })
    }

    pub async fn update(&self, id: &str, req: UpdateRoleRequest) -> AppResult<RoleResponse> {
        let mut role =
            sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = $1 AND is_deleted = FALSE")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| AppError::NotFound(format!("Role with id '{}' not found", id)))?;

        if let Some(display_name) = req.display_name {
            role.display_name = display_name;
        }
        if let Some(description) = req.description {
            role.description = Some(description);
        }
        if let Some(is_enabled) = req.is_enabled {
            role.is_enabled = is_enabled;
        }
        role.updated_at = Utc::now();

        let updated_role = sqlx::query_as::<_, Role>(
            r#"
            UPDATE roles
            SET display_name = $1, description = $2, is_enabled = $3, updated_at = $4
            WHERE id = $5
            RETURNING *
            "#,
        )
        .bind(&role.display_name)
        .bind(&role.description)
        .bind(role.is_enabled)
        .bind(role.updated_at)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        Ok(updated_role.into())
    }

    pub async fn delete(&self, id: &str) -> AppResult<()> {
        let result = sqlx::query(
            "UPDATE roles SET is_deleted = TRUE, updated_at = $1 WHERE id = $2 AND is_deleted = FALSE",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!(
                "Role with id '{}' not found",
                id
            )));
        }

        Ok(())
    }

    pub async fn assign_role(&self, req: AssignRoleRequest) -> AppResult<()> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO user_roles (id, user_id, role_id, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, role_id) DO NOTHING
            "#,
        )
        .bind(&id)
        .bind(&req.user_id)
        .bind(&req.role_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn remove_role(&self, user_id: &str, role_id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2")
            .bind(user_id)
            .bind(role_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!(
                "User role assignment not found for user '{}' and role '{}'",
                user_id, role_id
            )));
        }

        Ok(())
    }

    pub async fn get_user_roles(&self, user_id: &str) -> AppResult<Vec<RoleResponse>> {
        let roles = sqlx::query_as::<_, Role>(
            r#"
            SELECT r.* FROM roles r
            INNER JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = $1 AND r.is_deleted = FALSE
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(roles.into_iter().map(|r| r.into()).collect())
    }
}
