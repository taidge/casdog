use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppResult;
use crate::models::{CreateGroupRequest, Group, GroupResponse, UpdateGroupRequest};

pub struct GroupService;

impl GroupService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<GroupResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let (groups, total): (Vec<Group>, i64) = if let Some(owner) = owner {
            let groups = sqlx::query_as::<_, Group>(
                r#"SELECT * FROM groups WHERE owner = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"#
            )
            .bind(owner)
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM groups WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?;

            (groups, total.0)
        } else {
            let groups = sqlx::query_as::<_, Group>(
                r#"SELECT * FROM groups ORDER BY created_at DESC LIMIT $1 OFFSET $2"#,
            )
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM groups")
                .fetch_one(pool)
                .await?;

            (groups, total.0)
        };

        Ok((groups.into_iter().map(Into::into).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<GroupResponse> {
        let group = sqlx::query_as::<_, Group>("SELECT * FROM groups WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await?;
        Ok(group.into())
    }

    pub async fn create(pool: &PgPool, req: CreateGroupRequest) -> AppResult<GroupResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let group = sqlx::query_as::<_, Group>(
            r#"INSERT INTO groups (
                id, owner, name, created_at, updated_at, display_name, manager,
                contact_email, type, parent_id, is_top_group, is_enabled
            ) VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *"#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(now)
        .bind(&req.display_name)
        .bind(&req.manager)
        .bind(&req.contact_email)
        .bind(&req.group_type)
        .bind(&req.parent_id)
        .bind(req.is_top_group.unwrap_or(false))
        .bind(req.is_enabled.unwrap_or(true))
        .fetch_one(pool)
        .await?;

        Ok(group.into())
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateGroupRequest,
    ) -> AppResult<GroupResponse> {
        let now = Utc::now();

        let group = sqlx::query_as::<_, Group>(
            r#"UPDATE groups SET
                updated_at = $2,
                display_name = COALESCE($3, display_name),
                manager = COALESCE($4, manager),
                contact_email = COALESCE($5, contact_email),
                type = COALESCE($6, type),
                parent_id = COALESCE($7, parent_id),
                is_top_group = COALESCE($8, is_top_group),
                is_enabled = COALESCE($9, is_enabled)
            WHERE id = $1 RETURNING *"#,
        )
        .bind(id)
        .bind(now)
        .bind(&req.display_name)
        .bind(&req.manager)
        .bind(&req.contact_email)
        .bind(&req.group_type)
        .bind(&req.parent_id)
        .bind(&req.is_top_group)
        .bind(&req.is_enabled)
        .fetch_one(pool)
        .await?;

        Ok(group.into())
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn add_user_to_group(pool: &PgPool, user_id: &str, group_id: &str) -> AppResult<()> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"INSERT INTO user_groups (id, user_id, group_id, created_at)
            VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING"#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(group_id)
        .bind(now)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn remove_user_from_group(
        pool: &PgPool,
        user_id: &str,
        group_id: &str,
    ) -> AppResult<()> {
        sqlx::query("DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2")
            .bind(user_id)
            .bind(group_id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn get_users_in_group(pool: &PgPool, group_id: &str) -> AppResult<Vec<String>> {
        let users: Vec<(String,)> =
            sqlx::query_as("SELECT user_id FROM user_groups WHERE group_id = $1")
                .bind(group_id)
                .fetch_all(pool)
                .await?;
        Ok(users.into_iter().map(|(id,)| id).collect())
    }

    pub async fn get_groups_for_user(pool: &PgPool, user_id: &str) -> AppResult<Vec<String>> {
        let groups: Vec<(String,)> =
            sqlx::query_as("SELECT group_id FROM user_groups WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(pool)
                .await?;
        Ok(groups.into_iter().map(|(id,)| id).collect())
    }
}
