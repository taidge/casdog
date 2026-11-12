use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
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
        let mut tx = pool.begin().await?;
        // Cloud reconciliation holds Syncer before any users. Do not lock the
        // Group first: a running importer can still need its member rows.
        let _:Vec<String>=sqlx::query_scalar("SELECT s.id FROM syncers s JOIN syncer_group_links l ON l.syncer_id=s.id WHERE l.group_id=$1 ORDER BY s.id FOR UPDATE OF s")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
        let group: Option<(String, String)> =
            sqlx::query_as("SELECT owner,name FROM groups WHERE id=$1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((owner, name)) = group else {
            tx.commit().await?;
            return Ok(());
        };
        let qualified = format!("{owner}/{name}");
        let users:Vec<String>=sqlx::query_scalar("SELECT u.id FROM users u WHERE u.owner=$2 AND (CASE WHEN jsonb_typeof(u.groups)='array' THEN (u.groups ? $3 OR u.groups ? $4) ELSE false END OR EXISTS(SELECT 1 FROM user_groups ug WHERE ug.user_id=u.id AND ug.group_id=$1) OR EXISTS(SELECT 1 FROM syncer_group_memberships m WHERE m.user_id=u.id AND m.group_id=$1)) ORDER BY u.id FOR UPDATE OF u")
            .bind(id).bind(&owner).bind(&qualified).bind(&name).fetch_all(&mut *tx).await?;
        // jsonb subtraction preserves unknown array elements exactly; malformed
        // legacy non-array JSON and every foreign tenant remain untouched.
        sqlx::query("UPDATE users SET groups=(groups-$3::text)-$4::text,updated_at=clock_timestamp() WHERE id=ANY($1) AND owner=$2 AND jsonb_typeof(groups)='array' AND (groups ? $3 OR groups ? $4)")
            .bind(&users).bind(&owner).bind(&qualified).bind(&name).execute(&mut *tx).await?;
        let deleted = sqlx::query("DELETE FROM groups WHERE id=$1 AND owner=$2 AND name=$3")
            .bind(id)
            .bind(&owner)
            .bind(&name)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if deleted == 0
            && sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM groups WHERE id=$1)")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?
        {
            return Err(AppError::Conflict(
                "Group changed during deletion; retry with its current identity".into(),
            ));
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn add_user_to_group(pool: &PgPool, user_id: &str, group_id: &str) -> AppResult<()> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let mut tx = pool.begin().await?;
        // Directory reconciliation uses this same user -> ledger -> pair
        // ordering, so a concurrent manual add cannot lose its intent.
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;

        sqlx::query(
            r#"INSERT INTO user_groups (id, user_id, group_id, created_at)
            VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING"#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(group_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // An explicit administrator add preserves the membership even if a
        // directory previously created the same pair. Row identity alone
        // cannot express this later manual ownership of an existing pair.
        sqlx::query("UPDATE syncer_group_memberships SET manual_preserved=true WHERE user_id=$1 AND group_id=$2")
            .bind(user_id).bind(group_id).execute(&mut *tx).await?;
        tx.commit().await?;

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
            sqlx::query_as("SELECT ug.user_id FROM user_groups ug JOIN users u ON u.id=ug.user_id JOIN groups g ON g.id=ug.group_id WHERE ug.group_id=$1 AND u.owner=g.owner")
                .bind(group_id)
                .fetch_all(pool)
                .await?;
        Ok(users.into_iter().map(|(id,)| id).collect())
    }

    pub async fn get_groups_for_user(pool: &PgPool, user_id: &str) -> AppResult<Vec<String>> {
        let groups: Vec<(String,)> =
            sqlx::query_as("SELECT ug.group_id FROM user_groups ug JOIN users u ON u.id=ug.user_id JOIN groups g ON g.id=ug.group_id WHERE ug.user_id=$1 AND u.owner=g.owner")
                .bind(user_id)
                .fetch_all(pool)
                .await?;
        Ok(groups.into_iter().map(|(id,)| id).collect())
    }
}
