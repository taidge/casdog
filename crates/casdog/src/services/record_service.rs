use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{
    CreateRecordRequest, Record, RecordFilterRequest, RecordResponse, UpdateRecordRequest,
};

pub struct RecordService;

impl RecordService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<RecordResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let records: Vec<Record> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, created_at, organization, client_ip, "user",
                       method, request_uri, action, object, is_triggered
                FROM records
                WHERE owner = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(owner)
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, created_at, organization, client_ip, "user",
                       method, request_uri, action, object, is_triggered
                FROM records
                ORDER BY created_at DESC
                LIMIT $1 OFFSET $2
                "#,
            )
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?
        };

        let total: i64 = if let Some(owner) = owner {
            sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM records")
                .fetch_one(pool)
                .await?
        };

        Ok((records.into_iter().map(|r| r.into()).collect(), total))
    }

    pub async fn list_filtered(
        pool: &PgPool,
        filter: RecordFilterRequest,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<RecordResponse>, i64)> {
        let offset = (page - 1) * page_size;

        // Build dynamic query based on filters
        let mut query = String::from(
            r#"
            SELECT id, owner, name, created_at, organization, client_ip, "user",
                   method, request_uri, action, object, is_triggered
            FROM records
            WHERE 1=1
            "#,
        );

        let mut count_query = String::from("SELECT COUNT(*) FROM records WHERE 1=1");
        let mut param_idx = 1;

        if filter.organization.is_some() {
            query.push_str(&format!(" AND organization = ${}", param_idx));
            count_query.push_str(&format!(" AND organization = ${}", param_idx));
            param_idx += 1;
        }

        if filter.user.is_some() {
            query.push_str(&format!(" AND \"user\" = ${}", param_idx));
            count_query.push_str(&format!(" AND \"user\" = ${}", param_idx));
            param_idx += 1;
        }

        if filter.action.is_some() {
            query.push_str(&format!(" AND action = ${}", param_idx));
            count_query.push_str(&format!(" AND action = ${}", param_idx));
            param_idx += 1;
        }

        if filter.start_time.is_some() {
            query.push_str(&format!(" AND created_at >= ${}", param_idx));
            count_query.push_str(&format!(" AND created_at >= ${}", param_idx));
            param_idx += 1;
        }

        if filter.end_time.is_some() {
            query.push_str(&format!(" AND created_at <= ${}", param_idx));
            count_query.push_str(&format!(" AND created_at <= ${}", param_idx));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        // Execute with dynamic binding
        let mut sql_query = sqlx::query_as::<_, Record>(&query);

        if let Some(ref org) = filter.organization {
            sql_query = sql_query.bind(org);
        }
        if let Some(ref user) = filter.user {
            sql_query = sql_query.bind(user);
        }
        if let Some(ref action) = filter.action {
            sql_query = sql_query.bind(action);
        }
        if let Some(ref start_time) = filter.start_time {
            sql_query = sql_query.bind(start_time);
        }
        if let Some(ref end_time) = filter.end_time {
            sql_query = sql_query.bind(end_time);
        }

        sql_query = sql_query.bind(page_size).bind(offset);

        let records = sql_query.fetch_all(pool).await?;

        // Count query
        let mut count_sql = sqlx::query_scalar::<_, i64>(&count_query);

        if let Some(ref org) = filter.organization {
            count_sql = count_sql.bind(org);
        }
        if let Some(ref user) = filter.user {
            count_sql = count_sql.bind(user);
        }
        if let Some(ref action) = filter.action {
            count_sql = count_sql.bind(action);
        }
        if let Some(ref start_time) = filter.start_time {
            count_sql = count_sql.bind(start_time);
        }
        if let Some(ref end_time) = filter.end_time {
            count_sql = count_sql.bind(end_time);
        }

        let total = count_sql.fetch_one(pool).await?;

        Ok((records.into_iter().map(|r| r.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<RecordResponse> {
        let record: Record = sqlx::query_as(
            r#"
            SELECT id, owner, name, created_at, organization, client_ip, "user",
                   method, request_uri, action, object, is_triggered
            FROM records
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Record not found".to_string()))?;

        Ok(record.into())
    }

    pub async fn create(pool: &PgPool, req: CreateRecordRequest) -> AppResult<RecordResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO records (id, owner, name, created_at, organization, client_ip, "user",
                                 method, request_uri, action, object, is_triggered)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(now)
        .bind(&req.organization)
        .bind(&req.client_ip)
        .bind(&req.user)
        .bind(&req.method)
        .bind(&req.request_uri)
        .bind(&req.action)
        .bind(&req.object)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateRecordRequest,
    ) -> AppResult<RecordResponse> {
        let result = sqlx::query(
            r#"
            UPDATE records
            SET owner = $2,
                name = $3,
                organization = $4,
                client_ip = $5,
                "user" = $6,
                method = $7,
                request_uri = $8,
                action = $9,
                object = $10
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.organization)
        .bind(&req.client_ip)
        .bind(&req.user)
        .bind(&req.method)
        .bind(&req.request_uri)
        .bind(&req.action)
        .bind(&req.object)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Record not found".to_string()));
        }

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM records WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Record not found".to_string()));
        }

        Ok(())
    }

    /// Create a record for an API action (for audit logging)
    pub async fn log_action(
        pool: &PgPool,
        owner: &str,
        organization: Option<&str>,
        client_ip: Option<&str>,
        user: Option<&str>,
        method: &str,
        request_uri: &str,
        action: &str,
        object: Option<&str>,
    ) -> AppResult<()> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let name = format!("record_{}", &id[..8]);

        sqlx::query(
            r#"
            INSERT INTO records (id, owner, name, created_at, organization, client_ip, "user",
                                 method, request_uri, action, object, is_triggered)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false)
            "#,
        )
        .bind(&id)
        .bind(owner)
        .bind(&name)
        .bind(now)
        .bind(organization)
        .bind(client_ip)
        .bind(user)
        .bind(method)
        .bind(request_uri)
        .bind(action)
        .bind(object)
        .execute(pool)
        .await?;

        Ok(())
    }
}
