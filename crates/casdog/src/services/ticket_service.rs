use crate::error::{AppError, AppResult};
use crate::models::{CreateTicketRequest, Ticket, TicketResponse, UpdateTicketRequest};
use sqlx::PgPool;
use uuid::Uuid;

pub struct TicketService;

impl TicketService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        status: Option<&str>,
        assignee: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<TicketResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let mut query = String::from(
            r#"
            SELECT id, owner, name, display_name, ticket_type, subject, content, status,
                   priority, assignee, reporter, comments, tags, is_deleted,
                   created_at, updated_at
            FROM tickets
            WHERE is_deleted = false
            "#,
        );

        let mut conditions: Vec<String> = Vec::new();
        if owner.is_some() {
            conditions.push("owner = $1".to_string());
        }
        if status.is_some() {
            conditions.push(format!("status = ${}", conditions.len() + 1));
        }
        if assignee.is_some() {
            conditions.push(format!("assignee = ${}", conditions.len() + 1));
        }

        if !conditions.is_empty() {
            query.push_str(" AND ");
            query.push_str(&conditions.join(" AND "));
        }

        query.push_str(" ORDER BY created_at DESC LIMIT $");
        query.push_str(&(conditions.len() + 1).to_string());
        query.push_str(" OFFSET $");
        query.push_str(&(conditions.len() + 2).to_string());

        let mut q = sqlx::query_as::<_, Ticket>(&query);
        if let Some(o) = owner {
            q = q.bind(o);
        }
        if let Some(s) = status {
            q = q.bind(s);
        }
        if let Some(a) = assignee {
            q = q.bind(a);
        }
        q = q.bind(page_size).bind(offset);

        let tickets = q.fetch_all(pool).await?;

        let mut count_query = String::from("SELECT COUNT(*) FROM tickets WHERE is_deleted = false");
        if !conditions.is_empty() {
            count_query.push_str(" AND ");
            let count_conditions: Vec<String> = (1..=conditions.len())
                .map(|i| {
                    if i == 1 && owner.is_some() {
                        "owner = $1".to_string()
                    } else if (i == 2 && owner.is_some() || i == 1 && owner.is_none()) && status.is_some() {
                        format!("status = ${}", i)
                    } else {
                        format!("assignee = ${}", i)
                    }
                })
                .collect();
            count_query.push_str(&count_conditions.join(" AND "));
        }

        let mut cq = sqlx::query_scalar::<_, i64>(&count_query);
        if let Some(o) = owner {
            cq = cq.bind(o);
        }
        if let Some(s) = status {
            cq = cq.bind(s);
        }
        if let Some(a) = assignee {
            cq = cq.bind(a);
        }

        let total = cq.fetch_one(pool).await?;

        Ok((tickets.into_iter().map(|t| t.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<TicketResponse> {
        let ticket: Ticket = sqlx::query_as(
            r#"
            SELECT id, owner, name, display_name, ticket_type, subject, content, status,
                   priority, assignee, reporter, comments, tags, is_deleted,
                   created_at, updated_at
            FROM tickets
            WHERE id = $1 AND is_deleted = false
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Ticket not found".to_string()))?;

        Ok(ticket.into())
    }

    pub async fn create(pool: &PgPool, req: CreateTicketRequest) -> AppResult<TicketResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO tickets (id, owner, name, display_name, ticket_type, subject, content,
                                 status, priority, assignee, reporter, comments, tags,
                                 is_deleted, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, false, $14, $15)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.ticket_type)
        .bind(&req.subject)
        .bind(&req.content)
        .bind(&req.status.unwrap_or_else(|| "open".to_string()))
        .bind(&req.priority.unwrap_or_else(|| "normal".to_string()))
        .bind(&req.assignee)
        .bind(&req.reporter)
        .bind(&req.comments)
        .bind(&req.tags)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateTicketRequest,
    ) -> AppResult<TicketResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE tickets
            SET display_name = COALESCE($1, display_name),
                ticket_type = COALESCE($2, ticket_type),
                subject = COALESCE($3, subject),
                content = COALESCE($4, content),
                status = COALESCE($5, status),
                priority = COALESCE($6, priority),
                assignee = COALESCE($7, assignee),
                reporter = COALESCE($8, reporter),
                comments = COALESCE($9, comments),
                tags = COALESCE($10, tags),
                updated_at = $11
            WHERE id = $12 AND is_deleted = false
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.ticket_type)
        .bind(&req.subject)
        .bind(&req.content)
        .bind(&req.status)
        .bind(&req.priority)
        .bind(&req.assignee)
        .bind(&req.reporter)
        .bind(&req.comments)
        .bind(&req.tags)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM tickets WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Ticket not found".to_string()));
        }

        Ok(())
    }
}
