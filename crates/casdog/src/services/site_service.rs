use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{CreateSiteRequest, Site, SiteListResponse, SiteResponse, UpdateSiteRequest};

pub struct SiteService;

impl SiteService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        include_global: bool,
        page: i64,
        page_size: i64,
    ) -> AppResult<SiteListResponse> {
        let offset = (page - 1) * page_size;

        let (sites, total) = match (owner, include_global) {
            (Some(owner), true) => {
                let sites: Vec<Site> = sqlx::query_as(
                    r#"
                    SELECT * FROM sites
                    WHERE is_deleted = false AND (owner = $1 OR owner = 'admin')
                    ORDER BY updated_at DESC
                    LIMIT $2 OFFSET $3
                    "#,
                )
                .bind(owner)
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let total: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM sites WHERE is_deleted = false AND (owner = $1 OR owner = 'admin')",
                )
                .bind(owner)
                .fetch_one(pool)
                .await?;

                (sites, total)
            }
            (Some(owner), false) => {
                let sites: Vec<Site> = sqlx::query_as(
                    r#"
                    SELECT * FROM sites
                    WHERE owner = $1 AND is_deleted = false
                    ORDER BY updated_at DESC
                    LIMIT $2 OFFSET $3
                    "#,
                )
                .bind(owner)
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let total: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM sites WHERE owner = $1 AND is_deleted = false",
                )
                .bind(owner)
                .fetch_one(pool)
                .await?;

                (sites, total)
            }
            (None, _) => {
                let sites: Vec<Site> = sqlx::query_as(
                    r#"
                    SELECT * FROM sites
                    WHERE is_deleted = false
                    ORDER BY updated_at DESC
                    LIMIT $1 OFFSET $2
                    "#,
                )
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let total: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM sites WHERE is_deleted = false")
                        .fetch_one(pool)
                        .await?;

                (sites, total)
            }
        };

        Ok(SiteListResponse {
            data: sites.into_iter().map(Into::into).collect(),
            total,
            page,
            page_size,
        })
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<SiteResponse> {
        let site: Site = sqlx::query_as("SELECT * FROM sites WHERE id = $1 AND is_deleted = false")
            .bind(id)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| AppError::NotFound("Site not found".to_string()))?;

        Ok(site.into())
    }

    pub async fn create(pool: &PgPool, req: CreateSiteRequest) -> AppResult<SiteResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let site: Site = sqlx::query_as(
            r#"
            INSERT INTO sites (
                id, owner, name, display_name, tag, domain, other_domains, need_redirect,
                disable_verbose, rules, enable_alert, alert_interval, alert_try_times,
                alert_providers, challenges, host, port, hosts, ssl_mode, ssl_cert,
                public_ip, node, status, nodes, casdoor_application,
                is_deleted, created_at, updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8,
                $9, $10, $11, $12, $13,
                $14, $15, $16, $17, $18, $19, $20,
                $21, $22, $23, $24, $25,
                false, $26, $27
            )
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.tag)
        .bind(&req.domain)
        .bind(&req.other_domains)
        .bind(req.need_redirect.unwrap_or(false))
        .bind(req.disable_verbose.unwrap_or(false))
        .bind(&req.rules)
        .bind(req.enable_alert.unwrap_or(false))
        .bind(req.alert_interval.unwrap_or(60))
        .bind(req.alert_try_times.unwrap_or(3))
        .bind(&req.alert_providers)
        .bind(&req.challenges)
        .bind(&req.host)
        .bind(req.port.unwrap_or(443))
        .bind(&req.hosts)
        .bind(req.ssl_mode.unwrap_or_else(|| "HTTPS Only".to_string()))
        .bind(&req.ssl_cert)
        .bind(&req.public_ip)
        .bind(&req.node)
        .bind(req.status.unwrap_or_else(|| "Active".to_string()))
        .bind(&req.nodes)
        .bind(&req.casdoor_application)
        .bind(now)
        .bind(now)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
                AppError::Conflict(format!(
                    "Site '{} / {}' already exists",
                    req.owner, req.name
                ))
            }
            _ => AppError::Database(e),
        })?;

        Ok(site.into())
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateSiteRequest,
    ) -> AppResult<SiteResponse> {
        let mut site: Site =
            sqlx::query_as("SELECT * FROM sites WHERE id = $1 AND is_deleted = false")
                .bind(id)
                .fetch_optional(pool)
                .await?
                .ok_or_else(|| AppError::NotFound("Site not found".to_string()))?;

        if let Some(v) = req.owner {
            site.owner = v;
        }
        if let Some(v) = req.name {
            site.name = v;
        }
        if let Some(v) = req.display_name {
            site.display_name = Some(v);
        }
        if let Some(v) = req.tag {
            site.tag = Some(v);
        }
        if let Some(v) = req.domain {
            site.domain = v;
        }
        if let Some(v) = req.other_domains {
            site.other_domains = Some(v);
        }
        if let Some(v) = req.need_redirect {
            site.need_redirect = v;
        }
        if let Some(v) = req.disable_verbose {
            site.disable_verbose = v;
        }
        if let Some(v) = req.rules {
            site.rules = Some(v);
        }
        if let Some(v) = req.enable_alert {
            site.enable_alert = v;
        }
        if let Some(v) = req.alert_interval {
            site.alert_interval = v;
        }
        if let Some(v) = req.alert_try_times {
            site.alert_try_times = v;
        }
        if let Some(v) = req.alert_providers {
            site.alert_providers = Some(v);
        }
        if let Some(v) = req.challenges {
            site.challenges = Some(v);
        }
        if let Some(v) = req.host {
            site.host = Some(v);
        }
        if let Some(v) = req.port {
            site.port = v;
        }
        if let Some(v) = req.hosts {
            site.hosts = Some(v);
        }
        if let Some(v) = req.ssl_mode {
            site.ssl_mode = v;
        }
        if let Some(v) = req.ssl_cert {
            site.ssl_cert = Some(v);
        }
        if let Some(v) = req.public_ip {
            site.public_ip = Some(v);
        }
        if let Some(v) = req.node {
            site.node = Some(v);
        }
        if let Some(v) = req.status {
            site.status = v;
        }
        if let Some(v) = req.nodes {
            site.nodes = Some(v);
        }
        if let Some(v) = req.casdoor_application {
            site.casdoor_application = Some(v);
        }
        site.updated_at = Utc::now();

        let updated: Site = sqlx::query_as(
            r#"
            UPDATE sites SET
                owner = $1,
                name = $2,
                display_name = $3,
                tag = $4,
                domain = $5,
                other_domains = $6,
                need_redirect = $7,
                disable_verbose = $8,
                rules = $9,
                enable_alert = $10,
                alert_interval = $11,
                alert_try_times = $12,
                alert_providers = $13,
                challenges = $14,
                host = $15,
                port = $16,
                hosts = $17,
                ssl_mode = $18,
                ssl_cert = $19,
                public_ip = $20,
                node = $21,
                status = $22,
                nodes = $23,
                casdoor_application = $24,
                updated_at = $25
            WHERE id = $26
            RETURNING *
            "#,
        )
        .bind(&site.owner)
        .bind(&site.name)
        .bind(&site.display_name)
        .bind(&site.tag)
        .bind(&site.domain)
        .bind(&site.other_domains)
        .bind(site.need_redirect)
        .bind(site.disable_verbose)
        .bind(&site.rules)
        .bind(site.enable_alert)
        .bind(site.alert_interval)
        .bind(site.alert_try_times)
        .bind(&site.alert_providers)
        .bind(&site.challenges)
        .bind(&site.host)
        .bind(site.port)
        .bind(&site.hosts)
        .bind(&site.ssl_mode)
        .bind(&site.ssl_cert)
        .bind(&site.public_ip)
        .bind(&site.node)
        .bind(&site.status)
        .bind(&site.nodes)
        .bind(&site.casdoor_application)
        .bind(site.updated_at)
        .bind(id)
        .fetch_one(pool)
        .await?;

        Ok(updated.into())
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let affected = sqlx::query(
            "UPDATE sites SET is_deleted = true, updated_at = $1 WHERE id = $2 AND is_deleted = false",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(AppError::NotFound("Site not found".to_string()));
        }

        Ok(())
    }
}
