use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SiteNodeItem {
    pub name: String,
    pub version: Option<String>,
    pub diff: Option<String>,
    pub pid: Option<i32>,
    pub status: Option<String>,
    pub message: Option<String>,
    pub provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Site {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: Option<String>,
    pub tag: Option<String>,
    pub domain: String,
    pub other_domains: Option<serde_json::Value>,
    pub need_redirect: bool,
    pub disable_verbose: bool,
    pub rules: Option<serde_json::Value>,
    pub enable_alert: bool,
    pub alert_interval: i32,
    pub alert_try_times: i32,
    pub alert_providers: Option<serde_json::Value>,
    pub challenges: Option<serde_json::Value>,
    pub host: Option<String>,
    pub port: i32,
    pub hosts: Option<serde_json::Value>,
    pub ssl_mode: String,
    pub ssl_cert: Option<String>,
    pub public_ip: Option<String>,
    pub node: Option<String>,
    pub status: String,
    pub nodes: Option<serde_json::Value>,
    pub casdoor_application: Option<String>,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSiteRequest {
    pub owner: String,
    pub name: String,
    pub display_name: Option<String>,
    pub tag: Option<String>,
    pub domain: String,
    pub other_domains: Option<serde_json::Value>,
    pub need_redirect: Option<bool>,
    pub disable_verbose: Option<bool>,
    pub rules: Option<serde_json::Value>,
    pub enable_alert: Option<bool>,
    pub alert_interval: Option<i32>,
    pub alert_try_times: Option<i32>,
    pub alert_providers: Option<serde_json::Value>,
    pub challenges: Option<serde_json::Value>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub hosts: Option<serde_json::Value>,
    pub ssl_mode: Option<String>,
    pub ssl_cert: Option<String>,
    pub public_ip: Option<String>,
    pub node: Option<String>,
    pub status: Option<String>,
    pub nodes: Option<serde_json::Value>,
    pub casdoor_application: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSiteRequest {
    pub owner: Option<String>,
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub tag: Option<String>,
    pub domain: Option<String>,
    pub other_domains: Option<serde_json::Value>,
    pub need_redirect: Option<bool>,
    pub disable_verbose: Option<bool>,
    pub rules: Option<serde_json::Value>,
    pub enable_alert: Option<bool>,
    pub alert_interval: Option<i32>,
    pub alert_try_times: Option<i32>,
    pub alert_providers: Option<serde_json::Value>,
    pub challenges: Option<serde_json::Value>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub hosts: Option<serde_json::Value>,
    pub ssl_mode: Option<String>,
    pub ssl_cert: Option<String>,
    pub public_ip: Option<String>,
    pub node: Option<String>,
    pub status: Option<String>,
    pub nodes: Option<serde_json::Value>,
    pub casdoor_application: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SiteResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: Option<String>,
    pub tag: Option<String>,
    pub domain: String,
    pub other_domains: Option<serde_json::Value>,
    pub need_redirect: bool,
    pub disable_verbose: bool,
    pub rules: Option<serde_json::Value>,
    pub enable_alert: bool,
    pub alert_interval: i32,
    pub alert_try_times: i32,
    pub alert_providers: Option<serde_json::Value>,
    pub challenges: Option<serde_json::Value>,
    pub host: Option<String>,
    pub port: i32,
    pub hosts: Option<serde_json::Value>,
    pub ssl_mode: String,
    pub ssl_cert: Option<String>,
    pub public_ip: Option<String>,
    pub node: Option<String>,
    pub status: String,
    pub nodes: Option<serde_json::Value>,
    pub casdoor_application: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Site> for SiteResponse {
    fn from(site: Site) -> Self {
        Self {
            id: site.id,
            owner: site.owner,
            name: site.name,
            display_name: site.display_name,
            tag: site.tag,
            domain: site.domain,
            other_domains: site.other_domains,
            need_redirect: site.need_redirect,
            disable_verbose: site.disable_verbose,
            rules: site.rules,
            enable_alert: site.enable_alert,
            alert_interval: site.alert_interval,
            alert_try_times: site.alert_try_times,
            alert_providers: site.alert_providers,
            challenges: site.challenges,
            host: site.host,
            port: site.port,
            hosts: site.hosts,
            ssl_mode: site.ssl_mode,
            ssl_cert: site.ssl_cert,
            public_ip: site.public_ip,
            node: site.node,
            status: site.status,
            nodes: site.nodes,
            casdoor_application: site.casdoor_application,
            created_at: site.created_at,
            updated_at: site.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SiteListResponse {
    pub data: Vec<SiteResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}
