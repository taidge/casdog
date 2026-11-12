//! Passive OpenClaw OTLP/HTTP ingestion. Administrative approval binds every
//! exporter to one provider, application and tenant; payload attributes cannot
//! change that identity. A success response means the complete batch committed.
use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::read::MultiGzDecoder;
use opentelemetry_proto::tonic::{
    collector::{
        logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest,
        trace::v1::ExportTraceServiceRequest,
    },
    metrics::v1::metric::Data,
};
use prost::Message;
use prost_reflect::{DescriptorPool, Kind, MessageDescriptor};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use std::{io::Read, sync::OnceLock};

pub const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_JSON: usize = 2 * 1024 * 1024;
const MAX_NODES: usize = 50_000;
const MAX_ITEMS: usize = 10_000;

#[derive(Clone, Copy, Debug)]
pub enum Signal {
    Traces,
    Metrics,
    Logs,
}
impl Signal {
    pub fn name(self) -> &'static str {
        match self {
            Self::Traces => "traces",
            Self::Metrics => "metrics",
            Self::Logs => "logs",
        }
    }
    fn descriptor(self) -> &'static str {
        match self {
            Self::Traces => "opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest",
            Self::Metrics => "opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest",
            Self::Logs => "opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest",
        }
    }
    fn entry_type(self) -> &'static str {
        match self {
            Self::Traces => "trace",
            Self::Metrics => "metrics",
            Self::Logs => "log",
        }
    }
}
#[derive(Debug)]
pub struct IngestError {
    pub status: u16,
    pub message: &'static str,
}
impl IngestError {
    pub fn new(status: u16, message: &'static str) -> Self {
        Self { status, message }
    }
}
type IngestResult<T> = Result<T, IngestError>;
impl From<sqlx::Error> for IngestError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error,"OTLP database operation failed");
        Self::new(503, "Telemetry storage unavailable")
    }
}
fn invalid() -> IngestError {
    IngestError::new(400, "Invalid OTLP protobuf batch")
}
fn denied() -> AppError {
    AppError::Authorization("Current tenant administrator required".into())
}
fn hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
fn new_token() -> String {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("otlp_{}", URL_SAFE_NO_PAD.encode(bytes))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReceiverInput {
    pub provider: String,
    pub application: String,
    #[serde(default = "default_mode")]
    pub auth_mode: String,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub rotate: bool,
}
fn default_mode() -> String {
    "token".into()
}
fn yes() -> bool {
    true
}
#[derive(sqlx::FromRow)]
struct Receiver {
    id: String,
    organization: String,
    provider_id: String,
    application_id: String,
    auth_mode: String,
    token_hash: Option<String>,
    allowed_sources: Vec<String>,
    enabled: bool,
}
const RECEIVER_COLUMNS: &str = "id,organization,provider_id,application_id,auth_mode,token_hash,ARRAY(SELECT unnest(allowed_sources)::text) AS allowed_sources,enabled";
fn public(receiver: &Receiver) -> Value {
    json!({"id":receiver.id,"organization":receiver.organization,"provider":receiver.provider_id,"application":receiver.application_id,"authMode":receiver.auth_mode,"allowedSources":receiver.allowed_sources,"enabled":receiver.enabled})
}

async fn admin(conn: &mut PgConnection, p: &Principal) -> AppResult<()> {
    if !p.admin || p.is_application() {
        return Err(denied());
    }
    let valid:Option<bool>=sqlx::query_scalar("SELECT true FROM users WHERE id=$1 AND owner=$2 AND name=$3 AND is_admin AND NOT is_deleted AND NOT is_forbidden FOR SHARE")
        .bind(&p.id).bind(&p.owner).bind(&p.name).fetch_optional(&mut *conn).await?;
    if valid != Some(true) {
        return Err(denied());
    }
    Ok(())
}
pub async fn list(pool: &PgPool, p: &Principal) -> AppResult<Value> {
    let mut conn = pool.acquire().await?;
    admin(&mut conn, p).await?;
    let rows:Vec<Receiver>=sqlx::query_as(&format!("SELECT {RECEIVER_COLUMNS} FROM telemetry_receivers WHERE ($1 OR organization=$2) ORDER BY organization,id"))
        .bind(p.global_admin()).bind(&p.owner).fetch_all(&mut *conn).await?;
    Ok(json!({"status":"ok","data":rows.iter().map(public).collect::<Vec<_>>()}))
}
pub async fn save(pool: &PgPool, p: &Principal, input: ReceiverInput) -> AppResult<Value> {
    if !matches!(input.auth_mode.as_str(), "token" | "source_ip")
        || input.provider.len() > 256
        || input.application.len() > 256
        || input.allowed_sources.len() > 16
    {
        return Err(AppError::Validation(
            "Invalid receiver configuration".into(),
        ));
    }
    let mut tx = pool.begin().await?;
    admin(&mut tx, p).await?;
    // Resolve a canonical ID, or an exact owner/name; bare names are scoped to
    // the administrator's tenant. Never select an arbitrary provider by name.
    let providers:Vec<(String,String)>=sqlx::query_as("SELECT id,owner FROM providers WHERE (id=$1 OR owner||'/'||name=$1 OR (owner=$2 AND name=$1)) AND category='Log' AND type='Agent' AND sub_type='OpenClaw' AND ($3 OR owner=$2) LIMIT 2")
        .bind(&input.provider).bind(&p.owner).bind(p.global_admin()).fetch_all(&mut *tx).await?;
    if providers.len() != 1 {
        return Err(AppError::Validation(
            "Unambiguous approved OpenClaw Log/Agent provider required".into(),
        ));
    }
    let (provider_id, owner) = providers.into_iter().next().unwrap();
    let apps:Vec<String>=sqlx::query_scalar("SELECT id FROM applications WHERE (id=$1 OR owner||'/'||name=$1 OR (organization=$2 AND name=$1)) AND organization=$2 AND NOT is_deleted LIMIT 2")
        .bind(&input.application).bind(&owner).fetch_all(&mut *tx).await?;
    if apps.len() != 1 {
        return Err(AppError::Validation(
            "Unambiguous active application in provider tenant required".into(),
        ));
    }
    let app = apps.into_iter().next().unwrap();
    let available:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin)").bind(&owner).fetch_one(&mut *tx).await?;
    if !available {
        return Err(AppError::Validation("Active organization required".into()));
    }
    let mut sources = Vec::new();
    for source in input.allowed_sources {
        // inet parsing is performed by PostgreSQL itself. /0 would approve the
        // public Internet and is deliberately not a source-authentication rule.
        if source.len() > 64 || source.is_empty() {
            return Err(AppError::Validation("Invalid source CIDR".into()));
        }
        // Validate locally first so malformed user input does not abort the transaction.
        let (ip, prefix) = source
            .split_once('/')
            .map_or((source.as_str(), None), |(a, b)| (a, Some(b)));
        let address: std::net::IpAddr = ip
            .parse()
            .map_err(|_| AppError::Validation("Invalid source CIDR".into()))?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        let prefix = prefix
            .map_or(Ok(max), str::parse::<u32>)
            .map_err(|_| AppError::Validation("Invalid source CIDR".into()))?;
        if prefix == 0 || prefix > max {
            return Err(AppError::Validation("Invalid source CIDR".into()));
        }
        // inet(...)/network accepts host addresses while canonicalizing their network bits.
        let canonical: String = sqlx::query_scalar("SELECT network($1::inet)::text")
            .bind(format!("{address}/{prefix}"))
            .fetch_one(&mut *tx)
            .await?;
        if !sources.contains(&canonical) {
            sources.push(canonical);
        }
    }
    if input.auth_mode == "source_ip" && sources.is_empty() {
        return Err(AppError::Validation(
            "Source IP authentication requires explicit CIDRs".into(),
        ));
    }
    // Serialize creation/update by provider, including initially absent rows.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 174883))")
        .bind(&provider_id)
        .execute(&mut *tx)
        .await?;
    let old: Option<Receiver> = sqlx::query_as(&format!(
        "SELECT {RECEIVER_COLUMNS} FROM telemetry_receivers WHERE provider_id=$1 FOR UPDATE"
    ))
    .bind(&provider_id)
    .fetch_optional(&mut *tx)
    .await?;
    let issued = if input.auth_mode == "token"
        && (input.rotate
            || old.as_ref().is_none_or(|r| {
                r.auth_mode != "token"
                    || r.token_hash.is_none()
                    || r.organization != owner
                    || r.application_id != app
            })) {
        Some(new_token())
    } else {
        None
    };
    let token_hash = issued
        .as_ref()
        .map(|t| hash(t))
        .or_else(|| old.as_ref().and_then(|r| r.token_hash.clone()));
    let id = old
        .as_ref()
        .map(|r| r.id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    sqlx::query("INSERT INTO telemetry_receivers(id,organization,provider_id,application_id,auth_mode,token_hash,allowed_sources,enabled,approved_by) VALUES($1,$2,$3,$4,$5,$6,$7::text[]::cidr[],$8,$9) ON CONFLICT(provider_id) DO UPDATE SET organization=EXCLUDED.organization,application_id=EXCLUDED.application_id,auth_mode=EXCLUDED.auth_mode,token_hash=EXCLUDED.token_hash,allowed_sources=EXCLUDED.allowed_sources,enabled=EXCLUDED.enabled,approved_by=EXCLUDED.approved_by,updated_at=clock_timestamp()")
        .bind(&id).bind(&owner).bind(&provider_id).bind(&app).bind(&input.auth_mode).bind(&token_hash).bind(&sources).bind(input.enabled).bind(&p.id).execute(&mut *tx).await?;
    let receiver = Receiver {
        id,
        organization: owner,
        provider_id,
        application_id: app,
        auth_mode: input.auth_mode,
        token_hash,
        allowed_sources: sources,
        enabled: input.enabled,
    };
    let mut data = public(&receiver);
    if let Some(token) = issued {
        data["token"] = json!(token);
    }
    tx.commit().await?;
    Ok(json!({"status":"ok","data":data}))
}
pub async fn disable(pool: &PgPool, p: &Principal, id: &str) -> AppResult<Value> {
    let mut tx = pool.begin().await?;
    admin(&mut tx, p).await?;
    let n=sqlx::query("UPDATE telemetry_receivers SET enabled=false,token_hash=NULL,updated_at=clock_timestamp() WHERE id=$1 AND ($2 OR organization=$3)")
        .bind(id).bind(p.global_admin()).bind(&p.owner).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(AppError::NotFound("Receiver unavailable".into()));
    }
    tx.commit().await?;
    Ok(json!({"status":"ok"}))
}

/// Validate protobuf nesting and the allocation budget before prost expands
/// repeated empty messages. Bytes/string fields remain opaque; unknown fields
/// are skipped according to their wire type, then retained in the raw batch.
fn varint(bytes: &[u8], position: &mut usize) -> IngestResult<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*position).ok_or_else(invalid)?;
        *position += 1;
        if shift == 63 && byte > 1 {
            return Err(invalid());
        }
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err(invalid())
}
fn preflight(
    bytes: &[u8],
    descriptor: &MessageDescriptor,
    depth: usize,
    nodes: &mut usize,
) -> IngestResult<()> {
    if depth > 32 {
        return Err(invalid());
    }
    let mut position = 0;
    while position < bytes.len() {
        *nodes += 1;
        if *nodes > MAX_NODES {
            return Err(IngestError::new(
                413,
                "OTLP batch exceeds structural budget",
            ));
        }
        let tag = varint(bytes, &mut position)?;
        let field = tag >> 3;
        if field == 0 || field > 0x1fff_ffff {
            return Err(invalid());
        }
        let end = match tag & 7 {
            0 => {
                varint(bytes, &mut position)?;
                position
            }
            1 => position.checked_add(8).ok_or_else(invalid)?,
            2 => {
                let length =
                    usize::try_from(varint(bytes, &mut position)?).map_err(|_| invalid())?;
                let end = position
                    .checked_add(length)
                    .filter(|end| *end <= bytes.len())
                    .ok_or_else(invalid)?;
                if let Some(field) = descriptor.get_field(field as u32) {
                    if let Kind::Message(message) = field.kind() {
                        preflight(&bytes[position..end], &message, depth + 1, nodes)?;
                    }
                }
                end
            }
            5 => position.checked_add(4).ok_or_else(invalid)?,
            _ => return Err(invalid()), // OTLP has no deprecated protobuf groups.
        };
        if end > bytes.len() {
            return Err(invalid());
        }
        position = end;
    }
    Ok(())
}
pub fn decode_batch(
    signal: Signal,
    body: &[u8],
    encoding: Option<&str>,
) -> IngestResult<(Vec<u8>, String, usize)> {
    if body.len() > MAX_BODY {
        return Err(IngestError::new(413, "OTLP batch too large"));
    }
    let decoded = match encoding
        .unwrap_or("identity")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "identity" => body.to_vec(),
        "gzip" => {
            let mut out = Vec::new();
            MultiGzDecoder::new(body)
                .take((MAX_BODY + 1) as u64)
                .read_to_end(&mut out)
                .map_err(|_| invalid())?;
            out
        }
        _ => return Err(IngestError::new(415, "Unsupported OTLP content encoding")),
    };
    if decoded.len() > MAX_BODY {
        return Err(IngestError::new(413, "Expanded OTLP batch too large"));
    }
    static DESCRIPTORS: OnceLock<DescriptorPool> = OnceLock::new();
    let pool = DESCRIPTORS.get_or_init(|| {
        DescriptorPool::decode(opentelemetry_proto::DESCRIPTORS)
            .expect("Bundled OTLP descriptors are valid")
    });
    let descriptor = pool
        .get_message_by_name(signal.descriptor())
        .ok_or_else(|| IngestError::new(503, "OTLP schema unavailable"))?;
    preflight(&decoded, &descriptor, 0, &mut 0)?;
    let (value, count) = match signal {
        Signal::Traces => {
            let request =
                ExportTraceServiceRequest::decode(decoded.as_slice()).map_err(|_| invalid())?;
            let mut count = 0;
            for resource in &request.resource_spans {
                for scope in &resource.scope_spans {
                    for span in &scope.spans {
                        if span.trace_id.len() != 16
                            || span.trace_id.iter().all(|v| *v == 0)
                            || span.span_id.len() != 8
                            || span.span_id.iter().all(|v| *v == 0)
                            || (!span.parent_span_id.is_empty() && span.parent_span_id.len() != 8)
                            || span.end_time_unix_nano < span.start_time_unix_nano
                        {
                            return Err(invalid());
                        }
                        count += 1;
                    }
                }
            }
            (
                serde_json::to_string(&request).map_err(|_| invalid())?,
                count,
            )
        }
        Signal::Logs => {
            let request =
                ExportLogsServiceRequest::decode(decoded.as_slice()).map_err(|_| invalid())?;
            let mut count = 0;
            for resource in &request.resource_logs {
                for scope in &resource.scope_logs {
                    for log in &scope.log_records {
                        if (!log.trace_id.is_empty() && log.trace_id.len() != 16)
                            || (!log.span_id.is_empty() && log.span_id.len() != 8)
                        {
                            return Err(invalid());
                        }
                        count += 1;
                    }
                }
            }
            (
                serde_json::to_string(&request).map_err(|_| invalid())?,
                count,
            )
        }
        Signal::Metrics => {
            let request =
                ExportMetricsServiceRequest::decode(decoded.as_slice()).map_err(|_| invalid())?;
            let mut count = 0;
            for resource in &request.resource_metrics {
                for scope in &resource.scope_metrics {
                    for metric in &scope.metrics {
                        if metric.name.is_empty() {
                            return Err(invalid());
                        }
                        count += match &metric.data {
                            Some(Data::Gauge(v)) => v.data_points.len(),
                            Some(Data::Sum(v)) => v.data_points.len(),
                            Some(Data::Histogram(v)) => v.data_points.len(),
                            Some(Data::ExponentialHistogram(v)) => v.data_points.len(),
                            Some(Data::Summary(v)) => v.data_points.len(),
                            None => return Err(invalid()),
                        };
                    }
                }
            }
            (
                serde_json::to_string(&request).map_err(|_| invalid())?,
                count,
            )
        }
    };
    if count > MAX_ITEMS || value.len() > MAX_JSON {
        return Err(IngestError::new(413, "OTLP batch exceeds storage budget"));
    }
    Ok((decoded, value, count))
}

pub async fn ingest(
    pool: &PgPool,
    signal: Signal,
    authorization: Option<&str>,
    peer: Option<std::net::IpAddr>,
    user_agent: &str,
    body: &[u8],
    encoding: Option<&str>,
) -> IngestResult<()> {
    let mut tx = pool.begin().await?;
    let peer = peer.map(|ip| ip.to_string());
    let receiver: Receiver = if let Some(authorization) = authorization {
        let token = authorization
            .split_once(' ')
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
            .map(|(_, token)| token)
            .filter(|v| {
                v.starts_with("otlp_")
                    && v.len() == 48
                    && v.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            })
            .ok_or_else(|| IngestError::new(401, "Exporter authentication required"))?;
        sqlx::query_as(&format!("SELECT {RECEIVER_COLUMNS} FROM telemetry_receivers WHERE token_hash=$1 AND auth_mode='token' AND enabled AND (cardinality(allowed_sources)=0 OR $2::inet <<= ANY(allowed_sources)) FOR UPDATE"))
            .bind(hash(token)).bind(&peer).fetch_optional(&mut *tx).await?.ok_or_else(||IngestError::new(401,"Exporter authentication required"))?
    } else {
        let ids:Vec<String>=sqlx::query_scalar("SELECT id FROM telemetry_receivers WHERE auth_mode='source_ip' AND enabled AND $1::inet <<= ANY(allowed_sources) ORDER BY id LIMIT 2")
            .bind(&peer).fetch_all(&mut *tx).await?;
        if ids.len() != 1 {
            return Err(IngestError::new(
                401,
                "Unambiguous exporter authentication required",
            ));
        }
        sqlx::query_as(&format!("SELECT {RECEIVER_COLUMNS} FROM telemetry_receivers WHERE id=$1 AND auth_mode='source_ip' AND enabled AND $2::inet <<= ANY(allowed_sources) FOR UPDATE"))
            .bind(&ids[0]).bind(&peer).fetch_optional(&mut *tx).await?.ok_or_else(||IngestError::new(401,"Exporter authentication required"))?
    };
    // These live reads are not cached: provider/app moves, deletion, disabling
    // the organization or receiver immediately revoke its prior approval.
    let binding:Option<(String,String,String,String)>=sqlx::query_as("SELECT p.owner,p.name,a.owner,a.name FROM providers p JOIN applications a ON a.id=$2 JOIN organizations o ON o.name=p.owner WHERE p.id=$1 AND p.owner=$3 AND p.category='Log' AND p.type='Agent' AND p.sub_type='OpenClaw' AND a.organization=p.owner AND NOT a.is_deleted AND NOT o.is_deleted AND NOT o.disable_signin FOR SHARE OF p,a,o")
        .bind(&receiver.provider_id).bind(&receiver.application_id).bind(&receiver.organization).fetch_optional(&mut *tx).await?;
    let (owner, provider_name, app_owner, app_name) =
        binding.ok_or_else(|| IngestError::new(401, "Exporter approval unavailable"))?;
    // Durable window counters make the budget effective across instances. The
    // receiver lock also linearizes revocation/rotation against batch commits.
    let allowed:bool=sqlx::query_scalar("UPDATE telemetry_receivers SET batch_count=CASE WHEN window_started_at<=clock_timestamp()-interval '1 minute' THEN 1 ELSE batch_count+1 END,byte_count=CASE WHEN window_started_at<=clock_timestamp()-interval '1 minute' THEN $2 ELSE byte_count+$2 END,window_started_at=CASE WHEN window_started_at<=clock_timestamp()-interval '1 minute' THEN clock_timestamp() ELSE window_started_at END WHERE id=$1 AND (window_started_at<=clock_timestamp()-interval '1 minute' OR (batch_count<120 AND byte_count+$2<=67108864)) RETURNING true")
        .bind(&receiver.id).bind(body.len() as i64).fetch_optional(&mut *tx).await?.unwrap_or(false);
    if !allowed {
        return Err(IngestError::new(429, "Exporter rate limit exceeded"));
    }
    let (protobuf, message, count) = match decode_batch(signal, body, encoding) {
        Ok(v) => v,
        Err(error) => {
            tx.commit().await?;
            return Err(error);
        }
    };
    if protobuf.len() > body.len() {
        // Compression must not turn the persistent byte budget into an
        // effectively unlimited storage allowance.
        let charged:bool=sqlx::query_scalar("UPDATE telemetry_receivers SET byte_count=byte_count+$2 WHERE id=$1 AND byte_count+$2<=67108864 RETURNING true")
            .bind(&receiver.id).bind((protobuf.len()-body.len()) as i64).fetch_optional(&mut *tx).await?.unwrap_or(false);
        if !charged {
            tx.commit().await?;
            return Err(IngestError::new(429, "Exporter byte limit exceeded"));
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    let time = chrono::Utc::now().to_rfc3339();
    // Entry CRUD uses the Casdoor qualified application reference. The receiver
    // separately keeps the immutable application ID used for authorization.
    let document = json!({"owner":owner,"name":id,"provider":format!("{owner}/{provider_name}"),"application":format!("{app_owner}/{app_name}"),"type":signal.entry_type(),"clientIp":peer.unwrap_or_default(),"userAgent":user_agent.chars().take(512).collect::<String>(),"message":message,"createdTime":time,"updatedTime":time});
    sqlx::query("INSERT INTO casdoor_objects(kind,owner,name,document) VALUES('entry',$1,$2,$3)")
        .bind(&owner)
        .bind(&id)
        .bind(document)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO telemetry_ingestions(id,receiver_id,organization,signal,item_count,protobuf) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(id).bind(receiver.id).bind(owner).bind(signal.name()).bind(count as i32).bind(protobuf).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
