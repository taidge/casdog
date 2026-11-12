use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    models::{CreateSyncerRequest, SyncerResponse, UpdateSyncerRequest},
    services::SyncerService,
};
use salvo::{
    oapi::extract::{JsonBody, PathParam, QueryParam},
    prelude::*,
};
use serde_json::{Value, json};
use sqlx::PgPool;

fn context(depot: &Depot) -> AppResult<(PgPool, Principal)> {
    let principal = Principal::from_depot(depot)?;
    if !principal.admin {
        return Err(AppError::Authorization(
            "Syncer administrator required".into(),
        ));
    }
    Ok((
        depot
            .obtain::<PgPool>()
            .cloned()
            .map_err(|_| AppError::Internal("Database unavailable".into()))?,
        principal,
    ))
}
fn scope(p: &Principal, owner: &str, organization: &str) -> AppResult<()> {
    if p.global_admin() || p.owner == owner && p.owner == organization {
        Ok(())
    } else {
        Err(AppError::Authorization(
            "Syncer belongs to another organization".into(),
        ))
    }
}
async fn checked(pool: &PgPool, p: &Principal, id: &str) -> AppResult<SyncerResponse> {
    let row = SyncerService::get_by_id(pool, id).await?;
    scope(p, &row.owner, &row.organization)?;
    Ok(row)
}
#[salvo::oapi::endpoint(tags("syncers"))]
pub async fn list_syncers(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    organization: QueryParam<String, false>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<Value>> {
    let (pool, p) = context(depot)?;
    let owner = owner
        .into_inner()
        .filter(|v| !v.is_empty())
        .or_else(|| (!p.global_admin()).then(|| p.owner.clone()));
    if !p.global_admin() && owner.as_deref() != Some(p.owner.as_str()) {
        return Err(AppError::Authorization("Syncer owner mismatch".into()));
    }
    let organization = organization
        .into_inner()
        .filter(|v| !v.is_empty())
        .or_else(|| (!p.global_admin()).then(|| p.owner.clone()));
    if !p.global_admin() && organization.as_deref() != Some(p.owner.as_str()) {
        return Err(AppError::Authorization("Syncer target mismatch".into()));
    }
    let (rows, total) = SyncerService::list_scoped(
        &pool,
        owner.as_deref(),
        organization.as_deref(),
        page.into_inner().unwrap_or(1),
        page_size.into_inner().unwrap_or(10),
    )
    .await?;
    Ok(Json(json!({"data":rows,"total":total})))
}
#[salvo::oapi::endpoint(tags("syncers"))]
pub async fn get_syncer(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<SyncerResponse>> {
    let (pool, p) = context(depot)?;
    Ok(Json(checked(&pool, &p, &id).await?))
}
#[salvo::oapi::endpoint(tags("syncers"))]
pub async fn create_syncer(
    depot: &mut Depot,
    body: JsonBody<CreateSyncerRequest>,
) -> AppResult<Json<SyncerResponse>> {
    let (pool, p) = context(depot)?;
    scope(&p, &body.owner, &body.organization)?;
    Ok(Json(SyncerService::create(&pool, body.into_inner()).await?))
}
#[salvo::oapi::endpoint(tags("syncers"))]
pub async fn update_syncer(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateSyncerRequest>,
) -> AppResult<Json<SyncerResponse>> {
    let (pool, p) = context(depot)?;
    let old = checked(&pool, &p, &id).await?;
    if let Some(org) = body.organization.as_deref() {
        scope(&p, &old.owner, org)?;
    }
    Ok(Json(
        SyncerService::update(&pool, &id, body.into_inner()).await?,
    ))
}
#[salvo::oapi::endpoint(tags("syncers"))]
pub async fn delete_syncer(depot: &mut Depot, id: PathParam<String>) -> AppResult<StatusCode> {
    let (pool, p) = context(depot)?;
    checked(&pool, &p, &id).await?;
    SyncerService::delete(&pool, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[salvo::oapi::endpoint(tags("syncers"))]
pub async fn run_syncer(depot: &mut Depot, id: PathParam<String>) -> AppResult<Json<Value>> {
    let (pool, p) = context(depot)?;
    checked(&pool, &p, &id).await?;
    let run = SyncerService::run_sync(&pool, &id).await?;
    Ok(Json(
        json!({"status":if run.success {"ok"}else{"error"},"msg":run.message,"syncerId":run.syncer_id,"recordsSynced":run.records_synced,"recordsExported":run.records_exported,"recordsForbidden":run.records_forbidden,"conflicts":run.conflicts,"operationsPending":run.operations_pending}),
    ))
}
fn legacy_value(row: SyncerResponse) -> Value {
    let columns=row.table_columns.map(|columns|columns.into_iter().map(|c|json!({"name":c.name,"type":c.column_type,"casdoorName":c.casdoor_name,"isKey":c.is_key,"isHashed":c.is_hashed,"values":c.values})).collect::<Vec<_>>());
    json!({"id":row.id,"owner":row.owner,"name":row.name,"createdTime":row.created_at.to_rfc3339(),"organization":row.organization,"type":row.syncer_type,"databaseType":row.database_type,"sslMode":row.ssl_mode,"host":row.host,"port":row.port,"user":row.user,"password":row.password,"database":row.database,"table":row.table_name,"tableColumns":columns,"affiliationTable":row.affiliation_table,"avatarBaseUrl":row.avatar_base_url,"syncInterval":row.sync_interval,"isReadOnly":row.is_read_only,"isEnabled":row.is_enabled,"errorText":row.error_text})
}
async fn legacy_id(pool: &PgPool, req: &Request, body: Option<&Value>) -> AppResult<String> {
    let reference = req
        .query::<String>("id")
        .or_else(|| body.and_then(|b| b["id"].as_str()).map(str::to_string));
    let pair = reference
        .as_deref()
        .and_then(|value| value.split_once('/'))
        .map(|(o, n)| (o.to_string(), n.to_string()))
        .or_else(|| {
            body.and_then(|b| {
                Some((
                    b["owner"].as_str()?.to_string(),
                    b["name"].as_str()?.to_string(),
                ))
            })
        });
    if let Some((owner, name)) = pair {
        crate::handlers::parity_resources::service::identity(&owner, &name)?;
        return sqlx::query_scalar("SELECT id FROM syncers WHERE owner=$1 AND name=$2")
            .bind(owner)
            .bind(name)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| AppError::NotFound("Syncer not found".into()));
    }
    reference
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::Validation("Syncer id is required".into()))
}
#[handler]
pub async fn legacy_get_syncers(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let (pool, p) = context(depot)?;
    let owner = req
        .query::<String>("owner")
        .filter(|v| !v.is_empty())
        .or_else(|| (!p.global_admin()).then(|| p.owner.clone()));
    if !p.global_admin() && owner.as_deref() != Some(p.owner.as_str()) {
        return Err(AppError::Authorization("Syncer owner mismatch".into()));
    }
    let page = req
        .query::<i64>("p")
        .or_else(|| req.query("page"))
        .unwrap_or(1);
    let size = req
        .query::<i64>("pageSize")
        .or_else(|| req.query("page_size"))
        .unwrap_or(1000);
    let organization = req
        .query::<String>("organization")
        .filter(|v| !v.is_empty())
        .or_else(|| (!p.global_admin()).then(|| p.owner.clone()));
    if !p.global_admin() && organization.as_deref() != Some(p.owner.as_str()) {
        return Err(AppError::Authorization("Syncer target mismatch".into()));
    }
    let (rows, total) =
        SyncerService::list_scoped(&pool, owner.as_deref(), organization.as_deref(), page, size)
            .await?;
    Ok(Json(
        json!({"status":"ok","data":rows.into_iter().map(legacy_value).collect::<Vec<_>>(),"data2":total}),
    ))
}
#[handler]
pub async fn legacy_get_syncer(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let (pool, p) = context(depot)?;
    let id = legacy_id(&pool, req, None).await?;
    Ok(Json(
        json!({"status":"ok","data":legacy_value(checked(&pool,&p,&id).await?)}),
    ))
}
#[handler]
pub async fn legacy_add_syncer(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let (pool, p) = context(depot)?;
    let body: CreateSyncerRequest = req
        .parse_json()
        .await
        .map_err(|_| AppError::Validation("Invalid syncer request".into()))?;
    scope(&p, &body.owner, &body.organization)?;
    let row = SyncerService::create(&pool, body).await?;
    Ok(Json(
        json!({"status":"ok","data":true,"data2":legacy_value(row)}),
    ))
}
#[handler]
pub async fn legacy_update_syncer(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let (pool, p) = context(depot)?;
    let body: Value = req
        .parse_json()
        .await
        .map_err(|_| AppError::Validation("Invalid syncer request".into()))?;
    let id = legacy_id(&pool, req, Some(&body)).await?;
    let old = checked(&pool, &p, &id).await?;
    for (field, expected) in [("owner", old.owner.as_str()), ("name", old.name.as_str())] {
        if body
            .get(field)
            .is_some_and(|v| v.as_str() != Some(expected))
        {
            return Err(AppError::Validation("Syncer identity is immutable".into()));
        }
    }
    let update: UpdateSyncerRequest = serde_json::from_value(body)
        .map_err(|_| AppError::Validation("Invalid syncer update".into()))?;
    if let Some(org) = update.organization.as_deref() {
        scope(&p, &old.owner, org)?;
    }
    SyncerService::update(&pool, &id, update).await?;
    Ok(Json(json!({"status":"ok","data":true})))
}
#[handler]
pub async fn legacy_delete_syncer(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let (pool, p) = context(depot)?;
    let body: Value = req
        .parse_json()
        .await
        .map_err(|_| AppError::Validation("Invalid syncer delete".into()))?;
    let id = legacy_id(&pool, req, Some(&body)).await?;
    checked(&pool, &p, &id).await?;
    SyncerService::delete(&pool, &id).await?;
    Ok(Json(json!({"status":"ok","data":true})))
}
