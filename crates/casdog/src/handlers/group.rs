use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{
    AddUserToGroupRequest, CreateGroupRequest, GroupResponse, RemoveUserFromGroupRequest,
    UpdateGroupRequest,
};
use crate::services::GroupService;

#[endpoint(tags("groups"), summary = "List groups")]
pub async fn list_groups(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let page = page.into_inner().unwrap_or(1);
    let page_size = page_size.into_inner().unwrap_or(10);
    let owner = owner.into_inner();

    let (groups, total) = GroupService::list(&pool, owner.as_deref(), page, page_size).await?;

    Ok(Json(serde_json::json!({
        "data": groups,
        "total": total
    })))
}

#[endpoint(tags("groups"), summary = "Get group by ID")]
pub async fn get_group(depot: &mut Depot, id: PathParam<String>) -> AppResult<Json<GroupResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let group = GroupService::get_by_id(&pool, &id).await?;
    Ok(Json(group))
}

#[endpoint(tags("groups"), summary = "Create group")]
pub async fn create_group(
    depot: &mut Depot,
    body: JsonBody<CreateGroupRequest>,
) -> AppResult<Json<GroupResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let group = GroupService::create(&pool, body.into_inner()).await?;
    Ok(Json(group))
}

#[endpoint(tags("groups"), summary = "Update group")]
pub async fn update_group(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateGroupRequest>,
) -> AppResult<Json<GroupResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let group = GroupService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(group))
}

#[endpoint(tags("groups"), summary = "Delete group")]
pub async fn delete_group(depot: &mut Depot, id: PathParam<String>) -> AppResult<StatusCode> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    GroupService::delete(&pool, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[endpoint(tags("groups"), summary = "Add user to group")]
pub async fn add_user_to_group(
    depot: &mut Depot,
    body: JsonBody<AddUserToGroupRequest>,
) -> AppResult<StatusCode> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let req = body.into_inner();
    GroupService::add_user_to_group(&pool, &req.user_id, &req.group_id).await?;
    Ok(StatusCode::OK)
}

#[endpoint(tags("groups"), summary = "Remove user from group")]
pub async fn remove_user_from_group(
    depot: &mut Depot,
    body: JsonBody<RemoveUserFromGroupRequest>,
) -> AppResult<StatusCode> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let req = body.into_inner();
    GroupService::remove_user_from_group(&pool, &req.user_id, &req.group_id).await?;
    Ok(StatusCode::OK)
}

#[endpoint(tags("groups"), summary = "Get users in group")]
pub async fn get_users_in_group(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<Vec<String>>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let users = GroupService::get_users_in_group(&pool, &id).await?;
    Ok(Json(users))
}
