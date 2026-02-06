use crate::error::{AppError, AppResult};
use crate::models::{CreateProductRequest, ProductResponse, UpdateProductRequest};
use crate::services::ProductService;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

#[endpoint(tags("products"), summary = "List products")]
pub async fn list_products(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let owner_ref = owner.as_deref();
    let page_val = page.into_inner().unwrap_or(1);
    let page_size_val = page_size.into_inner().unwrap_or(10);

    let (products, total) =
        ProductService::list(&pool, owner_ref, page_val, page_size_val).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": products,
        "total": total
    })))
}

#[endpoint(tags("products"), summary = "Get product by ID")]
pub async fn get_product(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<ProductResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let product = ProductService::get_by_id(&pool, &id).await?;
    Ok(Json(product))
}

#[endpoint(tags("products"), summary = "Create product")]
pub async fn create_product(
    depot: &mut Depot,
    body: JsonBody<CreateProductRequest>,
) -> AppResult<Json<ProductResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let product = ProductService::create(&pool, body.into_inner()).await?;
    Ok(Json(product))
}

#[endpoint(tags("products"), summary = "Update product")]
pub async fn update_product(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateProductRequest>,
) -> AppResult<Json<ProductResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let product = ProductService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(product))
}

#[endpoint(tags("products"), summary = "Delete product")]
pub async fn delete_product(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    ProductService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Product deleted"
    })))
}
