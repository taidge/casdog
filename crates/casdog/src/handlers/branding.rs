use crate::error::{AppError, AppResult};
use salvo::prelude::*;
use serde_json::Value;
#[handler]
pub async fn get_branding(req: &mut Request, depot: &mut Depot) -> AppResult<Json<Value>> {
    let reference = req
        .query::<String>("application")
        .ok_or_else(|| AppError::Validation("Application required".into()))?;
    let pool = super::social_login::pg_pool(depot)?;
    Ok(Json(
        super::parity_resources::marketplace::public_branding(&pool, &reference).await?,
    ))
}
