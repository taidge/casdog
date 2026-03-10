use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::{
    AssignPermissionRequest, CreatePermissionRequest, Permission, PermissionListResponse,
    PermissionQuery, PermissionResponse, UpdatePermissionRequest,
};
use crate::schema::{permissions, role_permissions};

#[derive(Clone)]
pub struct PermissionService {
    pool: DieselPool,
}

impl PermissionService {
    pub fn new(pool: DieselPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, req: CreatePermissionRequest) -> AppResult<PermissionResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let permission = diesel::insert_into(permissions::table)
            .values((
                permissions::id.eq(&id),
                permissions::owner.eq(&req.owner),
                permissions::name.eq(&req.name),
                permissions::display_name.eq(&req.display_name),
                permissions::description.eq(&req.description),
                permissions::resource_type.eq(&req.resource_type),
                permissions::resources.eq(&req.resources),
                permissions::actions.eq(&req.actions),
                permissions::effect.eq(req.effect.as_deref().unwrap_or("allow")),
                permissions::is_enabled.eq(req.is_enabled.unwrap_or(true)),
                permissions::created_at.eq(now),
                permissions::updated_at.eq(now),
            ))
            .returning(Permission::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                ) => AppError::Conflict(format!(
                    "Permission '{}' already exists in '{}'",
                    req.name, req.owner
                )),
                _ => AppError::Internal(e.to_string()),
            })?;

        Ok(permission.into())
    }

    pub async fn get_by_id(&self, id: &str) -> AppResult<PermissionResponse> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let permission = permissions::table
            .filter(permissions::id.eq(id))
            .filter(permissions::is_deleted.eq(false))
            .first::<Permission>(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("Permission with id '{}' not found", id)))?;

        Ok(permission.into())
    }

    pub async fn list(&self, query: PermissionQuery) -> AppResult<PermissionListResponse> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).min(100);
        let offset = (page - 1) * page_size;

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let (perm_list, total): (Vec<Permission>, i64) = if let Some(ref owner) = query.owner {
            let perm_list = permissions::table
                .filter(permissions::owner.eq(owner))
                .filter(permissions::is_deleted.eq(false))
                .order(permissions::created_at.desc())
                .limit(page_size)
                .offset(offset)
                .load::<Permission>(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let total: i64 = permissions::table
                .filter(permissions::owner.eq(owner))
                .filter(permissions::is_deleted.eq(false))
                .count()
                .get_result(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            (perm_list, total)
        } else {
            let perm_list = permissions::table
                .filter(permissions::is_deleted.eq(false))
                .order(permissions::created_at.desc())
                .limit(page_size)
                .offset(offset)
                .load::<Permission>(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let total: i64 = permissions::table
                .filter(permissions::is_deleted.eq(false))
                .count()
                .get_result(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            (perm_list, total)
        };

        Ok(PermissionListResponse {
            data: perm_list.into_iter().map(|p| p.into()).collect(),
            total,
            page,
            page_size,
        })
    }

    pub async fn update(
        &self,
        id: &str,
        req: UpdatePermissionRequest,
    ) -> AppResult<PermissionResponse> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let mut permission = permissions::table
            .filter(permissions::id.eq(id))
            .filter(permissions::is_deleted.eq(false))
            .first::<Permission>(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("Permission with id '{}' not found", id)))?;

        if let Some(display_name) = req.display_name {
            permission.display_name = display_name;
        }
        if let Some(description) = req.description {
            permission.description = Some(description);
        }
        if let Some(resource_type) = req.resource_type {
            permission.resource_type = resource_type;
        }
        if let Some(resources) = req.resources {
            permission.resources = resources;
        }
        if let Some(actions) = req.actions {
            permission.actions = actions;
        }
        if let Some(effect) = req.effect {
            permission.effect = effect;
        }
        if let Some(is_enabled) = req.is_enabled {
            permission.is_enabled = is_enabled;
        }
        permission.updated_at = Utc::now();

        let updated_permission = diesel::update(permissions::table.filter(permissions::id.eq(id)))
            .set((
                permissions::display_name.eq(&permission.display_name),
                permissions::description.eq(&permission.description),
                permissions::resource_type.eq(&permission.resource_type),
                permissions::resources.eq(&permission.resources),
                permissions::actions.eq(&permission.actions),
                permissions::effect.eq(&permission.effect),
                permissions::is_enabled.eq(permission.is_enabled),
                permissions::updated_at.eq(permission.updated_at),
            ))
            .returning(Permission::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(updated_permission.into())
    }

    pub async fn delete(&self, id: &str) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let count = diesel::update(
            permissions::table
                .filter(permissions::id.eq(id))
                .filter(permissions::is_deleted.eq(false)),
        )
        .set((
            permissions::is_deleted.eq(true),
            permissions::updated_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        if count == 0 {
            return Err(AppError::NotFound(format!(
                "Permission with id '{}' not found",
                id
            )));
        }

        Ok(())
    }

    pub async fn assign_permission(&self, req: AssignPermissionRequest) -> AppResult<()> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::insert_into(role_permissions::table)
            .values((
                role_permissions::id.eq(&id),
                role_permissions::role_id.eq(&req.role_id),
                role_permissions::permission_id.eq(&req.permission_id),
                role_permissions::created_at.eq(now),
            ))
            .on_conflict((role_permissions::role_id, role_permissions::permission_id))
            .do_nothing()
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(())
    }

    pub async fn remove_permission(&self, role_id: &str, permission_id: &str) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let count = diesel::delete(
            role_permissions::table
                .filter(role_permissions::role_id.eq(role_id))
                .filter(role_permissions::permission_id.eq(permission_id)),
        )
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        if count == 0 {
            return Err(AppError::NotFound(format!(
                "Permission assignment not found for role '{}' and permission '{}'",
                role_id, permission_id
            )));
        }

        Ok(())
    }

    pub async fn get_role_permissions(&self, role_id: &str) -> AppResult<Vec<PermissionResponse>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let perm_list = permissions::table
            .inner_join(
                role_permissions::table.on(permissions::id.eq(role_permissions::permission_id)),
            )
            .filter(role_permissions::role_id.eq(role_id))
            .filter(permissions::is_deleted.eq(false))
            .select(Permission::as_select())
            .load::<Permission>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(perm_list.into_iter().map(|p| p.into()).collect())
    }
}
