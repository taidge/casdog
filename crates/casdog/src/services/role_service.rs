use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::{
    AssignRoleRequest, CreateRoleRequest, Role, RoleListResponse, RoleQuery, RoleResponse,
    UpdateRoleRequest,
};
use crate::schema::{roles, user_roles};

#[derive(Clone)]
pub struct RoleService {
    pool: DieselPool,
}

impl RoleService {
    pub fn new(pool: DieselPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, req: CreateRoleRequest) -> AppResult<RoleResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let role = diesel::insert_into(roles::table)
            .values((
                roles::id.eq(&id),
                roles::owner.eq(&req.owner),
                roles::name.eq(&req.name),
                roles::display_name.eq(&req.display_name),
                roles::description.eq(&req.description),
                roles::is_enabled.eq(req.is_enabled.unwrap_or(true)),
                roles::created_at.eq(now),
                roles::updated_at.eq(now),
            ))
            .returning(Role::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                ) => AppError::Conflict(format!(
                    "Role '{}' already exists in '{}'",
                    req.name, req.owner
                )),
                _ => AppError::Internal(e.to_string()),
            })?;

        Ok(role.into())
    }

    pub async fn get_by_id(&self, id: &str) -> AppResult<RoleResponse> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let role = roles::table
            .filter(roles::id.eq(id))
            .filter(roles::is_deleted.eq(false))
            .first::<Role>(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("Role with id '{}' not found", id)))?;

        Ok(role.into())
    }

    pub async fn list(&self, query: RoleQuery) -> AppResult<RoleListResponse> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).min(100);
        let offset = (page - 1) * page_size;

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let (role_list, total): (Vec<Role>, i64) = if let Some(ref owner) = query.owner {
            let role_list = roles::table
                .filter(roles::owner.eq(owner))
                .filter(roles::is_deleted.eq(false))
                .order(roles::created_at.desc())
                .limit(page_size)
                .offset(offset)
                .load::<Role>(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let total: i64 = roles::table
                .filter(roles::owner.eq(owner))
                .filter(roles::is_deleted.eq(false))
                .count()
                .get_result(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            (role_list, total)
        } else {
            let role_list = roles::table
                .filter(roles::is_deleted.eq(false))
                .order(roles::created_at.desc())
                .limit(page_size)
                .offset(offset)
                .load::<Role>(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let total: i64 = roles::table
                .filter(roles::is_deleted.eq(false))
                .count()
                .get_result(&mut conn)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            (role_list, total)
        };

        Ok(RoleListResponse {
            data: role_list.into_iter().map(|r| r.into()).collect(),
            total,
            page,
            page_size,
        })
    }

    pub async fn update(&self, id: &str, req: UpdateRoleRequest) -> AppResult<RoleResponse> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let mut role = roles::table
            .filter(roles::id.eq(id))
            .filter(roles::is_deleted.eq(false))
            .first::<Role>(&mut conn)
            .await
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("Role with id '{}' not found", id)))?;

        if let Some(display_name) = req.display_name {
            role.display_name = display_name;
        }
        if let Some(description) = req.description {
            role.description = Some(description);
        }
        if let Some(is_enabled) = req.is_enabled {
            role.is_enabled = is_enabled;
        }
        role.updated_at = Utc::now();

        let updated_role = diesel::update(roles::table.filter(roles::id.eq(id)))
            .set((
                roles::display_name.eq(&role.display_name),
                roles::description.eq(&role.description),
                roles::is_enabled.eq(role.is_enabled),
                roles::updated_at.eq(role.updated_at),
            ))
            .returning(Role::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(updated_role.into())
    }

    pub async fn delete(&self, id: &str) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let count = diesel::update(
            roles::table
                .filter(roles::id.eq(id))
                .filter(roles::is_deleted.eq(false)),
        )
        .set((roles::is_deleted.eq(true), roles::updated_at.eq(Utc::now())))
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        if count == 0 {
            return Err(AppError::NotFound(format!(
                "Role with id '{}' not found",
                id
            )));
        }

        Ok(())
    }

    pub async fn assign_role(&self, req: AssignRoleRequest) -> AppResult<()> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        diesel::insert_into(user_roles::table)
            .values((
                user_roles::id.eq(&id),
                user_roles::user_id.eq(&req.user_id),
                user_roles::role_id.eq(&req.role_id),
                user_roles::created_at.eq(now),
            ))
            .on_conflict((user_roles::user_id, user_roles::role_id))
            .do_nothing()
            .execute(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(())
    }

    pub async fn remove_role(&self, user_id: &str, role_id: &str) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let count = diesel::delete(
            user_roles::table
                .filter(user_roles::user_id.eq(user_id))
                .filter(user_roles::role_id.eq(role_id)),
        )
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        if count == 0 {
            return Err(AppError::NotFound(format!(
                "User role assignment not found for user '{}' and role '{}'",
                user_id, role_id
            )));
        }

        Ok(())
    }

    pub async fn get_user_roles(&self, user_id: &str) -> AppResult<Vec<RoleResponse>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let role_list = roles::table
            .inner_join(user_roles::table.on(roles::id.eq(user_roles::role_id)))
            .filter(user_roles::user_id.eq(user_id))
            .filter(roles::is_deleted.eq(false))
            .select(Role::as_select())
            .load::<Role>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(role_list.into_iter().map(|r| r.into()).collect())
    }
}
