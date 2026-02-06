use std::sync::Arc;

use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi, RbacApi};
use sqlx_adapter::SqlxAdapter;
use tokio::sync::RwLock;

use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::{
    BatchEnforceResponse, EnforceRequest, EnforceRequestItem, EnforceResponse, EnforceResultItem,
    PolicyListResponse, PolicyRequest, PolicyResponse,
};

#[derive(Clone)]
pub struct CasbinService {
    enforcer: Arc<RwLock<Enforcer>>,
}

impl CasbinService {
    pub async fn new() -> AppResult<Self> {
        let config = AppConfig::get();
        let model_path = config.casbin.model_path.clone();
        let db_url = config.database.url.clone();

        let model = DefaultModel::from_file(&model_path)
            .await
            .map_err(|e| AppError::Casbin(format!("Failed to load casbin model: {}", e)))?;

        let adapter = SqlxAdapter::new(&db_url, 8)
            .await
            .map_err(|e| AppError::Casbin(format!("Failed to create adapter: {}", e)))?;

        let enforcer = Enforcer::new(model, adapter)
            .await
            .map_err(|e| AppError::Casbin(format!("Failed to create enforcer: {}", e)))?;

        Ok(Self {
            enforcer: Arc::new(RwLock::new(enforcer)),
        })
    }

    pub async fn enforce(&self, req: EnforceRequest) -> AppResult<EnforceResponse> {
        let enforcer = self.enforcer.read().await;
        let allowed = enforcer
            .enforce((&req.sub, &req.obj, &req.act))
            .map_err(|e| AppError::Casbin(format!("Enforce error: {}", e)))?;

        Ok(EnforceResponse { allowed })
    }

    pub async fn check_permission(&self, sub: &str, obj: &str, act: &str) -> AppResult<bool> {
        let enforcer = self.enforcer.read().await;
        let allowed = enforcer
            .enforce((sub, obj, act))
            .map_err(|e| AppError::Casbin(format!("Enforce error: {}", e)))?;

        Ok(allowed)
    }

    pub async fn add_policy(&self, req: PolicyRequest) -> AppResult<bool> {
        let mut enforcer = self.enforcer.write().await;

        let policy = if req.ptype == "p" {
            vec![req.v0, req.v1, req.v2]
        } else if req.ptype == "g" {
            vec![req.v0, req.v1]
        } else {
            return Err(AppError::Validation(format!(
                "Invalid policy type: {}",
                req.ptype
            )));
        };

        let added = if req.ptype == "p" {
            enforcer
                .add_policy(policy)
                .await
                .map_err(|e| AppError::Casbin(format!("Failed to add policy: {}", e)))?
        } else {
            enforcer
                .add_grouping_policy(policy)
                .await
                .map_err(|e| AppError::Casbin(format!("Failed to add grouping policy: {}", e)))?
        };

        Ok(added)
    }

    pub async fn remove_policy(&self, req: PolicyRequest) -> AppResult<bool> {
        let mut enforcer = self.enforcer.write().await;

        let policy = if req.ptype == "p" {
            vec![req.v0, req.v1, req.v2]
        } else if req.ptype == "g" {
            vec![req.v0, req.v1]
        } else {
            return Err(AppError::Validation(format!(
                "Invalid policy type: {}",
                req.ptype
            )));
        };

        let removed = if req.ptype == "p" {
            enforcer
                .remove_policy(policy)
                .await
                .map_err(|e| AppError::Casbin(format!("Failed to remove policy: {}", e)))?
        } else {
            enforcer
                .remove_grouping_policy(policy)
                .await
                .map_err(|e| AppError::Casbin(format!("Failed to remove grouping policy: {}", e)))?
        };

        Ok(removed)
    }

    pub async fn get_policies(&self) -> AppResult<PolicyListResponse> {
        let enforcer = self.enforcer.read().await;

        let policies = enforcer.get_policy();
        let grouping_policies = enforcer.get_grouping_policy();

        let mut data: Vec<PolicyResponse> = policies
            .into_iter()
            .map(|p| PolicyResponse {
                ptype: "p".to_string(),
                v0: p.get(0).cloned().unwrap_or_default(),
                v1: p.get(1).cloned().unwrap_or_default(),
                v2: p.get(2).cloned().unwrap_or_default(),
                v3: p.get(3).cloned(),
                v4: p.get(4).cloned(),
            })
            .collect();

        let grouping_data: Vec<PolicyResponse> = grouping_policies
            .into_iter()
            .map(|p| PolicyResponse {
                ptype: "g".to_string(),
                v0: p.get(0).cloned().unwrap_or_default(),
                v1: p.get(1).cloned().unwrap_or_default(),
                v2: String::new(),
                v3: p.get(2).cloned(),
                v4: p.get(3).cloned(),
            })
            .collect();

        data.extend(grouping_data);

        Ok(PolicyListResponse { data })
    }

    pub async fn add_role_for_user(&self, user: &str, role: &str) -> AppResult<bool> {
        let mut enforcer = self.enforcer.write().await;
        let added = enforcer
            .add_grouping_policy(vec![user.to_string(), role.to_string()])
            .await
            .map_err(|e| AppError::Casbin(format!("Failed to add role for user: {}", e)))?;

        Ok(added)
    }

    pub async fn delete_role_for_user(&self, user: &str, role: &str) -> AppResult<bool> {
        let mut enforcer = self.enforcer.write().await;
        let removed = enforcer
            .remove_grouping_policy(vec![user.to_string(), role.to_string()])
            .await
            .map_err(|e| AppError::Casbin(format!("Failed to remove role for user: {}", e)))?;

        Ok(removed)
    }

    pub async fn get_roles_for_user(&self, user: &str) -> AppResult<Vec<String>> {
        let enforcer = self.enforcer.read().await;
        let roles = enforcer.get_roles_for_user(user, None);
        Ok(roles)
    }

    pub async fn reload(&self) -> AppResult<()> {
        let mut enforcer = self.enforcer.write().await;
        enforcer
            .load_policy()
            .await
            .map_err(|e| AppError::Casbin(format!("Failed to reload policy: {}", e)))?;
        Ok(())
    }

    pub async fn batch_enforce(
        &self,
        reqs: Vec<EnforceRequestItem>,
    ) -> AppResult<BatchEnforceResponse> {
        let enforcer = self.enforcer.read().await;
        let mut results = Vec::with_capacity(reqs.len());

        for req in reqs {
            let allowed = enforcer
                .enforce((&req.sub, &req.obj, &req.act))
                .map_err(|e| AppError::Casbin(format!("Batch enforce error: {}", e)))?;
            results.push(EnforceResultItem {
                sub: req.sub,
                obj: req.obj,
                act: req.act,
                allowed,
            });
        }

        Ok(BatchEnforceResponse { results })
    }

    pub async fn get_all_objects(&self) -> AppResult<Vec<String>> {
        let enforcer = self.enforcer.read().await;
        let policies = enforcer.get_policy();

        let mut objects: Vec<String> = policies
            .into_iter()
            .filter_map(|p| p.get(1).cloned())
            .collect();
        objects.sort();
        objects.dedup();

        Ok(objects)
    }

    pub async fn get_all_actions(&self) -> AppResult<Vec<String>> {
        let enforcer = self.enforcer.read().await;
        let policies = enforcer.get_policy();

        let mut actions: Vec<String> = policies
            .into_iter()
            .filter_map(|p| p.get(2).cloned())
            .collect();
        actions.sort();
        actions.dedup();

        Ok(actions)
    }

    pub async fn get_all_roles(&self) -> AppResult<Vec<String>> {
        let enforcer = self.enforcer.read().await;
        let grouping_policies = enforcer.get_grouping_policy();

        let mut roles: Vec<String> = grouping_policies
            .into_iter()
            .filter_map(|p| p.get(1).cloned())
            .collect();
        roles.sort();
        roles.dedup();

        Ok(roles)
    }

    /// Enforces a 6-tuple authorization check used by the `AuthzFilter` middleware.
    ///
    /// The tuple follows Casdoor's API authorization model:
    /// `(sub_owner, sub_name, method, url_path, obj_owner, obj_name)`
    ///
    /// If the enforcer's model does not support a 6-tuple (e.g. only 3 values),
    /// the method falls back to a 3-tuple check `(sub_name, url_path, method)`.
    /// If the enforcer is not available or not configured, this returns `Ok(true)`
    /// (allow) to avoid blocking requests when authorization is not set up.
    pub async fn enforce_ex(
        &self,
        sub_owner: &str,
        sub_name: &str,
        method: &str,
        url_path: &str,
        obj_owner: &str,
        obj_name: &str,
    ) -> AppResult<bool> {
        let enforcer = self.enforcer.read().await;

        // Try 6-tuple enforcement first (matches Casdoor's model)
        let result = enforcer.enforce((sub_owner, sub_name, method, url_path, obj_owner, obj_name));

        match result {
            Ok(allowed) => Ok(allowed),
            Err(_) => {
                // If 6-tuple fails (e.g. model only supports 3 args), try 3-tuple fallback
                let fallback = enforcer
                    .enforce((sub_name, url_path, method))
                    .map_err(|e| {
                        AppError::Casbin(format!("Enforce error (fallback 3-tuple): {}", e))
                    })?;
                Ok(fallback)
            }
        }
    }
}
