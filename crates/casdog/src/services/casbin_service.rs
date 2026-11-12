use std::sync::Arc;

use casbin::{Assertion, CoreApi, DefaultModel, Enforcer, MemoryAdapter, MgmtApi, Model, RbacApi};
use sqlx::{PgPool, postgres::PgPoolOptions};
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
    pool: PgPool,
}

impl CasbinService {
    pub async fn new() -> AppResult<Self> {
        let config = AppConfig::get();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&config.database.url)
            .await?;
        Self::with_pool(pool).await
    }

    pub async fn with_pool(pool: PgPool) -> AppResult<Self> {
        let model_path = AppConfig::get().casbin.model_path;

        let model = DefaultModel::from_file(&model_path)
            .await
            .map_err(|e| AppError::Casbin(format!("Failed to load casbin model: {}", e)))?;

        Self::with_model_and_pool(model, pool).await
    }

    pub async fn with_model_and_pool(model: DefaultModel, pool: PgPool) -> AppResult<Self> {
        let adapter = SqlxAdapter::new_with_pool(pool.clone())
            .await
            .map_err(|e| AppError::Casbin(format!("Failed to create adapter: {}", e)))?;

        let enforcer = Enforcer::new(model, adapter)
            .await
            .map_err(|e| AppError::Casbin(format!("Failed to create enforcer: {}", e)))?;

        Ok(Self {
            enforcer: Arc::new(RwLock::new(enforcer)),
            pool,
        })
    }

    /// Add paid roles to an isolated policy snapshot. Never persist temporary
    /// grouping rules or share their role managers with the base enforcer.
    /// Evaluating once with all memberships preserves the model's deny effect.
    async fn subscription_enforcer(
        &self,
        subject: &str,
        alias: Option<&str>,
    ) -> AppResult<Option<Enforcer>> {
        let Some((owner, name)) = subject.split_once('/') else {
            return Ok(None);
        };
        let base = self.enforcer.read().await;
        let mut model = DefaultModel::default();
        for (section, assertions) in base.get_model().get_model() {
            for (key, assertion) in assertions {
                model
                    .get_mut_model()
                    .entry(section.clone())
                    .or_default()
                    .insert(
                        key.clone(),
                        Assertion {
                            key: assertion.key.clone(),
                            value: assertion.value.clone(),
                            tokens: assertion.tokens.clone(),
                            policy: assertion.policy.clone(),
                            ..Default::default()
                        },
                    );
            }
        }
        drop(base);
        // Read after the policy lock, so waiting for a policy update cannot
        // retain subscription grants that expired while the lock was held.
        let roles = super::SubscriptionService::active_role_names(&self.pool, owner, name).await?;
        if roles.is_empty() {
            return Ok(None);
        }
        for role in roles {
            if !model.add_policy("g", "g", vec![subject.into(), role]) {
                // An existing grouping is valid too; a model without g is not.
                if !model
                    .get_model()
                    .get("g")
                    .is_some_and(|g| g.contains_key("g"))
                {
                    return Err(AppError::Casbin(
                        "Subscription roles require an RBAC g definition".into(),
                    ));
                }
            }
        }
        if let Some(alias) = alias.filter(|alias| *alias != subject) {
            model.add_policy("g", "g", vec![alias.into(), subject.into()]);
        }
        let mut enforcer = Enforcer::new_raw(model, MemoryAdapter::default())
            .await
            .map_err(|error| AppError::Casbin(error.to_string()))?;
        enforcer
            .build_role_links()
            .map_err(|error| AppError::Casbin(error.to_string()))?;
        Ok(Some(enforcer))
    }

    pub async fn enforce(&self, req: EnforceRequest) -> AppResult<EnforceResponse> {
        let allowed = self.check_permission(&req.sub, &req.obj, &req.act).await?;
        Ok(EnforceResponse { allowed })
    }

    pub async fn check_permission(&self, sub: &str, obj: &str, act: &str) -> AppResult<bool> {
        self.reload().await?;
        if let Some(enforcer) = self.subscription_enforcer(sub, None).await? {
            return enforcer
                .enforce((sub, obj, act))
                .map_err(|error| AppError::Casbin(error.to_string()));
        }
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
        self.reload().await?;
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
        self.reload().await?;
        if let Some(enforcer) = self.subscription_enforcer(user, None).await? {
            return Ok(enforcer.get_roles_for_user(user, None));
        }
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
        let mut results = Vec::with_capacity(reqs.len());

        for req in reqs {
            let allowed = self.check_permission(&req.sub, &req.obj, &req.act).await?;
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

    /// Enforces a 6-tuple authorization check used by the `AuthzFilter` hoop.
    ///
    /// The tuple follows Casdoor's API authorization model:
    /// `(sub_owner, sub_name, method, url_path, obj_owner, obj_name)`
    ///
    /// If the enforcer's model does not support a 6-tuple (e.g. only 3 values),
    /// the method falls back to a 3-tuple check `(sub_name, url_path, method)`.
    /// Configuration and enforcement errors are propagated to the caller.
    pub async fn enforce_ex(
        &self,
        sub_owner: &str,
        sub_name: &str,
        method: &str,
        url_path: &str,
        obj_owner: &str,
        obj_name: &str,
    ) -> AppResult<bool> {
        self.reload().await?;
        if let Some(enforcer) = self
            .subscription_enforcer(&format!("{sub_owner}/{sub_name}"), Some(sub_name))
            .await?
        {
            return Self::enforce_tuple(
                &enforcer, sub_owner, sub_name, method, url_path, obj_owner, obj_name,
            );
        }
        let enforcer = self.enforcer.read().await;
        Self::enforce_tuple(
            &enforcer, sub_owner, sub_name, method, url_path, obj_owner, obj_name,
        )
    }

    fn enforce_tuple(
        enforcer: &Enforcer,
        sub_owner: &str,
        sub_name: &str,
        method: &str,
        url_path: &str,
        obj_owner: &str,
        obj_name: &str,
    ) -> AppResult<bool> {
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
