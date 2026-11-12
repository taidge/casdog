//! Casdoor Pricing.IsUserAllowed: invitations are exact current usernames,
//! including names not yet registered. They are not user UUID foreign keys.
use crate::{
    error::{AppError, AppResult},
    models::{Pricing, User},
};
use serde_json::{Map, Value};
use sqlx::PgConnection;
pub struct PricingAccessService;
impl PricingAccessService {
    pub fn validate_users(users: &[String]) -> AppResult<()> {
        if users.len() > 1000
            || users
                .iter()
                .any(|v| v.is_empty() || v.chars().count() > 100 || v.chars().any(char::is_control))
        {
            return Err(AppError::Validation(
                "Pricing users must be at most 1000 nonempty usernames of at most 100 characters"
                    .into(),
            ));
        }
        Ok(())
    }
    pub fn validate_fields(fields: &Map<String, Value>) -> AppResult<()> {
        if fields
            .get("is_invite_only")
            .is_some_and(|v| !v.is_boolean())
        {
            return Err(AppError::Validation("isInviteOnly must be boolean".into()));
        }
        if let Some(value) = fields.get("users") {
            let users: Vec<String> = serde_json::from_value(value.clone()).map_err(|_| {
                AppError::Validation("Pricing users must be an array of usernames".into())
            })?;
            Self::validate_users(&users)?;
        }
        Ok(())
    }
    pub fn allows(pricing: &Pricing, user: Option<&User>) -> bool {
        if Self::validate_users(&pricing.users).is_err() {
            return false;
        }
        !pricing.is_invite_only
            || user.is_some_and(|user| {
                user.owner == pricing.owner
                    && (pricing.users.is_empty()
                        || pricing.users.iter().any(|name| name == &user.name))
            })
    }
    pub fn allows_json(pricing: &Value, user: Option<&Value>) -> bool {
        let Some(invite) = pricing
            .get("is_invite_only")
            .or_else(|| pricing.get("isInviteOnly"))
            .and_then(Value::as_bool)
        else {
            return false;
        };
        let Some(users) = pricing.get("users").and_then(Value::as_array) else {
            return false;
        };
        let Some(names) = users
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<String>>>()
        else {
            return false;
        };
        if Self::validate_users(&names).is_err() {
            return false;
        }
        if !invite {
            return true;
        }
        user.is_some_and(|user| {
            pricing["owner"]
                .as_str()
                .is_some_and(|owner| user["owner"].as_str() == Some(owner))
                && user["name"]
                    .as_str()
                    .is_some_and(|name| names.is_empty() || names.iter().any(|value| value == name))
        })
    }
    pub async fn ensure_allowed_conn(
        conn: &mut PgConnection,
        pricing_id: &str,
        user_id: &str,
        owner: &str,
    ) -> AppResult<Pricing> {
        let pricing:Pricing=sqlx::query_as("SELECT * FROM pricings WHERE id=$1 AND owner=$2 AND is_enabled AND NOT is_deleted FOR SHARE").bind(pricing_id).bind(owner).fetch_optional(&mut *conn).await?.ok_or_else(||AppError::Authorization("Pricing unavailable".into()))?;
        let user:User=sqlx::query_as("SELECT u.* FROM users u JOIN organizations o ON o.name=u.owner WHERE u.id=$1 AND u.owner=$2 AND NOT u.is_deleted AND NOT u.is_forbidden AND NOT o.is_deleted AND NOT o.disable_signin FOR SHARE OF u,o").bind(user_id).bind(owner).fetch_optional(&mut *conn).await?.ok_or_else(||AppError::Authorization("Pricing requires a current user in its tenant".into()))?;
        if !Self::allows(&pricing, Some(&user)) {
            return Err(AppError::Authorization(
                "This pricing is invite-only".into(),
            ));
        }
        Ok(pricing)
    }
}
