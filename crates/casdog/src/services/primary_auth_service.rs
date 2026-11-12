//! Shared policy for server-verified passwordless and directory first factors.
use serde_json::{Value, json};
use sqlx::PgConnection;

use crate::{
    error::{AppError, AppResult},
    models::{Application, Organization, Provider, User},
    services::{CheckService, social_state_service::proof_hash},
};

pub struct PrimaryAuthService;
impl PrimaryAuthService {
    pub fn method_enabled(app: &Application, method: &str) -> bool {
        // Global switches remain authoritative when a configured methods list
        // narrows the available methods. LDAP has its own explicit list entry.
        if (method == "password" && !app.enable_password)
            || (matches!(method, "code_email" | "code_sms") && !app.enable_code_signin)
        {
            return false;
        }
        let methods = app.signin_methods.as_ref().and_then(Value::as_array);
        if methods.is_none_or(Vec::is_empty) {
            return match method {
                "password" => app.enable_password,
                "code_email" | "code_sms" => app.enable_code_signin,
                _ => false,
            };
        }
        methods.unwrap().iter().any(|entry| {
            let name = entry["name"].as_str().unwrap_or_default();
            let rule = entry["rule"].as_str().unwrap_or_default();
            if matches!(rule, "Hide" | "Hide-Password" | "None") {
                return false;
            }
            match method {
                "password" => name == "Password",
                "ldap" => name == "LDAP",
                "code_email" => name == "Verification code" && rule != "Phone only",
                "code_sms" => name == "Verification code" && rule != "Email only",
                _ => false,
            }
        })
    }

    pub fn credential_stamp(user: &User) -> String {
        proof_hash(
            &json!([
                user.password_hash,
                user.password_type,
                user.password_salt,
                user.email,
                user.phone,
                user.country_code,
                user.ldap,
            ])
            .to_string(),
        )
    }

    pub fn ldap_stamp(provider: &Provider, user: &User) -> String {
        proof_hash(
            &json!([
                provider.id,
                provider.owner,
                provider.category,
                provider.host,
                provider.port,
                provider.client_id,
                provider.client_secret,
                provider.metadata,
                provider.disable_ssl,
                user.ldap,
                user.name,
                user.external_id,
                user.email,
                user.phone,
            ])
            .to_string(),
        )
    }

    pub async fn account(
        conn: &mut PgConnection,
        owner: &str,
        identifier: &str,
    ) -> AppResult<User> {
        let users: Vec<User> = sqlx::query_as(
            "SELECT * FROM users WHERE owner=$1 AND NOT is_deleted AND NOT is_forbidden AND (name=$2 OR lower(email)=lower($2) OR phone=$2) ORDER BY id LIMIT 2 FOR UPDATE",
        ).bind(owner).bind(identifier).fetch_all(&mut *conn).await?;
        if users.len() != 1 {
            return Err(Self::denied());
        }
        Ok(users.into_iter().next().unwrap())
    }

    pub async fn policy(
        conn: &mut PgConnection,
        user: &User,
        app: &Application,
        method: &str,
    ) -> AppResult<Organization> {
        if user.is_deleted
            || user.is_forbidden
            || app.is_deleted
            || app.organization != user.owner
            || !Self::method_enabled(app, method)
        {
            return Err(Self::denied());
        }
        let org: Organization = sqlx::query_as(
            "SELECT * FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin",
        )
        .bind(&user.owner)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(Self::denied)?;
        CheckService::check_signin_lockout(
            user.signin_wrong_times,
            user.last_signin_wrong_time.as_deref(),
            None,
            None,
        )?;
        CheckService::check_login_permission_conn(conn, &user.id, &app.id).await?;
        Ok(org)
    }

    pub async fn ldap_provider(conn: &mut PgConnection, user: &User) -> AppResult<Provider> {
        let reference = user
            .ldap
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(Self::denied)?;
        sqlx::query_as("SELECT * FROM providers WHERE owner=$1 AND category='LDAP' AND (id=$2 OR name=$2 OR owner||'/'||name=$2)")
            .bind(&user.owner).bind(reference).fetch_optional(&mut *conn).await?.ok_or_else(Self::denied)
    }

    pub async fn delivery_provider(
        conn: &mut PgConnection,
        app: &Application,
        user: &User,
        method: &str,
    ) -> AppResult<Provider> {
        let category = if method == "email" { "Email" } else { "SMS" };
        for item in app
            .providers
            .as_ref()
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(reference) = item["name"].as_str() else {
                continue;
            };
            let rule = item["rule"].as_str().unwrap_or_default();
            if !rule.is_empty()
                && !["all", "signin", "login"]
                    .iter()
                    .any(|r| rule.eq_ignore_ascii_case(r))
            {
                continue;
            }
            if method == "sms"
                && item["countryCodes"].as_array().is_some_and(|countries| {
                    !countries.is_empty()
                        && !countries
                            .iter()
                            .any(|c| c.as_str() == user.country_code.as_deref())
                })
            {
                continue;
            }
            let provider: Option<Provider>=sqlx::query_as("SELECT * FROM providers WHERE category=$1 AND (owner=$2 OR owner=$3) AND (owner||'/'||name=$4 OR (owner=$2 AND name=$4) OR id=$4)")
                .bind(category).bind(&app.owner).bind(&user.owner).bind(reference).fetch_optional(&mut *conn).await?;
            if let Some(provider) = provider {
                return Ok(provider);
            }
        }
        Err(AppError::Authorization(
            "Configure a sign-in delivery provider for this application".into(),
        ))
    }

    pub fn denied() -> AppError {
        AppError::Authentication("Invalid or expired primary authentication".into())
    }
}
