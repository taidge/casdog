//! Live API credential authentication. Credentials identify a current principal;
//! they never mint a user session or confer authority by their mere presence.
use base64::{Engine, engine::general_purpose::STANDARD};
use salvo::{Depot, Request};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use subtle::ConstantTimeEq;

use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    models::Application,
};

#[derive(Clone, Debug)]
pub enum CredentialIdentity {
    User(Principal),
    Application {
        principal: Principal,
        application_id: String,
        trusted_static: bool,
    },
}
impl CredentialIdentity {
    pub fn principal(&self) -> &Principal {
        match self {
            Self::User(p) | Self::Application { principal: p, .. } => p,
        }
    }
}

pub fn application_identity(depot: &Depot) -> bool {
    matches!(
        depot.obtain::<CredentialIdentity>(),
        Ok(CredentialIdentity::Application { .. })
    )
}
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialSource {
    Bearer(String),
    AccessKey(String, String),
    Client(String, String),
    Basic(String, String),
}

/// Load the configured Casbin model with current shared policies for a service
/// identity. Reload per decision so revocation also works across instances.
pub async fn application_policy(
    pool: &PgPool,
    principal: &Principal,
    path: &str,
    method: &str,
) -> AppResult<bool> {
    use casbin::{CoreApi, DefaultModel, Enforcer, MemoryAdapter, MgmtApi};
    let model = DefaultModel::from_file(&crate::config::AppConfig::get().casbin.model_path)
        .await
        .map_err(|_| privilege_denied())?;
    let mut enforcer = Enforcer::new(model, MemoryAdapter::default())
        .await
        .map_err(|_| privilege_denied())?;
    let policies: Vec<(String, String, String, String, String, String, String)> =
        sqlx::query_as("SELECT ptype,v0,v1,v2,v3,v4,v5 FROM casbin_rule ORDER BY id")
            .fetch_all(pool)
            .await?;
    for (ptype, v0, v1, v2, v3, v4, v5) in policies {
        let mut values = vec![v0, v1, v2, v3, v4, v5];
        while values.last().is_some_and(String::is_empty) {
            values.pop();
        }
        if ptype.starts_with('p') {
            enforcer
                .add_named_policy(&ptype, values)
                .await
                .map_err(|_| privilege_denied())?;
        } else if ptype.starts_with('g') {
            enforcer
                .add_named_grouping_policy(&ptype, values)
                .await
                .map_err(|_| privilege_denied())?;
        }
    }
    enforcer
        .enforce((
            format!("{}/{}", principal.owner, principal.name),
            path,
            method,
        ))
        .map_err(|_| privilege_denied())
}
fn denied() -> AppError {
    AppError::Authentication("Invalid API credentials or principal unavailable".into())
}
fn privilege_denied() -> AppError {
    AppError::Authorization(
        "A current real administrator of the application organization is required".into(),
    )
}
fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap_or("")
}
fn equal_secret(expected: &str, actual: &str) -> bool {
    // Fixed-length digest comparison also avoids secret-length timing differences.
    bool::from(Sha256::digest(expected.as_bytes()).ct_eq(&Sha256::digest(actual.as_bytes())))
        && !expected.is_empty()
        && !actual.is_empty()
}
fn pair(first: Option<String>, second: Option<String>) -> AppResult<Option<(String, String)>> {
    match (first, second) {
        (None, None) => Ok(None),
        (Some(id), Some(secret))
            if !id.is_empty() && id.len() <= 1024 && !secret.is_empty() && secret.len() <= 4096 =>
        {
            Ok(Some((id, secret)))
        }
        _ => Err(denied()),
    }
}
/// Exactly one explicit source is accepted. Failed credentials cannot fall back
/// to another transport, an old identity in Depot, or anonymous authorization.
pub fn source(req: &Request) -> AppResult<Option<CredentialSource>> {
    for name in [
        "accessKey",
        "accessSecret",
        "clientId",
        "clientSecret",
        "accessToken",
    ] {
        if req
            .queries()
            .get_vec(name)
            .is_some_and(|values| values.len() != 1)
        {
            return Err(denied());
        }
    }
    let mut sources = Vec::new();
    if let Some((id, secret)) = pair(req.query("accessKey"), req.query("accessSecret"))? {
        sources.push(CredentialSource::AccessKey(id, secret));
    }
    if let Some((id, secret)) = pair(req.query("clientId"), req.query("clientSecret"))? {
        sources.push(CredentialSource::Client(id, secret));
    }
    if let Some(token) = req.query::<String>("accessToken") {
        if token.is_empty() || token.len() > 16384 {
            return Err(denied());
        }
        sources.push(CredentialSource::Bearer(token));
    }
    let auth: Vec<_> = req.headers().get_all("Authorization").iter().collect();
    if auth.len() > 1 {
        return Err(denied());
    }
    if let Some(auth) = auth.first() {
        let auth = auth.to_str().map_err(|_| denied())?;
        let (scheme, value) = auth.split_once(' ').ok_or_else(denied)?;
        if scheme.eq_ignore_ascii_case("Bearer") {
            if value.is_empty() || value.len() > 16384 {
                return Err(denied());
            }
            sources.push(CredentialSource::Bearer(value.into()));
        } else if scheme.eq_ignore_ascii_case("Basic") {
            if value.len() > 8192 {
                return Err(denied());
            }
            let bytes = STANDARD.decode(value).map_err(|_| denied())?;
            let value = String::from_utf8(bytes).map_err(|_| denied())?;
            let (id, secret) = value.split_once(':').ok_or_else(denied)?;
            let (id, secret) = pair(Some(id.into()), Some(secret.into()))?.ok_or_else(denied)?;
            sources.push(CredentialSource::Basic(id, secret));
        } else {
            return Err(denied());
        }
    }
    if sources.len() > 1 {
        return Err(denied());
    }
    Ok(sources.pop())
}

pub fn insert_identity(depot: &mut Depot, identity: CredentialIdentity) {
    crate::hoops::authz::set_application_identity(
        depot,
        matches!(identity, CredentialIdentity::Application { .. }),
    );
    let p = identity.principal();
    depot.insert("user_id", p.id.clone());
    depot.insert("user_owner", p.owner.clone());
    depot.insert("user_name", p.name.clone());
    depot.insert("is_admin", p.admin);
    if let CredentialIdentity::Application { application_id, .. } = &identity {
        depot.insert("application_identity", application_id.clone());
    }
    depot.inject(identity);
}

pub async fn authenticate(
    pool: &PgPool,
    source: &CredentialSource,
) -> AppResult<CredentialIdentity> {
    let (id, secret, basic, client) = match source {
        CredentialSource::AccessKey(id, secret) => (id, secret, false, false),
        CredentialSource::Client(id, secret) => (id, secret, false, true),
        CredentialSource::Basic(id, secret) => (id, secret, true, false),
        CredentialSource::Bearer(_) => return Err(denied()),
    };
    // Read all credential and binding state from one database snapshot. No
    // process-local cache can keep a revoked Key or deleted subject alive.
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let keys: Vec<(String, Value)> = if !client {
        sqlx::query_as("SELECT owner,document FROM casdoor_objects WHERE kind='key' AND document->>'accessKey'=$1 LIMIT 2").bind(id).fetch_all(&mut *tx).await?
    } else {
        Vec::new()
    };
    let users: Vec<(String, String, String, bool, String, bool)> = if !client {
        sqlx::query_as("SELECT id,owner,name,is_admin,COALESCE(access_secret,''),NOT is_deleted AND NOT is_forbidden FROM users WHERE access_key=$1 AND access_key<>'' LIMIT 2").bind(id).fetch_all(&mut *tx).await?
    } else {
        Vec::new()
    };
    let applications: Vec<Application> = if basic || client {
        sqlx::query_as("SELECT * FROM applications WHERE client_id=$1 LIMIT 2")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?
    } else {
        Vec::new()
    };
    if keys.len() + users.len() + applications.len() != 1 {
        return Err(denied());
    }
    let result = if let Some((owner, key)) = keys.first() {
        if text(key, "owner") != owner
            || !equal_secret(text(key, "accessSecret"), secret)
            || text(key, "state") != "Active"
            || !["User", "Application", "Organization", "General"].contains(&text(key, "type"))
        {
            return Err(denied());
        }
        let expires = text(key, "expireTime");
        if !expires.is_empty() {
            let expiry = chrono::DateTime::parse_from_rfc3339(expires).map_err(|_| denied())?;
            let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *tx)
                .await?;
            if now >= expiry {
                return Err(denied());
            }
        }
        let org = text(key, "organization");
        if org != owner {
            return Err(denied());
        }
        organization(&mut tx, org).await?;
        let app = if text(key, "application").is_empty() {
            None
        } else {
            Some(bound_application(&mut tx, org, text(key, "application")).await?)
        };
        let user = text(key, "user");
        if text(key, "type") == "User" && user.is_empty()
            || text(key, "type") == "Application" && app.is_none()
        {
            return Err(denied());
        }
        // Upstream chooses User before Application irrespective of Type. Keys
        // with no bound subject (General/Organization) are not sign-in proofs.
        if !user.is_empty() {
            let (id,owner,name,admin):(String,String,String,bool)=sqlx::query_as("SELECT id,owner,name,is_admin FROM users WHERE owner=$1 AND name=$2 AND NOT is_deleted AND NOT is_forbidden")
                .bind(org).bind(user).fetch_optional(&mut *tx).await?.ok_or_else(denied)?;
            if let Some(app) = app {
                crate::services::CheckService::check_login_permission_conn(&mut tx, &id, &app.id)
                    .await?;
            }
            CredentialIdentity::User(Principal {
                application_identity: false,
                id,
                owner,
                name,
                admin,
            })
        } else if let Some(app) = app {
            app_identity(&mut tx, &app).await?
        } else {
            return Err(denied());
        }
    } else if let Some((id, owner, name, admin, expected, active)) = users.first() {
        if !active || !equal_secret(expected, secret) {
            return Err(denied());
        }
        organization(&mut tx, owner).await?;
        CredentialIdentity::User(Principal {
            application_identity: false,
            id: id.clone(),
            owner: owner.clone(),
            name: name.clone(),
            admin: *admin,
        })
    } else {
        let app = applications.first().ok_or_else(denied)?;
        if app.is_deleted || !equal_secret(&app.client_secret, secret) {
            return Err(denied());
        }
        organization(&mut tx, &app.organization).await?;
        app_identity(&mut tx, app).await?
    };
    tx.commit().await?;
    Ok(result)
}
async fn organization(conn: &mut PgConnection, organization: &str) -> AppResult<()> {
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin)").bind(organization).fetch_one(conn).await?;
    if active { Ok(()) } else { Err(denied()) }
}
async fn bound_application(
    conn: &mut PgConnection,
    org: &str,
    reference: &str,
) -> AppResult<Application> {
    let (owner, name) = reference
        .split_once('/')
        .map(|(o, n)| (Some(o), n))
        .unwrap_or((None, reference));
    let apps:Vec<Application>=sqlx::query_as("SELECT * FROM applications WHERE organization=$1 AND name=$2 AND ($3::text IS NULL OR owner=$3) AND NOT is_deleted LIMIT 2").bind(org).bind(name).bind(owner).fetch_all(conn).await?;
    if apps.len() != 1 {
        return Err(denied());
    }
    Ok(apps.into_iter().next().unwrap())
}
fn dynamic(app: &Application) -> bool {
    app.name.starts_with("dcr_")
        || app.tags.as_ref().is_some_and(|tags| {
            tags.as_array().is_some_and(|tags| {
                tags.iter()
                    .any(|tag| matches!(tag.as_str(), Some("dcr" | "cimd")))
            })
        })
}
async fn app_identity(conn: &mut PgConnection, app: &Application) -> AppResult<CredentialIdentity> {
    let origin:Option<(String,String,String)>=sqlx::query_as("SELECT origin,application_owner,organization FROM application_credential_origins WHERE application_id=$1").bind(&app.id).fetch_optional(conn).await?;
    let trusted_static = !dynamic(app)
        && origin.is_some_and(|(origin, owner, org)| {
            origin == "static" && owner == app.owner && org == app.organization
        });
    let principal = Principal {
        application_identity: true,
        id: format!("app:{}", app.id),
        owner: app.organization.clone(),
        name: format!("app/{}/{}", app.owner, app.name),
        admin: trusted_static,
    };
    Ok(CredentialIdentity::Application {
        principal,
        application_id: app.id.clone(),
        trusted_static,
    })
}

async fn approver(conn: &mut PgConnection, app: &Application, actor: &Principal) -> AppResult<()> {
    if actor.is_application()
        || !actor.admin
        || (!actor.global_admin() && actor.owner != app.organization)
    {
        return Err(privilege_denied());
    }
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND owner=$2 AND name=$3 AND is_admin AND NOT is_deleted AND NOT is_forbidden)")
        .bind(&actor.id).bind(&actor.owner).bind(&actor.name).fetch_one(&mut *conn).await?;
    if !active {
        return Err(privilege_denied());
    }
    organization(conn, &actor.owner).await?;
    organization(conn, &app.organization).await?;
    Ok(())
}
/// For trusted normal application creation only; existing origins are immutable
/// here. Historical unverified applications require explicit review/trust.
pub async fn mark_static_application(
    pool: &PgPool,
    application_id: &str,
    actor: &Principal,
) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    mark_static_application_conn(&mut tx, application_id, actor).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn mark_static_application_conn(
    conn: &mut PgConnection,
    application_id: &str,
    actor: &Principal,
) -> AppResult<()> {
    let app: Application =
        sqlx::query_as("SELECT * FROM applications WHERE id=$1 AND NOT is_deleted FOR UPDATE")
            .bind(application_id)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or_else(privilege_denied)?;
    approver(conn, &app, actor).await?;
    if dynamic(&app) {
        return Err(privilege_denied());
    }
    sqlx::query("INSERT INTO application_credential_origins(application_id,origin,application_owner,organization,approved_by) VALUES($1,'static',$2,$3,$4) ON CONFLICT(application_id) DO NOTHING")
        .bind(&app.id).bind(&app.owner).bind(&app.organization).bind(&actor.id).execute(conn).await?;
    Ok(())
}
pub async fn mark_dynamic_application(pool: &PgPool, application_id: &str) -> AppResult<()> {
    sqlx::query("INSERT INTO application_credential_origins(application_id,origin,application_owner,organization) SELECT id,'dynamic',owner,organization FROM applications WHERE id=$1 ON CONFLICT(application_id) DO UPDATE SET origin='dynamic',approved_by=NULL")
        .bind(application_id).execute(pool).await?;
    Ok(())
}
pub async fn trust_application(
    pool: &PgPool,
    application_id: &str,
    actor: &Principal,
) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    let app: Application =
        sqlx::query_as("SELECT * FROM applications WHERE id=$1 AND NOT is_deleted FOR UPDATE")
            .bind(application_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(privilege_denied)?;
    approver(&mut tx, &app, actor).await?;
    if dynamic(&app) {
        return Err(privilege_denied());
    }
    let result=sqlx::query("INSERT INTO application_credential_origins(application_id,origin,application_owner,organization,approved_by) VALUES($1,'static',$2,$3,$4) ON CONFLICT(application_id) DO UPDATE SET origin='static',application_owner=EXCLUDED.application_owner,organization=EXCLUDED.organization,approved_by=EXCLUDED.approved_by WHERE application_credential_origins.origin IN ('unverified','static')")
        .bind(&app.id).bind(&app.owner).bind(&app.organization).bind(&actor.id).execute(&mut *tx).await?;
    if result.rows_affected() != 1 {
        return Err(privilege_denied());
    }
    tx.commit().await?;
    Ok(())
}
