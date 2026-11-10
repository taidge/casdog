use salvo::oapi::{ToSchema, endpoint};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};

pub use super::social_link::{
    unlink_compat as unlink_provider_compat, unlink_link as unlink_provider,
};
pub use super::social_session::consume_social_session;
use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::{Application, Provider, User};
use crate::services::check_service::CheckService;
use crate::services::providers::oauth_provider::{OAuthProviderTrait, create_oauth_provider};
use crate::services::social_state_service::{
    self, COMPLETION_TTL_SECONDS, NewCompletion, NewOAuthFlow,
};

const BROWSER_COOKIE: &str = "casdog_oauth_browser";
const SESSION_COOKIE: &str = "casdog_oauth_completion";

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthUrlResponse {
    pub url: String,
}

pub(crate) fn public_origin() -> AppResult<String> {
    let config = AppConfig::get();
    let origin = config
        .server
        .public_url
        .unwrap_or_else(|| format!("http://{}:{}", config.server.host, config.server.port));
    let parsed = reqwest::Url::parse(&origin)
        .map_err(|_| AppError::Config("Invalid server.public_url".into()))?;
    let loopback = matches!(
        parsed.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    if (parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(AppError::Config(
            "server.public_url must be an HTTPS origin (HTTP loopback allowed for development)"
                .into(),
        ));
    }
    Ok(parsed.origin().ascii_serialization())
}
pub(crate) fn cookie(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name && !value.is_empty()).then(|| value.to_string())
        })
}
pub(crate) fn set_cookie(res: &mut Response, name: &str, value: &str, seconds: u32, secure: bool) {
    let header = format!(
        "{name}={value}; Path=/api/auth; HttpOnly; SameSite=Lax; Max-Age={seconds}{}",
        if secure { "; Secure" } else { "" }
    );
    res.headers_mut().append(
        "set-cookie",
        header
            .parse()
            .expect("fixed cookie names and URL-safe nonces"),
    );
    res.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    res.headers_mut()
        .insert("referrer-policy", "no-referrer".parse().unwrap());
}
pub(crate) fn pg_pool(depot: &Depot) -> AppResult<PgPool> {
    depot
        .obtain::<PgPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool not available".into()))
}
pub(crate) async fn application(pool: &PgPool, reference: &str) -> AppResult<Application> {
    let mut conn = pool.acquire().await?;
    application_conn(&mut conn, reference).await
}
pub(crate) async fn application_conn(
    conn: &mut PgConnection,
    reference: &str,
) -> AppResult<Application> {
    // Bare names are confined to the canonical application owner; callers may
    // supply owner/name or an opaque ID for another explicitly configured app.
    sqlx::query_as("SELECT * FROM applications WHERE is_deleted = false AND (id = $1 OR owner || '/' || name = $1 OR (owner = 'admin' AND name = $1))")
        .bind(reference).fetch_optional(&mut *conn).await?
        .ok_or_else(|| AppError::NotFound("Application not found".into()))
}
fn allowed_provider(app: &Application, provider: &Provider) -> Option<bool> {
    app.providers.as_ref()?.as_array()?.iter().find_map(|item| {
        let name = item.get("name")?.as_str()?;
        let matches = name == format!("{}/{}", provider.owner, provider.name)
            || (name == provider.name && provider.owner == app.owner);
        if !matches
            || !item
                .get("canSignIn")
                .and_then(Value::as_bool)
                .unwrap_or(true)
        {
            return None;
        }
        Some(
            item.get("canSignUp")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        )
    })
}
pub(crate) fn oauth_provider(provider: &Provider) -> AppResult<Box<dyn OAuthProviderTrait>> {
    if provider.category != "OAuth" {
        return Err(AppError::Validation("OAuth provider required".into()));
    }
    create_oauth_provider(
        &provider.provider_type,
        provider.client_id.as_deref().unwrap_or_default(),
        provider.client_secret.as_deref().unwrap_or_default(),
        provider.custom_auth_url.as_deref(),
        provider.custom_token_url.as_deref(),
        provider.custom_user_info_url.as_deref(),
        provider.scopes.as_deref(),
    )
    .ok_or_else(|| AppError::Validation("Unsupported OAuth provider".into()))
}
pub(crate) async fn provider_for_application(
    pool: &PgPool,
    app: &Application,
    name: &str,
) -> AppResult<Provider> {
    let mut conn = pool.acquire().await?;
    provider_for_application_conn(&mut conn, app, name).await
}
pub(crate) async fn provider_for_application_conn(
    conn: &mut PgConnection,
    app: &Application,
    name: &str,
) -> AppResult<Provider> {
    // The route's provider name is resolved only among configured application entries.
    let candidates: Vec<Provider> =
        sqlx::query_as("SELECT * FROM providers WHERE name = $1 AND category = 'OAuth'")
            .bind(name)
            .fetch_all(&mut *conn)
            .await?;
    let mut allowed = candidates
        .into_iter()
        .filter(|provider| allowed_provider(app, provider).is_some());
    let provider = allowed.next().ok_or_else(|| {
        AppError::Authorization("Provider is not enabled for this application".into())
    })?;
    if allowed.next().is_some() {
        return Err(AppError::Validation(
            "Ambiguous provider configuration".into(),
        ));
    }
    Ok(provider)
}

/// Public, application-scoped list. Never serializes provider credentials.
#[endpoint(tags("Social Login"))]
pub async fn list_social_providers(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let pool = pg_pool(depot)?;
    let reference = req
        .query::<String>("application")
        .ok_or_else(|| AppError::Validation("application is required".into()))?;
    let app = application(&pool, &reference).await?;
    let providers: Vec<Provider> =
        sqlx::query_as("SELECT * FROM providers WHERE category = 'OAuth' ORDER BY name")
            .fetch_all(&pool)
            .await?;
    let data: Vec<Value> = providers
        .iter()
        .filter(|p| allowed_provider(&app, p).is_some() && oauth_provider(p).is_ok())
        .map(|p| json!({"name": p.name, "display_name": p.display_name, "type": p.provider_type}))
        .collect();
    Ok(Json(
        json!({"status": "ok", "data": data, "organization": app.organization}),
    ))
}

/// Generate authorization state on the server and bind it to this browser.
#[endpoint(tags("Social Login"))]
pub async fn get_provider_auth_url(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<Json<AuthUrlResponse>> {
    let pool = pg_pool(depot)?;
    let name = req
        .param::<String>("provider")
        .ok_or_else(|| AppError::Validation("Provider required".into()))?;
    let reference = req
        .query::<String>("application")
        .ok_or_else(|| AppError::Validation("application is required".into()))?;
    let app = application(&pool, &reference).await?;
    let provider = provider_for_application(&pool, &app, &name).await?;
    let origin = public_origin()?;
    let redirect_uri = format!("{origin}/api/auth/{}/callback", urlencoding::encode(&name));
    // A client-supplied redirect can never alter the code exchange destination.
    if req
        .query::<String>("redirect_uri")
        .is_some_and(|value| value != redirect_uri)
    {
        return Err(AppError::Validation("OAuth callback URI mismatch".into()));
    }
    let (state, browser) = social_state_service::create_flow(
        &pool,
        &NewOAuthFlow {
            provider_id: provider.id.clone(),
            provider_name: name,
            application_id: app.id,
            organization: app.organization,
            redirect_uri: redirect_uri.clone(),
            purpose: "signin".into(),
            context: json!({}),
        },
    )
    .await?;
    let url = oauth_provider(&provider)?.get_auth_url(&redirect_uri, &state, None);
    set_cookie(
        res,
        BROWSER_COOKIE,
        &browser,
        300,
        origin.starts_with("https://"),
    );
    Ok(Json(AuthUrlResponse { url }))
}

/// Validated callback sends only a one-use completion cookie, never a JWT in a URL.
#[endpoint(tags("Social Login"))]
pub async fn provider_callback(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<()> {
    let name = req.param::<String>("provider").unwrap_or_default();
    let state = req.query::<String>("state").unwrap_or_default();
    let browser = cookie(req, BROWSER_COOKIE)
        .ok_or_else(|| AppError::Authentication("OAuth browser binding missing".into()))?;
    let pool = pg_pool(depot)?;
    let flow = social_state_service::consume_flow(&pool, &state, &browser, &name).await?;
    let code = req
        .query::<String>("code")
        .filter(|c| !c.is_empty())
        .ok_or_else(|| AppError::Authentication("Provider did not authorize login".into()))?;
    let app = application(&pool, &flow.application_id).await?;
    if app.organization != flow.organization {
        return Err(AppError::Authentication(
            "Application organization changed".into(),
        ));
    }
    let provider = provider_for_application(&pool, &app, &name).await?;
    if provider.id != flow.provider_id {
        return Err(AppError::Authentication(
            "Provider configuration changed".into(),
        ));
    }
    let oauth = oauth_provider(&provider)?;
    let token = oauth.exchange_code(&code, &flow.redirect_uri).await?;
    let info = oauth.get_user_info(&token).await?;
    if info.id.trim().is_empty() || info.id == "unknown" {
        return Err(AppError::Authentication(
            "Provider returned no stable subject".into(),
        ));
    }
    if flow.purpose == "link" {
        super::social_link::finalize_link(&pool, &flow, &provider, &info.id).await?;
        set_cookie(
            res,
            BROWSER_COOKIE,
            "",
            0,
            flow.redirect_uri.starts_with("https://"),
        );
        res.render(salvo::writing::Redirect::other("/?social=linked"));
        return Ok(());
    }
    if flow.purpose != "signin" {
        return Err(AppError::Authentication("Unexpected OAuth purpose".into()));
    }
    // Namespace the link by provider configuration, not provider type. Identical
    // subject strings from two OAuth client configurations are not the same identity.
    let link_key = format!("oauth:{}", provider.id);
    let mut transaction = pool.begin().await?;
    super::social_link::lock_identity(&mut transaction, &app.organization, &provider.id, &info.id)
        .await?;
    let existing = super::social_link::find_identity(
        &mut transaction,
        &app.organization,
        &provider.id,
        &info.id,
    )
    .await?;
    let user = match existing {
        Some(user) => user,
        None => {
            if !app.enable_idp_signup || allowed_provider(&app, &provider) != Some(true) {
                return Err(AppError::Authorization(
                    "Social sign-up is disabled; link an account before signing in".into(),
                ));
            }
            // Never merge accounts merely because a provider claims an email.
            let id = uuid::Uuid::new_v4().to_string();
            let name = format!("social_{}", uuid::Uuid::new_v4().simple());
            let links = json!({link_key.clone(): info.id});
            sqlx::query_as::<_, User>("INSERT INTO users (id, owner, name, password_hash, display_name, email, email_verified, avatar, provider_ids, signup_application) VALUES ($1, $2, $3, '', $4, $5, false, $6, $7, $8) RETURNING *")
                .bind(id).bind(&app.organization).bind(&name).bind(if info.display_name.is_empty() { &name } else { &info.display_name })
                .bind(&info.email).bind(&info.avatar_url).bind(links).bind(format!("{}/{}", app.owner, app.name))
                .fetch_one(&mut *transaction).await?
        }
    };
    if user.is_forbidden {
        return Err(AppError::Authentication("User account is disabled".into()));
    }
    transaction.commit().await?;
    ensure_social_account_policy(&pool, &user).await?;
    CheckService::check_login_permission(&pool, &user.id, &app.id).await?;
    let completion = social_state_service::create_completion(
        &pool,
        &NewCompletion {
            user_id: user.id,
            organization: app.organization,
            application_id: app.id,
            provider_name: name,
            provider_id: provider.id,
            context: json!({"link_key":link_key,"subject":info.id}),
        },
    )
    .await?;
    let secure = flow.redirect_uri.starts_with("https://");
    set_cookie(res, BROWSER_COOKIE, "", 0, secure);
    set_cookie(
        res,
        SESSION_COOKIE,
        &completion,
        COMPLETION_TTL_SECONDS,
        secure,
    );
    res.render(salvo::writing::Redirect::other("/?social=complete"));
    Ok(())
}

pub(crate) async fn ensure_social_account_policy(pool: &PgPool, user: &User) -> AppResult<()> {
    let mut conn = pool.acquire().await?;
    ensure_social_account_policy_conn(&mut conn, user).await
}
pub(crate) async fn ensure_social_account_policy_conn(
    conn: &mut PgConnection,
    user: &User,
) -> AppResult<()> {
    if user.is_deleted || user.is_forbidden {
        return Err(AppError::Authentication("User account is disabled".into()));
    }
    let enabled: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE name = $1 AND is_deleted = false AND disable_signin = false)")
        .bind(&user.owner).fetch_one(&mut *conn).await?;
    if !enabled {
        return Err(AppError::Authentication(
            "Organization sign-in is disabled".into(),
        ));
    }
    Ok(())
}
