use base64::Engine;
use salvo::oapi::{ToSchema, endpoint};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Digest;
use sqlx::{PgConnection, PgPool};

pub use super::social_link::{
    unlink_compat as unlink_provider_compat, unlink_link as unlink_provider,
};
pub use super::social_session::consume_social_session;
use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::{Application, Provider, User};
use crate::services::check_service::CheckService;
use crate::services::providers::oauth_provider::{
    OAuthExchangeContext, OAuthProviderTrait, builtin, configuration_stamp,
    create_oauth_provider_resolved, validate_oauth_configuration,
};
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
pub(crate) async fn prepare_oauth(
    pool: &PgPool,
    provider: &Provider,
    user_agent: &str,
    wechat_transport: Option<&crate::services::wechat_flow::WeChatTestTransport>,
) -> AppResult<(Box<dyn OAuthProviderTrait>, Value)> {
    validate_oauth_configuration(provider)?;
    let network = network_binding(&mut *pool.acquire().await?, provider, false).await?;
    let endpoints = if builtin(&provider.provider_type) {
        None
    } else {
        Some(
            crate::services::providers::generic_oauth::resolve_endpoints(
                provider,
                network != "unapproved",
            )
            .await?,
        )
    };
    let verifier = endpoints.as_ref().filter(|e| e.pkce_s256).map(|_| {
        format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        )
    });
    let nonce = endpoints.as_ref().filter(|e| e.issuer.is_some()).map(|_| {
        format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        )
    });
    let context = json!({"provider_stamp":configuration_stamp(provider),"network_binding":network,"oauth_endpoints":endpoints,"oauth_code_verifier":verifier,"oauth_nonce":nonce,"oauth_started_at":chrono::Utc::now().timestamp(),"wechat_flow":crate::services::wechat_flow::prepare(provider,user_agent)?});
    let oauth = checked_oauth_provider(pool, provider, &context, wechat_transport).await?;
    Ok((oauth, context))
}
pub(crate) fn authorization_url(
    oauth: &dyn OAuthProviderTrait,
    context: &Value,
    redirect: &str,
    state: &str,
) -> AppResult<String> {
    let original = oauth.get_auth_url(redirect, state, None);
    let verifier = context["oauth_code_verifier"].as_str();
    let nonce = context["oauth_nonce"].as_str();
    if verifier.is_none() && nonce.is_none() {
        return Ok(original);
    }
    let mut url = reqwest::Url::parse(&original)
        .map_err(|_| AppError::Authentication("Invalid OAuth authorization endpoint".into()))?;
    let pairs: Vec<_> = url
        .query_pairs()
        .filter(|(k, _)| {
            !matches!(
                k.as_ref(),
                "code_challenge" | "code_challenge_method" | "nonce"
            )
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.query_pairs_mut().clear().extend_pairs(pairs);
    if let Some(verifier) = verifier {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(verifier.as_bytes()));
        url.query_pairs_mut()
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
    }
    if let Some(nonce) = nonce {
        url.query_pairs_mut().append_pair("nonce", nonce);
    }
    Ok(url.into())
}
pub(crate) fn require_provider_stamp(context: &Value, provider: &Provider) -> AppResult<()> {
    if context["provider_stamp"].as_str() != Some(configuration_stamp(provider).as_str()) {
        return Err(AppError::Authentication(
            "OAuth provider configuration changed; restart sign-in".into(),
        ));
    }
    Ok(())
}
pub(crate) async fn network_binding(
    conn: &mut PgConnection,
    provider: &Provider,
    lock: bool,
) -> AppResult<String> {
    let sql = if lock {
        "SELECT configuration_stamp,generation FROM oauth_provider_network_approvals WHERE provider_id=$1 FOR SHARE"
    } else {
        "SELECT configuration_stamp,generation FROM oauth_provider_network_approvals WHERE provider_id=$1"
    };
    let approval: Option<(String, String)> = sqlx::query_as(sql)
        .bind(&provider.id)
        .fetch_optional(conn)
        .await?;
    Ok(match approval {
        Some((stamp, time)) if stamp == configuration_stamp(provider) => {
            social_state_service::proof_hash(&format!("oauth.network.approval.v1:{stamp}:{time}"))
        }
        _ => "unapproved".into(),
    })
}
async fn checked_oauth_provider(
    pool: &PgPool,
    provider: &Provider,
    context: &Value,
    wechat_transport: Option<&crate::services::wechat_flow::WeChatTestTransport>,
) -> AppResult<Box<dyn OAuthProviderTrait>> {
    let mut conn = pool.acquire().await?;
    let current: Provider = sqlx::query_as("SELECT * FROM providers WHERE id=$1")
        .bind(&provider.id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| AppError::Authentication("OAuth provider unavailable".into()))?;
    require_provider_stamp(context, &current)?;
    let network = network_binding(&mut conn, &current, false).await?;
    if context["network_binding"].as_str() != Some(network.as_str()) {
        return Err(AppError::Authentication(
            "OAuth network approval changed; restart sign-in".into(),
        ));
    }
    if let Some(oauth) =
        crate::services::wechat_flow::provider(&current, &context["wechat_flow"], wechat_transport)?
    {
        return Ok(oauth);
    }
    let endpoints = context
        .get("oauth_endpoints")
        .filter(|v| !v.is_null())
        .map(|v| {
            serde_json::from_value::<
                crate::services::providers::generic_oauth::ResolvedOAuthEndpoints,
            >(v.clone())
            .map_err(|_| AppError::Authentication("Invalid OAuth endpoint proof".into()))
        })
        .transpose()?;
    create_oauth_provider_resolved(&current, network != "unapproved", endpoints.as_ref())
}
pub(crate) async fn lock_provider_stamp(
    conn: &mut PgConnection,
    context: &Value,
    provider: &Provider,
) -> AppResult<()> {
    let current: Provider = sqlx::query_as("SELECT * FROM providers WHERE id=$1 FOR SHARE")
        .bind(&provider.id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| AppError::Authentication("OAuth provider unavailable".into()))?;
    require_provider_stamp(context, &current)?;
    let network = network_binding(conn, &current, true).await?;
    if context["network_binding"].as_str() != Some(network.as_str()) {
        return Err(AppError::Authentication(
            "OAuth network approval changed; restart sign-in".into(),
        ));
    }
    Ok(())
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
        .filter(|p| allowed_provider(&app, p).is_some() && validate_oauth_configuration(p).is_ok())
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
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let transport = depot
        .obtain::<std::sync::Arc<crate::services::wechat_flow::WeChatTestTransport>>()
        .ok()
        .cloned();
    let (oauth, context) =
        prepare_oauth(&pool, &provider, user_agent, transport.as_deref()).await?;
    let (state, browser) = social_state_service::create_flow(
        &pool,
        &NewOAuthFlow {
            provider_id: provider.id.clone(),
            provider_name: name,
            application_id: app.id,
            organization: app.organization,
            redirect_uri: redirect_uri.clone(),
            purpose: "signin".into(),
            context: context.clone(),
        },
    )
    .await?;
    let url = authorization_url(oauth.as_ref(), &context, &redirect_uri, &state)?;
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
    require_provider_stamp(&flow.context, &provider)?;
    let transport = depot
        .obtain::<std::sync::Arc<crate::services::wechat_flow::WeChatTestTransport>>()
        .ok()
        .cloned();
    let oauth =
        checked_oauth_provider(&pool, &provider, &flow.context, transport.as_deref()).await?;
    let exchange = OAuthExchangeContext {
        state: state.clone(),
        code_verifier: flow.context["oauth_code_verifier"]
            .as_str()
            .map(str::to_owned),
        nonce: flow.context["oauth_nonce"].as_str().map(str::to_owned),
        started_at: flow.context["oauth_started_at"].as_i64(),
    };
    let token = oauth
        .exchange_code_token(&code, &flow.redirect_uri, &exchange)
        .await?;
    // Re-read the persisted grant and configuration between the two requests;
    // revocation must not permit a second request using cached private access.
    let identity = checked_oauth_provider(&pool, &provider, &flow.context, transport.as_deref())
        .await?
        .verify_identity(&token, &exchange)
        .await?;
    let info = checked_oauth_provider(&pool, &provider, &flow.context, transport.as_deref())
        .await?
        .get_user_info_verified(&token, &exchange, identity)
        .await?;
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
    lock_provider_stamp(&mut transaction, &flow.context, &provider).await?;
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
            let mut name = format!("social_{}", uuid::Uuid::new_v4().simple());
            if CheckService::check_username(&info.username).is_ok() {
                let occupied: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE owner=$1 AND name=$2)",
                )
                .bind(&app.organization)
                .bind(&info.username)
                .fetch_one(&mut *transaction)
                .await?;
                if !occupied {
                    name = info.username.clone();
                }
            }
            let links = json!({link_key.clone(): info.id});
            let country = info
                .phone
                .as_deref()
                .and_then(|p| phonenumber::parse(None, p).ok())
                .filter(|n| n.is_valid())
                .and_then(|n| n.country().id())
                .map(|id| id.as_ref().to_owned());
            let profile = json!({"oauth_profile":{"provider_id":provider.id,"id":info.id,"username":info.username,"displayName":info.display_name,"email":info.email,"emailVerified":info.email_verified,"phone":info.phone,"phoneVerified":info.phone_verified,"avatarUrl":info.avatar_url}});
            let mut created = None;
            for _ in 0..2 {
                created=sqlx::query_as::<_, User>("INSERT INTO users (id, owner, name, password_hash, display_name, email, email_verified, avatar, provider_ids, signup_application,phone,country_code,properties) VALUES ($1, $2, $3, '', $4, $5, $9, $6, $7, $8,$10,$11,$12) ON CONFLICT(owner,name) DO NOTHING RETURNING *")
                    .bind(&id).bind(&app.organization).bind(&name).bind(if info.display_name.is_empty() { &name } else { &info.display_name })
                    .bind(&info.email).bind(&info.avatar_url).bind(&links).bind(format!("{}/{}", app.owner, app.name))
                    .bind(info.email_verified).bind(&info.phone).bind(&country).bind(&profile)
                    .fetch_optional(&mut *transaction).await?;
                if created.is_some() {
                    break;
                }
                name = format!("social_{}", uuid::Uuid::new_v4().simple());
            }
            created.ok_or_else(|| {
                AppError::Conflict("Social account name unavailable; restart sign-in".into())
            })?
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
            provider_id: provider.id.clone(),
            context: json!({"link_key":link_key,"subject":info.id,"provider_stamp":configuration_stamp(&provider),"network_binding":flow.context["network_binding"]}),
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
