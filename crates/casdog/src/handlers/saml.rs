use salvo::http::header::{CONTENT_TYPE, HeaderValue};
use salvo::oapi::ToSchema;
use salvo::oapi::extract::*;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::{Application, Certificate, User};
use crate::services::{AppService, ProviderService, SamlService, UserService};

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct SamlLoginResponse {
    #[serde(rename = "authURL")]
    pub auth_url: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "formHTML")]
    pub form_html: Option<String>,
}

fn request_origin(req: &Request) -> String {
    let config = AppConfig::get();
    let forwarded_proto = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok());
    let host = req
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok());

    match (forwarded_proto, host) {
        (Some(proto), Some(host)) => format!("{proto}://{host}"),
        _ => format!("http://{}:{}", config.server.host, config.server.port),
    }
}

async fn resolve_application(req: &Request, app_service: &AppService) -> AppResult<Application> {
    let reference = req
        .query::<String>("application")
        .or_else(|| req.query::<String>("id"))
        .ok_or_else(|| AppError::Validation("application is required".to_string()))?;
    let owner = req.query::<String>("owner");
    app_service
        .find_internal(&reference, owner.as_deref())
        .await
}

async fn resolve_certificate(
    pool: &Pool<Postgres>,
    application: &Application,
) -> AppResult<Option<Certificate>> {
    if let Some(cert_name) = application.cert.as_deref() {
        let cert = sqlx::query_as::<_, Certificate>(
            "SELECT * FROM certificates WHERE owner = $1 AND name = $2 LIMIT 1",
        )
        .bind(&application.owner)
        .bind(cert_name)
        .fetch_optional(pool)
        .await?;
        if cert.is_some() {
            return Ok(cert);
        }

        let cert = sqlx::query_as::<_, Certificate>(
            "SELECT * FROM certificates WHERE name = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(cert_name)
        .fetch_optional(pool)
        .await?;
        if cert.is_some() {
            return Ok(cert);
        }
    }

    sqlx::query_as::<_, Certificate>(
        "SELECT * FROM certificates WHERE scope = 'JWT' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

fn build_login_redirect(
    owner: &str,
    application: &str,
    relay_state: Option<&str>,
    saml_request: Option<&str>,
    origin: &str,
    username: Option<&str>,
    login_hint: Option<&str>,
) -> String {
    let mut url = format!(
        "{origin}/login/saml/authorize/{owner}/{application}",
        origin = origin,
        owner = urlencoding::encode(owner),
        application = urlencoding::encode(application)
    );

    let mut query = Vec::new();
    if let Some(relay_state) = relay_state {
        if !relay_state.is_empty() {
            query.push(format!("relayState={}", urlencoding::encode(relay_state)));
        }
    }
    if let Some(saml_request) = saml_request {
        if !saml_request.is_empty() {
            query.push(format!("samlRequest={}", urlencoding::encode(saml_request)));
        }
    }
    if let Some(username) = username {
        if !username.is_empty() {
            query.push(format!("username={}", urlencoding::encode(username)));
        }
    }
    if let Some(login_hint) = login_hint {
        if !login_hint.is_empty() {
            query.push(format!("login_hint={}", urlencoding::encode(login_hint)));
        }
    }

    if !query.is_empty() {
        url.push('?');
        url.push_str(&query.join("&"));
    }

    url
}

fn append_query_param(url: &str, key: &str, value: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}{key}={value}")
}

async fn load_current_user(depot: &Depot, pool: &Pool<Postgres>) -> AppResult<Option<User>> {
    let Ok(user_id) = depot.get::<String>("user_id").cloned() else {
        return Ok(None);
    };
    let user_service = UserService::new(pool.clone());
    user_service.get_by_id_internal(&user_id).await.map(Some)
}

/// SAML IdP metadata endpoint.
#[endpoint(tags("SAML"), summary = "Get SAML IdP metadata")]
pub async fn saml_metadata(req: &mut Request, depot: &mut Depot) -> Result<String, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let app_service = AppService::new(pool.clone());
    let application = resolve_application(req, &app_service).await?;
    let enable_post_binding = req.query::<bool>("enablePostBinding").unwrap_or(false);
    let cert = resolve_certificate(&pool, &application)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "No certificate configured for application '{}'",
                application.name
            ))
        })?;

    let origin = request_origin(req);
    let entity_id = origin.clone();
    let sso_url = format!(
        "{}/api/saml/redirect/{}/{}",
        origin, application.owner, application.name
    );
    let metadata = SamlService::generate_idp_metadata(
        &entity_id,
        &sso_url,
        None,
        &cert.certificate,
        enable_post_binding,
    )?;

    Ok(metadata)
}

/// Get the SAML login URL/form for an external IdP provider.
#[endpoint(tags("SAML"), summary = "Get SAML login")]
pub async fn get_saml_login(
    req: &mut Request,
    depot: &mut Depot,
) -> AppResult<Json<SamlLoginResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let provider_id = req
        .query::<String>("id")
        .ok_or_else(|| AppError::Validation("id is required".to_string()))?;
    let relay_state = req.query::<String>("relayState");
    let provider = ProviderService::get_by_id_internal(&pool, &provider_id).await?;
    if provider.category != "SAML" {
        return Err(AppError::Validation(format!(
            "provider '{}' is not a SAML provider",
            provider.name
        )));
    }

    let destination = SamlService::provider_sso_url(&provider).ok_or_else(|| {
        AppError::Validation(format!(
            "provider '{}' does not have a SAML SSO endpoint",
            provider.name
        ))
    })?;
    let origin = request_origin(req);
    let acs_url = format!("{origin}/api/acs");
    let request_issuer = provider
        .provider_url
        .clone()
        .unwrap_or_else(|| acs_url.clone());
    let login_request = SamlService::build_authn_request(
        &request_issuer,
        &acs_url,
        &destination,
        relay_state.as_deref(),
        provider.enable_sign_authn_request,
    )?;

    Ok(Json(SamlLoginResponse {
        auth_url: login_request.auth_url,
        method: login_request.method,
        form_html: login_request.form_html,
    }))
}

/// SAML redirect endpoint.
#[endpoint(tags("SAML"), summary = "Handle SAML redirect")]
pub async fn saml_redirect(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    owner: PathParam<String>,
    application: PathParam<String>,
) -> AppResult<()> {
    let owner = owner.into_inner();
    let application_name = application.into_inner();
    let origin = request_origin(req);
    let relay_state = req.query::<String>("RelayState");
    let saml_request = req.query::<String>("SAMLRequest");
    let username = req.query::<String>("username");
    let login_hint = req.query::<String>("login_hint");

    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let app_service = AppService::new(pool.clone());
    let application = app_service.get_by_name(&owner, &application_name).await?;

    let Some(user) = load_current_user(depot, &pool).await? else {
        let redirect = build_login_redirect(
            &owner,
            &application_name,
            relay_state.as_deref(),
            saml_request.as_deref(),
            &origin,
            username.as_deref(),
            login_hint.as_deref(),
        );
        res.render(salvo::writing::Redirect::found(redirect));
        return Ok(());
    };

    let saml_request = saml_request.ok_or_else(|| {
        AppError::Validation("SAMLRequest is required once the user is authenticated".to_string())
    })?;
    let issuer = origin.clone();
    let (response, destination, method) =
        SamlService::build_application_response(&application, &user, &saml_request, &issuer)?;

    if method == "POST" {
        let html = SamlService::build_auto_post_form(
            &destination,
            &[
                ("SAMLResponse", response.as_str()),
                ("RelayState", relay_state.as_deref().unwrap_or_default()),
            ],
        );
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        res.render(html);
        return Ok(());
    }

    let mut redirect = append_query_param(
        &destination,
        "SAMLResponse",
        &urlencoding::encode(&response),
    );
    if let Some(relay_state) = relay_state.as_deref() {
        if !relay_state.is_empty() {
            redirect =
                append_query_param(&redirect, "RelayState", &urlencoding::encode(relay_state));
        }
    }
    res.render(salvo::writing::Redirect::found(redirect));
    Ok(())
}

/// SAML Assertion Consumer Service.
#[endpoint(tags("SAML"), summary = "SAML ACS endpoint")]
pub async fn saml_acs(req: &mut Request, res: &mut Response) -> AppResult<()> {
    let relay_state = if let Some(value) = req.query::<String>("RelayState") {
        Some(value)
    } else if let Some(value) = req.query::<String>("relayState") {
        Some(value)
    } else if let Some(value) = req.form::<String>("RelayState").await {
        Some(value)
    } else {
        req.form::<String>("relayState").await
    };

    let saml_response = if let Some(value) = req.query::<String>("SAMLResponse") {
        Some(value)
    } else if let Some(value) = req.query::<String>("samlResponse") {
        Some(value)
    } else if let Some(value) = req.form::<String>("SAMLResponse").await {
        Some(value)
    } else {
        req.form::<String>("samlResponse").await
    }
    .ok_or_else(|| AppError::Validation("SAMLResponse is required".to_string()))?;

    let target = relay_state
        .as_deref()
        .and_then(SamlService::decode_relay_state_target)
        .unwrap_or_else(|| "/callback".to_string());

    let relay_state_encoded = relay_state.unwrap_or_default();
    let target = append_query_param(
        &target,
        "relayState",
        &urlencoding::encode(&relay_state_encoded),
    );
    let target = append_query_param(
        &target,
        "samlResponse",
        &urlencoding::encode(&saml_response),
    );

    res.render(salvo::writing::Redirect::found(target));
    Ok(())
}
