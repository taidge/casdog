use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::config::AppConfig;
use crate::models::{
    Certificate, Jwks, OauthProtectedResourceMetadata, OidcDiscovery, UserinfoResponse,
    WebfingerLink, WebfingerResponse,
};
use crate::services::CertService;

fn issuer_for(application: Option<&str>) -> String {
    let config = AppConfig::get();
    let issuer = format!("http://{}:{}", config.server.host, config.server.port);
    if let Some(application) = application {
        format!("{issuer}/.well-known/{application}")
    } else {
        issuer
    }
}

/// OpenID Connect Discovery endpoint
#[endpoint(tags("oidc"), summary = "OpenID Connect Discovery")]
pub async fn openid_configuration() -> Json<OidcDiscovery> {
    let issuer = issuer_for(None);
    Json(OidcDiscovery::new(&issuer))
}

/// Application-specific OpenID Connect Discovery endpoint
#[endpoint(
    tags("oidc"),
    summary = "Application-specific OpenID Connect Discovery"
)]
pub async fn app_openid_configuration(
    application: salvo::oapi::extract::PathParam<String>,
) -> Json<OidcDiscovery> {
    let application = application.into_inner();
    let issuer = issuer_for(Some(&application));
    Json(OidcDiscovery::new(&issuer))
}

/// JSON Web Key Set endpoint
#[endpoint(tags("oidc"), summary = "JSON Web Key Set")]
pub async fn jwks(depot: &mut Depot) -> Json<Jwks> {
    let pool = match depot.obtain::<Pool<Postgres>>() {
        Ok(pool) => pool.clone(),
        Err(_) => return Json(Jwks { keys: vec![] }),
    };

    let certs = sqlx::query_as::<_, Certificate>("SELECT * FROM certificates WHERE scope = 'JWT'")
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

    let keys = certs
        .iter()
        .filter_map(|cert| CertService::get_jwk_from_cert(cert).ok())
        .collect();

    Json(Jwks { keys })
}

/// Application-specific JSON Web Key Set endpoint
#[endpoint(tags("oidc"), summary = "Application-specific JSON Web Key Set")]
pub async fn app_jwks(
    depot: &mut Depot,
    application: salvo::oapi::extract::PathParam<String>,
) -> Json<Jwks> {
    let pool = match depot.obtain::<Pool<Postgres>>() {
        Ok(pool) => pool.clone(),
        Err(_) => return Json(Jwks { keys: vec![] }),
    };

    let app_name = application.into_inner();

    // Try to find the application's cert
    let cert_name: Option<(Option<String>,)> =
        sqlx::query_as("SELECT cert FROM applications WHERE name = $1 AND is_deleted = FALSE")
            .bind(&app_name)
            .fetch_optional(&pool)
            .await
            .unwrap_or(None);

    let keys = if let Some((Some(cert_name),)) = cert_name {
        // Get the specific cert for this application
        let certs = sqlx::query_as::<_, Certificate>("SELECT * FROM certificates WHERE name = $1")
            .bind(&cert_name)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();

        certs
            .iter()
            .filter_map(|cert| CertService::get_jwk_from_cert(cert).ok())
            .collect()
    } else {
        // Fallback to all JWT certs
        let certs =
            sqlx::query_as::<_, Certificate>("SELECT * FROM certificates WHERE scope = 'JWT'")
                .fetch_all(&pool)
                .await
                .unwrap_or_default();

        certs
            .iter()
            .filter_map(|cert| CertService::get_jwk_from_cert(cert).ok())
            .collect()
    };

    Json(Jwks { keys })
}

/// WebFinger endpoint for discovery
#[endpoint(tags("oidc"), summary = "WebFinger")]
pub async fn webfinger(resource: QueryParam<String, true>) -> Json<WebfingerResponse> {
    let issuer = issuer_for(None);

    Json(WebfingerResponse {
        subject: resource.into_inner(),
        links: vec![WebfingerLink {
            rel: "http://openid.net/specs/connect/1.0/issuer".to_string(),
            href: issuer,
        }],
    })
}

/// Application-specific WebFinger endpoint for discovery.
#[endpoint(tags("oidc"), summary = "Application-specific WebFinger")]
pub async fn app_webfinger(
    application: salvo::oapi::extract::PathParam<String>,
    resource: QueryParam<String, true>,
) -> Json<WebfingerResponse> {
    let application = application.into_inner();
    let issuer = issuer_for(Some(&application));

    Json(WebfingerResponse {
        subject: resource.into_inner(),
        links: vec![WebfingerLink {
            rel: "http://openid.net/specs/connect/1.0/issuer".to_string(),
            href: issuer,
        }],
    })
}

/// OAuth 2.0 Authorization Server Metadata (RFC 8414).
#[endpoint(tags("oauth"), summary = "OAuth authorization server metadata")]
pub async fn oauth_server_metadata() -> Json<OidcDiscovery> {
    let issuer = issuer_for(None);
    Json(OidcDiscovery::new(&issuer))
}

/// Application-specific OAuth 2.0 Authorization Server Metadata (RFC 8414).
#[endpoint(
    tags("oauth"),
    summary = "Application-specific OAuth authorization server metadata"
)]
pub async fn app_oauth_server_metadata(
    application: salvo::oapi::extract::PathParam<String>,
) -> Json<OidcDiscovery> {
    let application = application.into_inner();
    let issuer = issuer_for(Some(&application));
    Json(OidcDiscovery::new(&issuer))
}

/// OAuth 2.0 Protected Resource Metadata (RFC 9728).
#[endpoint(tags("oauth"), summary = "OAuth protected resource metadata")]
pub async fn oauth_protected_resource_metadata() -> Json<OauthProtectedResourceMetadata> {
    let issuer = issuer_for(None);
    Json(OauthProtectedResourceMetadata {
        resource: issuer.clone(),
        authorization_servers: vec![issuer],
        bearer_methods_supported: vec!["header".to_string()],
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "read".to_string(),
            "write".to_string(),
        ],
        resource_signing_alg_values_supported: vec!["RS256".to_string()],
        resource_documentation: None,
    })
}

/// Application-specific OAuth 2.0 Protected Resource Metadata (RFC 9728).
#[endpoint(
    tags("oauth"),
    summary = "Application-specific OAuth protected resource metadata"
)]
pub async fn app_oauth_protected_resource_metadata(
    application: salvo::oapi::extract::PathParam<String>,
) -> Json<OauthProtectedResourceMetadata> {
    let application = application.into_inner();
    let resource = issuer_for(Some(&application));
    Json(OauthProtectedResourceMetadata {
        resource: resource.clone(),
        authorization_servers: vec![resource],
        bearer_methods_supported: vec!["header".to_string()],
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "read".to_string(),
            "write".to_string(),
        ],
        resource_signing_alg_values_supported: vec!["RS256".to_string()],
        resource_documentation: None,
    })
}

/// Userinfo endpoint - fetches full user info from the database
#[endpoint(tags("oidc"), summary = "Get user information")]
pub async fn userinfo(depot: &mut Depot) -> Result<Json<UserinfoResponse>, StatusCode> {
    let user_id = depot
        .get::<String>("user_id")
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .clone();

    // Fetch full user info from database
    let user: Option<(String, String, Option<String>, Option<String>, Option<String>, bool)> =
        sqlx::query_as(
            "SELECT id, name, email, phone, avatar, is_admin FROM users WHERE id = $1 AND is_deleted = FALSE"
        )
        .bind(user_id)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None);

    match user {
        Some((id, name, email, phone, avatar, _is_admin)) => {
            // Fetch user's groups
            let groups: Vec<(String,)> = sqlx::query_as(
                "SELECT g.name FROM groups g INNER JOIN user_groups ug ON g.id = ug.group_id WHERE ug.user_id = $1"
            )
            .bind(&id)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();

            let group_names: Vec<String> = groups.into_iter().map(|(n,)| n).collect();

            Ok(Json(UserinfoResponse {
                sub: id,
                name: Some(name.clone()),
                preferred_username: Some(name),
                email: email.clone(),
                email_verified: email.as_ref().map(|_| true),
                phone_number: phone.clone(),
                phone_number_verified: phone.as_ref().map(|_| false),
                picture: avatar,
                groups: if group_names.is_empty() {
                    None
                } else {
                    Some(group_names)
                },
            }))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// OAuth authorize endpoint (redirect to login page)
#[endpoint(tags("oauth"), summary = "OAuth authorize")]
pub async fn authorize(
    res: &mut Response,
    client_id: QueryParam<String, true>,
    redirect_uri: QueryParam<String, true>,
    response_type: QueryParam<String, true>,
    scope: QueryParam<String, false>,
    state: QueryParam<String, false>,
    code_challenge: QueryParam<String, false>,
    code_challenge_method: QueryParam<String, false>,
    nonce: QueryParam<String, false>,
) -> Result<(), StatusCode> {
    let config = AppConfig::get();
    let base_url = format!("http://{}:{}", config.server.host, config.server.port);

    // Build login URL with OAuth parameters
    let mut login_url = format!(
        "{}/login?client_id={}&redirect_uri={}&response_type={}&scope={}",
        base_url,
        client_id.as_str(),
        urlencoding::encode(redirect_uri.as_str()),
        response_type.as_str(),
        scope.as_deref().unwrap_or("openid profile"),
    );

    if let Some(state) = state.as_deref() {
        login_url.push_str(&format!("&state={}", urlencoding::encode(state)));
    }
    if let Some(cc) = code_challenge.as_deref() {
        login_url.push_str(&format!("&code_challenge={}", urlencoding::encode(cc)));
    }
    if let Some(ccm) = code_challenge_method.as_deref() {
        login_url.push_str(&format!(
            "&code_challenge_method={}",
            urlencoding::encode(ccm)
        ));
    }
    if let Some(n) = nonce.as_deref() {
        login_url.push_str(&format!("&nonce={}", urlencoding::encode(n)));
    }

    res.render(salvo::writing::Redirect::found(login_url));
    Ok(())
}
