use crate::config::AppConfig;
use crate::models::{Jwks, OidcDiscovery, UserinfoResponse, WebfingerLink, WebfingerResponse};
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;

/// OpenID Connect Discovery endpoint
#[endpoint(tags("oidc"), summary = "OpenID Connect Discovery")]
pub async fn openid_configuration() -> Json<OidcDiscovery> {
    let config = AppConfig::get();
    let issuer = format!("http://{}:{}", config.server.host, config.server.port);
    Json(OidcDiscovery::new(&issuer))
}

/// Application-specific OpenID Connect Discovery endpoint
#[endpoint(tags("oidc"), summary = "Application-specific OpenID Connect Discovery")]
pub async fn app_openid_configuration(
    _application: salvo::oapi::extract::PathParam<String>,
) -> Json<OidcDiscovery> {
    let config = AppConfig::get();
    let issuer = format!("http://{}:{}", config.server.host, config.server.port);
    Json(OidcDiscovery::new(&issuer))
}

/// JSON Web Key Set endpoint
#[endpoint(tags("oidc"), summary = "JSON Web Key Set")]
pub async fn jwks() -> Json<Jwks> {
    // Return empty JWKS for now - in production, this should return the actual keys
    Json(Jwks { keys: vec![] })
}

/// Application-specific JSON Web Key Set endpoint
#[endpoint(tags("oidc"), summary = "Application-specific JSON Web Key Set")]
pub async fn app_jwks(
    _application: salvo::oapi::extract::PathParam<String>,
) -> Json<Jwks> {
    Json(Jwks { keys: vec![] })
}

/// WebFinger endpoint for discovery
#[endpoint(tags("oidc"), summary = "WebFinger")]
pub async fn webfinger(
    resource: QueryParam<String, true>,
) -> Json<WebfingerResponse> {
    let config = AppConfig::get();
    let issuer = format!("http://{}:{}", config.server.host, config.server.port);

    Json(WebfingerResponse {
        subject: resource.into_inner(),
        links: vec![WebfingerLink {
            rel: "http://openid.net/specs/connect/1.0/issuer".to_string(),
            href: issuer,
        }],
    })
}

/// Userinfo endpoint
#[endpoint(tags("oidc"), summary = "Get user information")]
pub async fn userinfo(depot: &mut Depot) -> Result<Json<UserinfoResponse>, StatusCode> {
    // Get user from JWT claims (set by auth middleware)
    let user_id = depot
        .get::<String>("user_id")
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // In a real implementation, fetch user details from database
    Ok(Json(UserinfoResponse {
        sub: user_id.clone(),
        name: None,
        preferred_username: Some(user_id.clone()),
        email: None,
        email_verified: None,
        phone_number: None,
        phone_number_verified: None,
        picture: None,
        groups: None,
    }))
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
) -> Result<(), StatusCode> {
    let config = AppConfig::get();
    let base_url = format!("http://{}:{}", config.server.host, config.server.port);

    // Build login URL with OAuth parameters
    let login_url = format!(
        "{}/login?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
        base_url,
        client_id.as_str(),
        urlencoding::encode(redirect_uri.as_str()),
        response_type.as_str(),
        scope.as_deref().unwrap_or("openid profile"),
        state.as_deref().unwrap_or("")
    );

    res.render(salvo::writing::Redirect::found(login_url));
    Ok(())
}
