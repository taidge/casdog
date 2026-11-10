use salvo::oapi::extract::*;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::AppError;
use crate::services::cas_service::CasService;

/// CAS service validate endpoint
#[endpoint(tags("CAS"), summary = "CAS service validate")]
pub async fn service_validate(
    depot: &mut Depot,
    req: &mut Request,
    ticket: QueryParam<String, true>,
    service: QueryParam<String, true>,
) -> Result<String, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    if !ticket.as_str().starts_with("ST-") {
        return Ok(cas_auth_failure(
            "INVALID_TICKET",
            &format!("Ticket {} not recognized", ticket.as_str()),
        ));
    }

    let mut result = CasService::validate_ticket(&pool, ticket.as_str(), service.as_str()).await?;
    attach_proxy_granting_ticket(&pool, req, &mut result, service.as_str()).await?;

    if result.valid {
        Ok(cas_success_response(&result, false))
    } else {
        Ok(cas_auth_failure(
            "INVALID_TICKET",
            "Ticket validation failed",
        ))
    }
}

/// CAS simple validate endpoint
#[endpoint(tags("CAS"), summary = "CAS validate")]
pub async fn validate(
    depot: &mut Depot,
    ticket: QueryParam<String, true>,
    service: QueryParam<String, true>,
) -> Result<String, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let result = CasService::validate_ticket(&pool, ticket.as_str(), service.as_str()).await;

    match result {
        Ok(r) if r.valid => Ok(format!("yes\n{}", r.user.unwrap_or_default())),
        _ => Ok("no\n".to_string()),
    }
}

/// CAS proxy validate endpoint.
#[endpoint(tags("CAS"), summary = "CAS proxy validate")]
pub async fn proxy_validate(
    depot: &mut Depot,
    req: &mut Request,
    ticket: QueryParam<String, true>,
    service: QueryParam<String, true>,
) -> Result<String, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let mut result = CasService::validate_ticket(&pool, ticket.as_str(), service.as_str()).await?;
    attach_proxy_granting_ticket(&pool, req, &mut result, service.as_str()).await?;

    if result.valid {
        Ok(cas_success_response(&result, true))
    } else {
        Ok(cas_auth_failure(
            "INVALID_TICKET",
            "Ticket validation failed",
        ))
    }
}

/// CAS proxy endpoint.
#[endpoint(tags("CAS"), summary = "CAS proxy")]
pub async fn proxy(depot: &mut Depot, req: &mut Request) -> Result<String, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pgt = req.query::<String>("pgt").unwrap_or_default();
    let target_service = req.query::<String>("targetService").unwrap_or_default();

    if pgt.is_empty() || target_service.is_empty() {
        return Ok(cas_proxy_failure(
            "INVALID_REQUEST",
            "pgt and targetService must exist",
        ));
    }

    match CasService::generate_proxy_ticket(&pool, &pgt, &target_service).await {
        Ok(proxy_ticket) => Ok(format!(
            r#"<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:proxySuccess>
    <cas:proxyTicket>{}</cas:proxyTicket>
  </cas:proxySuccess>
</cas:serviceResponse>"#,
            escape_xml(&proxy_ticket)
        )),
        Err(_) => Ok(cas_proxy_failure(
            "UNAUTHORIZED_SERVICE",
            "service not authorized",
        )),
    }
}

/// CAS SAML validate endpoint.
#[endpoint(tags("CAS"), summary = "CAS SAML validate")]
pub async fn saml_validate(depot: &mut Depot, req: &mut Request) -> Result<String, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let target = req
        .query::<String>("TARGET")
        .or_else(|| req.query::<String>("target"))
        .or_else(|| req.query::<String>("service"))
        .unwrap_or_default();
    let body = req
        .payload()
        .await
        .map_err(|e| AppError::Validation(format!("Failed to read SAML request: {}", e)))?;
    let body = String::from_utf8_lossy(body);
    let ticket = extract_saml_artifact(&body)
        .ok_or_else(|| AppError::Validation("SAML AssertionArtifact is required".to_string()))?;
    if target.is_empty() {
        return Err(AppError::Validation("TARGET is required".to_string()));
    }

    let result = CasService::validate_ticket(&pool, &ticket, &target).await?;
    let user = escape_xml(result.user.as_deref().unwrap_or_default());
    let now = chrono::Utc::now().to_rfc3339();
    let assertion = format!(
        r#"<saml1p:Response xmlns:saml1p="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:saml1="urn:oasis:names:tc:SAML:1.0:assertion" IssueInstant="{now}" MajorVersion="1" MinorVersion="1" Recipient="{target}">
  <saml1p:Status>
    <saml1p:StatusCode Value="saml1p:Success"/>
  </saml1p:Status>
  <saml1:Assertion AssertionID="{}" IssueInstant="{now}" Issuer="casdog" MajorVersion="1" MinorVersion="1">
    <saml1:AuthenticationStatement AuthenticationInstant="{now}" AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password">
      <saml1:Subject>
        <saml1:NameIdentifier>{user}</saml1:NameIdentifier>
      </saml1:Subject>
    </saml1:AuthenticationStatement>
  </saml1:Assertion>
</saml1p:Response>"#,
        escape_xml(&format!("_{}", uuid::Uuid::new_v4())),
        target = escape_xml(&target)
    );

    Ok(format!(
        r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>{assertion}</SOAP-ENV:Body></SOAP-ENV:Envelope>"#
    ))
}

async fn attach_proxy_granting_ticket(
    pool: &Pool<Postgres>,
    req: &Request,
    result: &mut crate::services::cas_service::CasValidationResult,
    service: &str,
) -> Result<(), AppError> {
    let Some(pgt_url) = req
        .query::<String>("pgtUrl")
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let parsed = reqwest::Url::parse(&pgt_url)
        .map_err(|e| AppError::Validation(format!("Invalid pgtUrl: {}", e)))?;
    if parsed.scheme() != "https" {
        return Err(AppError::Validation(
            "CAS proxy callback must use https".to_string(),
        ));
    }

    let grant = CasService::generate_proxy_granting_ticket(pool, result, service).await?;
    let mut callback = parsed;
    callback
        .query_pairs_mut()
        .append_pair("pgtId", &grant.pgt_id)
        .append_pair("pgtIou", &grant.pgt_iou);

    let response = reqwest::Client::new()
        .get(callback)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("CAS proxy callback failed: {}", e)))?;
    if !response.status().is_success() && !response.status().is_redirection() {
        return Err(AppError::Validation(format!(
            "CAS proxy callback returned {}",
            response.status()
        )));
    }

    result
        .attributes
        .push(("proxyGrantingTicket".to_string(), grant.pgt_iou.to_string()));
    Ok(())
}

fn cas_success_response(
    result: &crate::services::cas_service::CasValidationResult,
    include_proxies: bool,
) -> String {
    let user = escape_xml(result.user.as_deref().unwrap_or_default());
    let attrs = result
        .attributes
        .iter()
        .filter(|(key, _)| key != "proxyGrantingTicket")
        .map(|(k, v)| format!("<cas:{k}>{}</cas:{k}>", escape_xml(v)))
        .collect::<Vec<_>>()
        .join("\n      ");
    let pgt = result
        .attributes
        .iter()
        .find(|(key, _)| key == "proxyGrantingTicket")
        .map(|(_, value)| {
            format!(
                "\n    <cas:proxyGrantingTicket>{}</cas:proxyGrantingTicket>",
                escape_xml(value)
            )
        })
        .unwrap_or_default();
    let proxies = if include_proxies {
        "\n    <cas:proxies />"
    } else {
        ""
    };

    format!(
        r#"<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>{user}</cas:user>
    <cas:attributes>
      {attrs}
    </cas:attributes>{pgt}{proxies}
  </cas:authenticationSuccess>
</cas:serviceResponse>"#
    )
}

fn cas_auth_failure(code: &str, msg: &str) -> String {
    format!(
        r#"<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationFailure code="{}">{}</cas:authenticationFailure>
</cas:serviceResponse>"#,
        escape_xml(code),
        escape_xml(msg)
    )
}

fn cas_proxy_failure(code: &str, msg: &str) -> String {
    format!(
        r#"<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:proxyFailure code="{}">{}</cas:proxyFailure>
</cas:serviceResponse>"#,
        escape_xml(code),
        escape_xml(msg)
    )
}

fn extract_saml_artifact(body: &str) -> Option<String> {
    let re = regex::Regex::new(
        r"(?s)<(?:\w+:)?AssertionArtifact[^>]*>(.*?)</(?:\w+:)?AssertionArtifact>",
    )
    .ok()?;
    re.captures(body)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().trim().to_string())
        .filter(|value| !value.is_empty())
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
