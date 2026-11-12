use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

pub struct LdapService;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LdapUser {
    pub dn: String,
    pub uid: String,
    pub cn: String,
    pub email: Option<String>,
    pub phone: Option<String>,
}

impl LdapService {
    /// Authenticate the configured directory identity of an existing local user.
    /// Never treat an empty-password anonymous bind as credential proof.
    pub async fn authenticate(
        provider: &crate::models::Provider,
        user: &crate::models::User,
        password: &str,
    ) -> AppResult<bool> {
        if password.is_empty()
            || user.ldap.as_deref().is_none_or(str::is_empty)
            || provider.owner != user.owner
            || provider.category != "LDAP"
        {
            return Ok(false);
        }
        let host = provider
            .host
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::Config("LDAP host is required".into()))?;
        let port =
            u16::try_from(
                provider
                    .port
                    .unwrap_or(if provider.disable_ssl { 389 } else { 636 }),
            )
            .map_err(|_| AppError::Config("Invalid LDAP port".into()))?;
        let url = Self::build_url(host, port);
        let settings = ldap3::LdapConnSettings::new()
            .set_conn_timeout(std::time::Duration::from_secs(5))
            .set_starttls(!provider.disable_ssl && url.starts_with("ldap://"));
        let metadata: serde_json::Value = provider
            .metadata
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| AppError::Config("Invalid LDAP metadata".into()))?
            .unwrap_or_default();
        let base = metadata["base_dn"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::Config("LDAP base_dn is required".into()))?;
        let base_filter = metadata["filter"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("(objectClass=person)")
            .replace("{}", "*");
        let fields: Vec<&str> = metadata["filter_fields"]
            .as_array()
            .map(|fields| {
                fields
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect()
            })
            .unwrap_or_else(|| vec!["uid"]);
        let mut assertions = Vec::new();
        for field in fields {
            let value = match field {
                "uid" | "sAMAccountName" => Some(user.name.as_str()),
                "userPrincipalName" | "mail" => user.email.as_deref(),
                "mobile" | "telephoneNumber" => user.phone.as_deref(),
                "entryUUID" | "objectGUID" => user.external_id.as_deref(),
                _ => {
                    return Err(AppError::Config(
                        "Unsupported LDAP identity filter field".into(),
                    ));
                }
            };
            if let Some(value) = value.filter(|s| !s.is_empty()) {
                assertions.push(format!("({field}={})", ldap3::ldap_escape(value)));
            }
        }
        if assertions.is_empty() {
            return Ok(false);
        }
        let filter = format!("(&{base_filter}(|{}))", assertions.join(""));
        let (connection, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|_| AppError::Internal("LDAP connection unavailable".into()))?;
        ldap3::drive!(connection);
        let timeout = std::time::Duration::from_secs(5);
        if let Some(bind_dn) = provider.client_id.as_deref().filter(|s| !s.is_empty()) {
            let secret = provider
                .client_secret
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    AppError::Config("LDAP directory bind password is required".into())
                })?;
            ldap.with_timeout(timeout)
                .simple_bind(bind_dn, secret)
                .await
                .map_err(|_| AppError::Internal("LDAP directory bind unavailable".into()))?
                .success()
                .map_err(|_| AppError::Config("LDAP directory bind rejected".into()))?;
        }
        let (entries, _) = ldap
            .with_timeout(timeout)
            .with_search_options(ldap3::SearchOptions::new().sizelimit(2).timelimit(5))
            .search(base, ldap3::Scope::Subtree, &filter, vec!["uid"])
            .await
            .map_err(|_| AppError::Internal("LDAP identity lookup unavailable".into()))?
            .success()
            .map_err(|_| AppError::Authentication("LDAP identity lookup rejected".into()))?;
        if entries.len() != 1 {
            let _ = ldap.unbind().await;
            return Ok(false);
        }
        let entry = ldap3::SearchEntry::construct(entries.into_iter().next().unwrap());
        if entry.dn.trim().is_empty() {
            let _ = ldap.unbind().await;
            return Ok(false);
        }
        let result = ldap
            .with_timeout(timeout)
            .simple_bind(&entry.dn, password)
            .await
            .map_err(|_| AppError::Internal("LDAP credential verification unavailable".into()))?;
        let accepted = result.rc == 0;
        let _ = ldap.unbind().await;
        Ok(accepted)
    }

    fn build_url(host: &str, port: u16) -> String {
        if host.starts_with("ldap://") || host.starts_with("ldaps://") {
            return host.to_string();
        }

        let scheme = if port == 636 { "ldaps" } else { "ldap" };
        format!("{}://{}:{}", scheme, host, port)
    }

    fn first_attr(entry: &ldap3::SearchEntry, names: &[&str]) -> Option<String> {
        names.iter().find_map(|name| {
            entry
                .attrs
                .get(*name)
                .and_then(|values| values.first())
                .map(ToOwned::to_owned)
        })
    }

    async fn connect(
        host: &str,
        port: u16,
        bind_dn: &str,
        bind_password: &str,
    ) -> AppResult<ldap3::Ldap> {
        let url = Self::build_url(host, port);
        let (conn, mut ldap) = ldap3::LdapConnAsync::new(&url)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to connect to LDAP: {}", e)))?;
        ldap3::drive!(conn);

        if !bind_dn.trim().is_empty() {
            ldap.simple_bind(bind_dn, bind_password)
                .await
                .map_err(|e| AppError::Internal(format!("LDAP bind request failed: {}", e)))?
                .success()
                .map_err(|e| AppError::Authentication(format!("LDAP bind failed: {}", e)))?;
        }

        Ok(ldap)
    }

    pub async fn sync_users(
        host: &str,
        port: u16,
        bind_dn: &str,
        bind_password: &str,
        base_dn: &str,
        filter: &str,
    ) -> AppResult<Vec<LdapUser>> {
        let mut ldap = Self::connect(host, port, bind_dn, bind_password).await?;
        let attrs = vec![
            "uid",
            "cn",
            "mail",
            "mobile",
            "telephoneNumber",
            "displayName",
            "userPrincipalName",
            "sAMAccountName",
        ];

        let (entries, _result) = ldap
            .search(base_dn, ldap3::Scope::Subtree, filter, attrs)
            .await
            .map_err(|e| AppError::Internal(format!("LDAP search failed: {}", e)))?
            .success()
            .map_err(|e| AppError::Internal(format!("LDAP search failed: {}", e)))?;

        let users = entries
            .into_iter()
            .filter_map(|entry| {
                let entry = ldap3::SearchEntry::construct(entry);
                let uid = Self::first_attr(&entry, &["uid", "sAMAccountName", "userPrincipalName"])
                    .or_else(|| Self::first_attr(&entry, &["cn", "displayName"]))?;
                let cn =
                    Self::first_attr(&entry, &["displayName", "cn"]).unwrap_or_else(|| uid.clone());
                let dn = entry.dn.clone();

                Some(LdapUser {
                    dn,
                    uid,
                    cn,
                    email: Self::first_attr(&entry, &["mail", "userPrincipalName"]),
                    phone: Self::first_attr(&entry, &["mobile", "telephoneNumber"]),
                })
            })
            .collect();

        ldap.unbind()
            .await
            .map_err(|e| AppError::Internal(format!("LDAP unbind failed: {}", e)))?;

        Ok(users)
    }

    /// Test LDAP connection
    pub async fn test_connection(
        host: &str,
        port: u16,
        bind_dn: &str,
        bind_password: &str,
    ) -> AppResult<bool> {
        let mut ldap = Self::connect(host, port, bind_dn, bind_password).await?;
        ldap.unbind()
            .await
            .map_err(|e| AppError::Internal(format!("LDAP unbind failed: {}", e)))?;
        Ok(true)
    }
}
