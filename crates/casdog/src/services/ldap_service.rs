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
