use sqlx::PgPool;

use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::{Application, Provider};
use crate::services::providers::{
    CustomHttpEmailProvider, EmailProviderTrait, SendGridEmailProvider, SmsProviderTrait,
    SmtpEmailProvider, TwilioSmsProvider, create_notification_provider,
};
use crate::services::{AppService, ProviderService};

#[derive(Clone)]
pub struct ProviderDispatchService {
    pool: PgPool,
    diesel_pool: Option<DieselPool>,
}

#[derive(Debug, Clone)]
pub struct DeliveryResult {
    pub provider: Provider,
    pub receivers: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedProvider {
    pub application: Option<Application>,
    pub provider: Provider,
}

#[derive(Debug, serde::Deserialize)]
struct ApplicationProviderItem {
    #[serde(default)]
    name: String,
    #[serde(default)]
    rule: String,
    #[serde(default, rename = "countryCodes")]
    country_codes: Vec<String>,
}

impl ProviderDispatchService {
    async fn http_private_access(&self, provider: &Provider) -> AppResult<bool> {
        if !crate::services::providers::http_delivery::is_custom_http(provider) {
            return Ok(false);
        }
        crate::services::providers::http_delivery::current_private_access(&self.pool, provider)
            .await
    }

    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            diesel_pool: None,
        }
    }

    pub fn with_diesel_pool(mut self, diesel_pool: DieselPool) -> Self {
        self.diesel_pool = Some(diesel_pool);
        self
    }

    fn app_service(&self) -> AppResult<AppService> {
        let diesel_pool = self.diesel_pool.clone().ok_or_else(|| {
            AppError::Internal("DieselPool not configured for ProviderDispatchService".to_string())
        })?;
        Ok(AppService::new(diesel_pool))
    }

    pub async fn resolve_provider(
        &self,
        category: &str,
        explicit_provider: Option<&str>,
        application_ref: Option<&str>,
        rule: Option<&str>,
        country_code: Option<&str>,
    ) -> AppResult<ResolvedProvider> {
        let application = if let Some(reference) = application_ref {
            Some(
                self.app_service()?
                    .find_internal(reference, Some("admin"))
                    .await?,
            )
        } else {
            None
        };

        if let Some(reference) = explicit_provider {
            let preferred_owner = application
                .as_ref()
                .map(|app| app.organization.as_str())
                .filter(|value| !value.is_empty());
            let provider = self
                .resolve_provider_reference(reference, preferred_owner)
                .await?;
            Self::ensure_category(category, &provider)?;
            return Ok(ResolvedProvider {
                application,
                provider,
            });
        }

        if let Some(application) = application.as_ref() {
            if let Some(provider) = self
                .resolve_from_application(application, category, rule, country_code)
                .await?
            {
                return Ok(ResolvedProvider {
                    application: Some(application.clone()),
                    provider,
                });
            }
        }

        let provider = self
            .find_default_provider(
                category,
                application.as_ref().map(|app| app.organization.as_str()),
            )
            .await?;
        Ok(ResolvedProvider {
            application,
            provider,
        })
    }

    pub async fn resolve_captcha_provider(
        &self,
        explicit_provider: Option<&str>,
        application_ref: Option<&str>,
    ) -> AppResult<Option<ResolvedProvider>> {
        let application = if let Some(reference) = application_ref {
            Some(
                self.app_service()?
                    .find_internal(reference, Some("admin"))
                    .await?,
            )
        } else {
            None
        };

        if let Some(reference) = explicit_provider {
            let preferred_owner = application
                .as_ref()
                .map(|app| app.organization.as_str())
                .filter(|value| !value.is_empty());
            let provider = self
                .resolve_provider_reference(reference, preferred_owner)
                .await?;
            Self::ensure_category("Captcha", &provider)?;
            if provider.provider_type.eq_ignore_ascii_case("default") {
                return Ok(None);
            }
            return Ok(Some(ResolvedProvider {
                application,
                provider,
            }));
        }

        let Some(application) = application else {
            return Ok(None);
        };

        let provider = self
            .resolve_from_application(&application, "Captcha", Some("captcha"), None)
            .await?;

        Ok(provider.and_then(|provider| {
            if provider.provider_type.eq_ignore_ascii_case("default") {
                None
            } else {
                Some(ResolvedProvider {
                    application: Some(application.clone()),
                    provider,
                })
            }
        }))
    }

    pub async fn send_email(
        &self,
        explicit_provider: Option<&str>,
        application_ref: Option<&str>,
        rule: Option<&str>,
        requested_receivers: &[String],
        subject: &str,
        content: &str,
        sender: Option<&str>,
    ) -> AppResult<DeliveryResult> {
        let resolved = self
            .resolve_provider("Email", explicit_provider, application_ref, rule, None)
            .await?;
        self.send_email_with_provider(
            &resolved.provider,
            requested_receivers,
            subject,
            content,
            sender,
        )
        .await
    }

    pub async fn send_email_with_provider(
        &self,
        provider_record: &Provider,
        requested_receivers: &[String],
        subject: &str,
        content: &str,
        sender: Option<&str>,
    ) -> AppResult<DeliveryResult> {
        Self::ensure_category("Email", provider_record)?;
        let provider_record = provider_record.clone();
        let receivers = receivers_with_provider_default(
            requested_receivers,
            provider_record.receiver.as_deref(),
        );
        if receivers.is_empty() {
            return Err(AppError::Validation(
                "At least one email receiver is required".to_string(),
            ));
        }

        if crate::services::providers::http_delivery::is_custom_http(&provider_record) {
            let allow_private = self.http_private_access(&provider_record).await?;
            CustomHttpEmailProvider::from_record(&provider_record, allow_private)?
                .with_pool(self.pool.clone())
                .send_many(&receivers, subject, content, sender)
                .await?;
            return Ok(DeliveryResult {
                provider: provider_record,
                receivers,
            });
        }
        let provider = email_provider_from_record(&provider_record, sender)?;
        for receiver in &receivers {
            provider.send_email(receiver, subject, content).await?;
        }

        Ok(DeliveryResult {
            provider: provider_record,
            receivers,
        })
    }

    pub async fn send_sms(
        &self,
        explicit_provider: Option<&str>,
        application_ref: Option<&str>,
        rule: Option<&str>,
        country_code: Option<&str>,
        requested_receivers: &[String],
        content: &str,
    ) -> AppResult<DeliveryResult> {
        let resolved = self
            .resolve_provider(
                "SMS",
                explicit_provider,
                application_ref,
                rule,
                country_code,
            )
            .await?;
        self.send_sms_with_provider(&resolved.provider, requested_receivers, content)
            .await
    }

    pub async fn send_sms_with_provider(
        &self,
        provider_record: &Provider,
        requested_receivers: &[String],
        content: &str,
    ) -> AppResult<DeliveryResult> {
        Self::ensure_category("SMS", provider_record)?;
        let provider_record = provider_record.clone();
        let receivers = receivers_with_provider_default(
            requested_receivers,
            provider_record.receiver.as_deref(),
        );
        if receivers.is_empty() {
            return Err(AppError::Validation(
                "At least one SMS receiver is required".to_string(),
            ));
        }

        let provider: Box<dyn SmsProviderTrait> =
            if crate::services::providers::http_delivery::is_custom_http(&provider_record) {
                let allow_private = self.http_private_access(&provider_record).await?;
                Box::new(
                    crate::services::providers::http_delivery::CustomHttpSmsProvider::from_record(
                        &provider_record,
                        allow_private,
                    )?
                    .with_pool(self.pool.clone()),
                )
            } else {
                sms_provider_from_record(&provider_record)?
            };
        for receiver in &receivers {
            provider.send_sms(receiver, content).await?;
        }

        Ok(DeliveryResult {
            provider: provider_record,
            receivers,
        })
    }

    pub async fn send_notification(
        &self,
        explicit_provider: Option<&str>,
        application_ref: Option<&str>,
        requested_receivers: &[String],
        title: &str,
        content: &str,
    ) -> AppResult<DeliveryResult> {
        let resolved = self
            .resolve_provider(
                "Notification",
                explicit_provider,
                application_ref,
                None,
                None,
            )
            .await?;
        let custom = crate::services::providers::http_delivery::is_custom_http(&resolved.provider);
        let default = if custom
            && crate::services::providers::http_delivery::notification_receiver_is_endpoint(
                &resolved.provider,
            ) {
            None
        } else {
            resolved.provider.receiver.as_deref()
        };
        let receivers = notification_receivers(requested_receivers, default);
        let allow_private = self.http_private_access(&resolved.provider).await?;
        let provider =
            notification_provider_from_record(&resolved.provider, allow_private, &self.pool)?;

        for receiver in &receivers {
            provider.send(title, content, receiver).await?;
        }

        Ok(DeliveryResult {
            provider: resolved.provider,
            receivers,
        })
    }

    async fn resolve_from_application(
        &self,
        application: &Application,
        category: &str,
        rule: Option<&str>,
        country_code: Option<&str>,
    ) -> AppResult<Option<Provider>> {
        let Some(items) = application
            .providers
            .as_ref()
            .and_then(serde_json::Value::as_array)
        else {
            return Ok(None);
        };

        for item in items {
            let Ok(item) = serde_json::from_value::<ApplicationProviderItem>(item.clone()) else {
                continue;
            };
            if item.name.trim().is_empty() {
                continue;
            }
            if !provider_item_matches(category, &item, rule, country_code) {
                continue;
            }

            let provider = self
                .resolve_provider_reference(&item.name, Some(application.organization.as_str()))
                .await?;
            if provider.category.eq_ignore_ascii_case(category) {
                return Ok(Some(provider));
            }
        }

        Ok(None)
    }

    async fn resolve_provider_reference(
        &self,
        reference: &str,
        preferred_owner: Option<&str>,
    ) -> AppResult<Provider> {
        if let Some((owner, name)) = reference.split_once('/') {
            return self.get_by_owner_and_name(owner, name).await;
        }

        if let Ok(provider) = ProviderService::get_by_id_internal(&self.pool, reference).await {
            return Ok(provider);
        }

        let providers = sqlx::query_as::<_, Provider>(
            r#"
            SELECT *
            FROM providers
            WHERE name = $1
            ORDER BY
                CASE
                    WHEN $2 <> '' AND owner = $2 THEN 0
                    WHEN owner = 'admin' THEN 1
                    ELSE 2
                END,
                created_at DESC
            "#,
        )
        .bind(reference)
        .bind(preferred_owner.unwrap_or_default())
        .fetch_all(&self.pool)
        .await?;

        providers
            .into_iter()
            .next()
            .ok_or_else(|| AppError::NotFound(format!("Provider '{}' not found", reference)))
    }

    async fn get_by_owner_and_name(&self, owner: &str, name: &str) -> AppResult<Provider> {
        sqlx::query_as::<_, Provider>(
            "SELECT * FROM providers WHERE owner = $1 AND name = $2 LIMIT 1",
        )
        .bind(owner)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Provider '{}/{}' not found", owner, name)))
    }

    async fn find_default_provider(
        &self,
        category: &str,
        preferred_owner: Option<&str>,
    ) -> AppResult<Provider> {
        sqlx::query_as::<_, Provider>(
            r#"
            SELECT *
            FROM providers
            WHERE lower(category) = lower($1)
            ORDER BY
                CASE
                    WHEN $2 <> '' AND owner = $2 THEN 0
                    WHEN owner = 'admin' THEN 1
                    ELSE 2
                END,
                CASE
                    WHEN lower(name) LIKE 'provider_%default%' THEN 0
                    ELSE 1
                END,
                created_at ASC
            LIMIT 1
            "#,
        )
        .bind(category)
        .bind(preferred_owner.unwrap_or_default())
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("No {} provider configured", category)))
    }

    fn ensure_category(category: &str, provider: &Provider) -> AppResult<()> {
        if provider.category.eq_ignore_ascii_case(category) {
            Ok(())
        } else {
            Err(AppError::Validation(format!(
                "Provider '{}' is not a {} provider",
                provider.name, category
            )))
        }
    }
}

fn provider_item_matches(
    category: &str,
    item: &ApplicationProviderItem,
    requested_rule: Option<&str>,
    country_code: Option<&str>,
) -> bool {
    if category.eq_ignore_ascii_case("Captcha") {
        return !item.rule.trim().is_empty() && !item.rule.eq_ignore_ascii_case("none");
    }

    if category.eq_ignore_ascii_case("SMS") && !country_code_matches(item, country_code) {
        return false;
    }

    match requested_rule
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        None => true,
        Some(requested_rule) => {
            item.rule.trim().is_empty()
                || item.rule.eq_ignore_ascii_case("all")
                || item.rule.eq_ignore_ascii_case("none")
                || item.rule.eq_ignore_ascii_case(requested_rule)
        }
    }
}

fn country_code_matches(item: &ApplicationProviderItem, country_code: Option<&str>) -> bool {
    if item.country_codes.is_empty() {
        return true;
    }

    let Some(country_code) = country_code
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };

    item.country_codes.iter().any(|candidate| {
        candidate.trim().is_empty()
            || candidate.eq_ignore_ascii_case("all")
            || candidate.eq_ignore_ascii_case(country_code)
    })
}

fn receivers_with_provider_default(
    requested: &[String],
    provider_default: Option<&str>,
) -> Vec<String> {
    let receivers = normalize_receivers(requested);
    if !receivers.is_empty() {
        return receivers;
    }

    split_receivers(provider_default)
}

fn notification_receivers(requested: &[String], provider_default: Option<&str>) -> Vec<String> {
    let receivers = receivers_with_provider_default(requested, provider_default);
    if receivers.is_empty() {
        vec![String::new()]
    } else {
        receivers
    }
}

fn normalize_receivers(receivers: &[String]) -> Vec<String> {
    receivers
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn split_receivers(receivers: Option<&str>) -> Vec<String> {
    receivers
        .unwrap_or_default()
        .split(|c| c == ',' || c == ';' || c == '\n')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Check a restored factor's actual delivery configuration without sending a
/// message. Keep restore validation in sync with the normal delivery factory.
pub fn validate_mfa_delivery_provider(provider: &Provider) -> AppResult<()> {
    if crate::services::providers::http_delivery::is_custom_http(provider) {
        return crate::services::providers::http_delivery::validate_record(provider);
    }
    let invalid = || {
        AppError::Validation("MFA delivery provider configuration is incomplete or invalid".into())
    };
    let nonempty = |value: Option<&str>| value.is_some_and(|v| !v.trim().is_empty());
    let http = |value: Option<&str>| -> AppResult<()> {
        let value = value.filter(|v| !v.trim().is_empty()).ok_or_else(invalid)?;
        let url = reqwest::Url::parse(value).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(invalid());
        }
        Ok(())
    };
    let kind = provider.provider_type.to_ascii_lowercase();
    match provider.category.as_str() {
        "Email" => {
            email_provider_from_record(provider, None)?;
            if kind.contains("custom http") {
                http(provider.endpoint.as_deref())?;
            } else {
                let from = provider
                    .client_id2
                    .as_deref()
                    .or(provider.receiver.as_deref())
                    .or(provider.client_id.as_deref())
                    .ok_or_else(invalid)?;
                from.parse::<lettre::message::Mailbox>()
                    .map_err(|_| invalid())?;
                let credential = if kind.contains("sendgrid") {
                    provider
                        .client_secret
                        .as_deref()
                        .or(provider.client_id.as_deref())
                } else {
                    provider.client_secret.as_deref()
                };
                if !nonempty(credential) {
                    return Err(invalid());
                }
                if !kind.contains("sendgrid")
                    && (!nonempty(provider.host.as_deref())
                        || !nonempty(provider.client_id.as_deref())
                        || !(1..=65535).contains(&provider.port.unwrap_or(587)))
                {
                    return Err(invalid());
                }
            }
        }
        "SMS" => {
            sms_provider_from_record(provider)?;
            if !nonempty(provider.client_secret.as_deref()) {
                return Err(invalid());
            }
            if kind.contains("twilio") {
                if !nonempty(provider.client_id.as_deref())
                    || !nonempty(
                        provider
                            .app_id
                            .as_deref()
                            .or(provider.sign_name.as_deref())
                            .or(provider.receiver.as_deref()),
                    )
                {
                    return Err(invalid());
                }
            } else {
                http(
                    provider
                        .endpoint
                        .as_deref()
                        .or(provider.provider_url.as_deref()),
                )?;
            }
        }
        _ => {
            return Err(AppError::Validation(
                "An Email or SMS delivery provider is required".into(),
            ));
        }
    }
    Ok(())
}

fn email_provider_from_record(
    provider: &Provider,
    sender: Option<&str>,
) -> AppResult<Box<dyn EmailProviderTrait>> {
    let provider_type = provider.provider_type.to_ascii_lowercase();
    if provider_type.contains("sendgrid") {
        let api_key = provider
            .client_secret
            .clone()
            .or_else(|| provider.client_id.clone())
            .ok_or_else(|| {
                AppError::Validation("SendGrid provider requires an API key".to_string())
            })?;
        let from_address =
            crate::services::provider_configuration_service::email_sender(provider, sender)?;
        Ok(Box::new(
            SendGridEmailProvider::from_provider_record(&api_key, &from_address.email.to_string())
                .with_sender(&from_address),
        ))
    } else if crate::services::providers::http_delivery::is_custom_http(provider) {
        Ok(Box::new(CustomHttpEmailProvider::from_record(
            provider, false,
        )?))
    } else {
        let host = provider
            .host
            .clone()
            .ok_or_else(|| AppError::Validation("SMTP provider requires host".to_string()))?;
        let port = provider.port.unwrap_or(587);
        let username = provider.client_id.clone().ok_or_else(|| {
            AppError::Validation("SMTP provider requires client_id username".to_string())
        })?;
        let password = provider.client_secret.clone().ok_or_else(|| {
            AppError::Validation("SMTP provider requires client_secret password".to_string())
        })?;
        let from_address =
            crate::services::provider_configuration_service::email_sender(provider, sender)?
                .to_string();
        Ok(Box::new(
            SmtpEmailProvider::from_provider_record(
                &host,
                port,
                &username,
                &password,
                &from_address,
                !provider.disable_ssl,
            )
            .with_ssl_mode(provider.ssl_mode.as_deref())?,
        ))
    }
}

fn sms_provider_from_record(provider: &Provider) -> AppResult<Box<dyn SmsProviderTrait>> {
    if crate::services::providers::http_delivery::is_custom_http(provider) {
        return Ok(Box::new(
            crate::services::providers::http_delivery::CustomHttpSmsProvider::from_record(
                provider, false,
            )?,
        ));
    }
    let provider_type = provider.provider_type.to_ascii_lowercase();
    if provider_type.contains("twilio") {
        let account_sid = provider.client_id.clone().ok_or_else(|| {
            AppError::Validation("Twilio provider requires client_id account SID".to_string())
        })?;
        let auth_token = provider.client_secret.clone().ok_or_else(|| {
            AppError::Validation("Twilio provider requires client_secret auth token".to_string())
        })?;
        let from_number = provider
            .app_id
            .clone()
            .or_else(|| provider.sign_name.clone())
            .or_else(|| provider.receiver.clone())
            .ok_or_else(|| {
                AppError::Validation(
                    "Twilio provider requires app_id or sign_name as from number".to_string(),
                )
            })?;
        Ok(Box::new(TwilioSmsProvider::new(
            account_sid,
            auth_token,
            from_number,
        )))
    } else {
        Err(AppError::Validation(
            "Unsupported SMS provider or missing HTTP endpoint".into(),
        ))
    }
}

fn notification_provider_from_record(
    provider: &Provider,
    allow_private: bool,
    pool: &PgPool,
) -> AppResult<Box<dyn crate::services::providers::NotificationProvider>> {
    if crate::services::providers::http_delivery::is_custom_http(provider) {
        return Ok(Box::new(
            crate::services::providers::custom_http_notify::CustomHttpNotifyProvider::from_record(
                provider,
                allow_private,
            )?
            .with_pool(pool.clone()),
        ));
    }
    let provider_type = normalize_notification_provider_type(&provider.provider_type);
    let token_or_url = match provider_type.as_str() {
        "CustomHTTP" | "Slack" | "Discord" | "DingTalk" | "Lark" | "Teams" => provider
            .endpoint
            .clone()
            .or_else(|| provider.provider_url.clone())
            .or_else(|| provider.client_id.clone())
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "Notification provider '{}' requires endpoint or provider_url",
                    provider.name
                ))
            })?,
        "Telegram" => provider
            .client_secret
            .clone()
            .or_else(|| provider.client_id.clone())
            .ok_or_else(|| {
                AppError::Validation(
                    "Telegram notification provider requires a bot token".to_string(),
                )
            })?,
        _ => provider
            .endpoint
            .clone()
            .or_else(|| provider.provider_url.clone())
            .or_else(|| provider.client_secret.clone())
            .or_else(|| provider.client_id.clone())
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "Notification provider '{}' is missing delivery credentials",
                    provider.name
                ))
            })?,
    };

    let config = provider
        .client_secret2
        .as_deref()
        .or(provider.metadata.as_deref())
        .or(provider.receiver.as_deref());

    create_notification_provider(&provider_type, &token_or_url, config)
}

fn normalize_notification_provider_type(provider_type: &str) -> String {
    if provider_type.eq_ignore_ascii_case("custom http")
        || provider_type.eq_ignore_ascii_case("custom http notification")
        || provider_type.eq_ignore_ascii_case("customhttp")
    {
        "CustomHTTP".to_string()
    } else {
        provider_type.trim().to_string()
    }
}
