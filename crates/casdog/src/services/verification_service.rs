use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{CaptchaResponse, Verification, VerificationResponse, VerifyCodeResponse};
use crate::services::ProviderDispatchService;
use crate::services::providers::create_captcha_provider;

const VERIFICATION_CODE_TTL_MINUTES: i64 = 10;
const VERIFICATION_RESEND_SECONDS: i64 = 60;
const CAPTCHA_TTL_MINUTES: i64 = 5;

static CAPTCHA_CHALLENGES: LazyLock<Mutex<HashMap<String, StoredCaptchaChallenge>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone)]
struct StoredCaptchaChallenge {
    kind: CaptchaChallengeKind,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
enum CaptchaChallengeKind {
    Local {
        code: String,
    },
    External {
        provider_ref: String,
        provider_type: String,
        site_key: Option<String>,
    },
}

pub struct VerificationService;

impl VerificationService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        user: Option<&str>,
    ) -> AppResult<Vec<VerificationResponse>> {
        let rows: Vec<Verification> = match (owner, user) {
            (Some(owner), Some(user)) => sqlx::query_as(
                r#"
                SELECT id, owner, name, created_at, remote_addr, "type", user_id, provider, receiver, code, is_used
                FROM verifications
                WHERE owner = $1 AND user_id = $2
                ORDER BY created_at DESC
                "#,
            )
            .bind(owner)
            .bind(user)
            .fetch_all(pool)
            .await?,
            (Some(owner), None) => sqlx::query_as(
                r#"
                SELECT id, owner, name, created_at, remote_addr, "type", user_id, provider, receiver, code, is_used
                FROM verifications
                WHERE owner = $1
                ORDER BY created_at DESC
                "#,
            )
            .bind(owner)
            .fetch_all(pool)
            .await?,
            (None, Some(user)) => sqlx::query_as(
                r#"
                SELECT id, owner, name, created_at, remote_addr, "type", user_id, provider, receiver, code, is_used
                FROM verifications
                WHERE user_id = $1
                ORDER BY created_at DESC
                "#,
            )
            .bind(user)
            .fetch_all(pool)
            .await?,
            (None, None) => sqlx::query_as(
                r#"
                SELECT id, owner, name, created_at, remote_addr, "type", user_id, provider, receiver, code, is_used
                FROM verifications
                ORDER BY created_at DESC
                "#,
            )
            .fetch_all(pool)
            .await?,
        };

        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<VerificationResponse> {
        let row: Verification = sqlx::query_as(
            r#"
            SELECT id, owner, name, created_at, remote_addr, "type", user_id, provider, receiver, code, is_used
            FROM verifications
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Verification not found".to_string()))?;

        Ok(row.into())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_verification_code(
        pool: &PgPool,
        owner: &str,
        user_id: Option<&str>,
        dest: &str,
        dest_type: &str,
        application_ref: Option<&str>,
        explicit_provider: Option<&str>,
        method: Option<&str>,
        country_code: Option<&str>,
        remote_addr: Option<&str>,
    ) -> AppResult<VerificationResponse> {
        let normalized_dest_type = dest_type.trim().to_ascii_lowercase();
        if normalized_dest_type != "email" && normalized_dest_type != "phone" {
            return Err(AppError::Validation(format!(
                "Unsupported verification type: {}",
                dest_type
            )));
        }

        Self::enforce_resend_limit(pool, dest, &normalized_dest_type, user_id).await?;

        let dispatch = ProviderDispatchService::new(pool.clone());
        let resolved = dispatch
            .resolve_provider(
                if normalized_dest_type == "email" {
                    "Email"
                } else {
                    "SMS"
                },
                explicit_provider,
                application_ref,
                method,
                country_code,
            )
            .await?;

        let code = generate_numeric_code(6);
        if normalized_dest_type == "email" {
            let subject = resolved
                .provider
                .title
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "Verification code".to_string());
            let content = render_email_verification_content(
                resolved.provider.content.as_deref(),
                &code,
                method,
            );
            dispatch
                .send_email_with_provider(
                    &resolved.provider,
                    &[dest.to_string()],
                    &subject,
                    &content,
                    None,
                )
                .await?;
        } else {
            let content = render_sms_verification_content(&resolved.provider, &code);
            dispatch
                .send_sms_with_provider(&resolved.provider, &[dest.to_string()], &content)
                .await?;
        }

        let id = Uuid::new_v4().to_string();
        let created_at = Utc::now();
        let record_owner = resolved
            .application
            .as_ref()
            .map(|app| app.organization.as_str())
            .filter(|value| !value.is_empty())
            .unwrap_or(owner)
            .to_string();
        let record_user = user_id.unwrap_or(owner).to_string();

        sqlx::query(
            r#"
            INSERT INTO verifications (id, owner, name, created_at, remote_addr, "type", user_id, provider, receiver, code, is_used)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false)
            "#,
        )
        .bind(&id)
        .bind(&record_owner)
        .bind(&format!("verification_{}", id))
        .bind(created_at)
        .bind(remote_addr)
        .bind(&normalized_dest_type)
        .bind(&record_user)
        .bind(&resolved.provider.name)
        .bind(dest)
        .bind(&code)
        .execute(pool)
        .await?;

        Ok(VerificationResponse {
            id,
            owner: record_owner,
            created_at,
            verification_type: normalized_dest_type,
            user: record_user,
            provider: resolved.provider.name,
            receiver: dest.to_string(),
            is_used: false,
        })
    }

    pub async fn verify_code(
        pool: &PgPool,
        dest: &str,
        code: &str,
    ) -> AppResult<VerifyCodeResponse> {
        let verification: Option<(String, bool, DateTime<Utc>)> = sqlx::query_as(
            r#"
            SELECT id, is_used, created_at
            FROM verifications
            WHERE receiver = $1 AND code = $2
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(dest)
        .bind(code)
        .fetch_optional(pool)
        .await?;

        match verification {
            Some((id, is_used, created_at)) => {
                if is_used {
                    return Ok(VerifyCodeResponse {
                        success: false,
                        message: "Code has already been used".to_string(),
                    });
                }

                if Utc::now() - created_at > Duration::minutes(VERIFICATION_CODE_TTL_MINUTES) {
                    return Ok(VerifyCodeResponse {
                        success: false,
                        message: "Verification code expired".to_string(),
                    });
                }

                sqlx::query("UPDATE verifications SET is_used = true WHERE id = $1")
                    .bind(&id)
                    .execute(pool)
                    .await?;

                Ok(VerifyCodeResponse {
                    success: true,
                    message: "Code verified successfully".to_string(),
                })
            }
            None => Ok(VerifyCodeResponse {
                success: false,
                message: "Invalid verification code".to_string(),
            }),
        }
    }

    pub async fn generate_captcha(
        pool: &PgPool,
        application_ref: Option<&str>,
        explicit_provider: Option<&str>,
    ) -> AppResult<CaptchaResponse> {
        let dispatch = ProviderDispatchService::new(pool.clone());
        if let Some(resolved) = dispatch
            .resolve_captcha_provider(explicit_provider, application_ref)
            .await?
        {
            let captcha_id = Uuid::new_v4().to_string();
            let provider_ref = format!("{}/{}", resolved.provider.owner, resolved.provider.name);
            let provider_type = resolved
                .provider
                .sub_type
                .clone()
                .unwrap_or_else(|| resolved.provider.provider_type.clone());
            let site_key = resolved.provider.client_id.clone();

            store_captcha_challenge(
                &captcha_id,
                CaptchaChallengeKind::External {
                    provider_ref: provider_ref.clone(),
                    provider_type: provider_type.clone(),
                    site_key: site_key.clone(),
                },
            )?;

            return Ok(CaptchaResponse {
                captcha_id,
                captcha_image: None,
                external: true,
                provider: Some(provider_ref),
                captcha_type: Some(provider_type),
                site_key,
            });
        }

        let captcha_id = Uuid::new_v4().to_string();
        let code = generate_local_captcha_code();
        let image = render_local_captcha_image(&code);
        store_captcha_challenge(&captcha_id, CaptchaChallengeKind::Local { code })?;

        Ok(CaptchaResponse {
            captcha_id,
            captcha_image: Some(image),
            external: false,
            provider: Some("default".to_string()),
            captcha_type: Some("Default".to_string()),
            site_key: None,
        })
    }

    pub async fn verify_captcha(
        pool: &PgPool,
        captcha_id: &str,
        captcha_code: Option<&str>,
        captcha_token: Option<&str>,
        application_ref: Option<&str>,
        explicit_provider: Option<&str>,
        remote_ip: Option<&str>,
    ) -> AppResult<bool> {
        if let Some(challenge) = take_captcha_challenge(captcha_id)? {
            if challenge.expires_at < Utc::now() {
                return Ok(false);
            }

            return match challenge.kind {
                CaptchaChallengeKind::Local { code } => Ok(captcha_code
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|candidate| candidate.eq_ignore_ascii_case(&code))
                    .unwrap_or(false)),
                CaptchaChallengeKind::External {
                    provider_ref,
                    provider_type,
                    ..
                } => {
                    let token = captcha_token
                        .or(captcha_code)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            AppError::Validation(
                                "captcha_token is required for external captcha".to_string(),
                            )
                        })?;
                    Self::verify_external_captcha(
                        pool,
                        Some(&provider_ref),
                        Some(&provider_type),
                        token,
                        remote_ip,
                    )
                    .await
                }
            };
        }

        let dispatch = ProviderDispatchService::new(pool.clone());
        if let Some(resolved) = dispatch
            .resolve_captcha_provider(explicit_provider, application_ref)
            .await?
        {
            let token = captcha_token
                .or(captcha_code)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    AppError::Validation(
                        "captcha_token is required for external captcha".to_string(),
                    )
                })?;
            let provider_ref = format!("{}/{}", resolved.provider.owner, resolved.provider.name);
            let provider_type = resolved
                .provider
                .sub_type
                .as_deref()
                .or(Some(resolved.provider.provider_type.as_str()));
            return Self::verify_external_captcha(
                pool,
                Some(&provider_ref),
                provider_type,
                token,
                remote_ip,
            )
            .await;
        }

        Ok(false)
    }

    pub async fn get_email_and_phone(
        pool: &PgPool,
        username: &str,
        _organization: &str,
    ) -> AppResult<(Option<String>, Option<String>)> {
        let user: Option<(Option<String>, Option<String>)> =
            sqlx::query_as("SELECT email, phone FROM users WHERE name = $1")
                .bind(username)
                .fetch_optional(pool)
                .await?;

        match user {
            Some((email, phone)) => Ok((email, phone)),
            None => Err(AppError::NotFound("User not found".to_string())),
        }
    }

    pub async fn disable_verification_code(pool: &PgPool, dest: &str) -> AppResult<()> {
        sqlx::query(
            "UPDATE verifications SET is_used = true WHERE receiver = $1 AND is_used = false",
        )
        .bind(dest)
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn enforce_resend_limit(
        pool: &PgPool,
        dest: &str,
        dest_type: &str,
        user_id: Option<&str>,
    ) -> AppResult<()> {
        let last_sent_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            r#"
            SELECT created_at
            FROM verifications
            WHERE receiver = $1
              AND "type" = $2
              AND ($3::varchar IS NULL OR user_id = $3)
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(dest)
        .bind(dest_type)
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

        if let Some(last_sent_at) = last_sent_at {
            if Utc::now() - last_sent_at < Duration::seconds(VERIFICATION_RESEND_SECONDS) {
                return Err(AppError::Validation(format!(
                    "Verification code can only be sent once every {} seconds",
                    VERIFICATION_RESEND_SECONDS
                )));
            }
        }

        Ok(())
    }

    async fn verify_external_captcha(
        pool: &PgPool,
        provider_ref: Option<&str>,
        provider_type_hint: Option<&str>,
        token: &str,
        remote_ip: Option<&str>,
    ) -> AppResult<bool> {
        let dispatch = ProviderDispatchService::new(pool.clone());
        let resolved = dispatch
            .resolve_provider("Captcha", provider_ref, None, None, None)
            .await?;
        let provider_type = provider_type_hint
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| resolved.provider.sub_type.clone())
            .unwrap_or_else(|| resolved.provider.provider_type.clone());
        let secret_key = resolved.provider.client_secret.clone().ok_or_else(|| {
            AppError::Validation(format!(
                "Captcha provider '{}' does not have a secret key",
                resolved.provider.name
            ))
        })?;
        let provider = create_captcha_provider(&provider_type, &secret_key);
        provider.verify(token, remote_ip).await
    }
}

fn generate_numeric_code(length: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| rng.gen_range(0..10).to_string())
        .collect()
}

fn generate_local_captcha_code() -> String {
    const CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut rng = rand::thread_rng();
    (0..5)
        .map(|_| {
            let index = rng.gen_range(0..CHARSET.len());
            CHARSET[index] as char
        })
        .collect()
}

fn render_local_captcha_image(code: &str) -> String {
    let mut rng = rand::thread_rng();
    let svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="220" height="80" viewBox="0 0 220 80">
<rect width="220" height="80" fill="#f6f8fb"/>
<path d="M10 65 C40 15, 80 15, 110 65 S180 115, 210 20" fill="none" stroke="#d0d7e2" stroke-width="2"/>
<path d="M5 20 C40 50, 100 0, 150 35 S205 75, 215 15" fill="none" stroke="#c3cedd" stroke-width="1.5"/>
<circle cx="28" cy="18" r="8" fill="#dbe5f0"/>
<circle cx="194" cy="60" r="10" fill="#dbe5f0"/>
<text x="24" y="54" font-family="Consolas, 'Courier New', monospace" font-size="34" letter-spacing="8" fill="#203040" transform="rotate({angle} 110 40)">{code}</text>
</svg>"##,
        angle = rng.gen_range(-6..=6),
        code = code
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(svg.as_bytes());
    format!("data:image/svg+xml;base64,{}", encoded)
}

fn render_email_verification_content(
    template: Option<&str>,
    code: &str,
    method: Option<&str>,
) -> String {
    let mut content = template
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("Your verification code is %s. It expires in 10 minutes.")
        .to_string();
    content = replace_first(&content, "%s", code);
    content = content.replace("%{user.friendlyName}", "Hi");
    if !method
        .map(|value| value.eq_ignore_ascii_case("forget"))
        .unwrap_or(false)
    {
        content = strip_tagged_section(&content, "<reset-link>", "</reset-link>");
    } else {
        content = content
            .replace("<reset-link>", "")
            .replace("</reset-link>", "");
    }
    content
}

fn render_sms_verification_content(provider: &crate::models::Provider, code: &str) -> String {
    let template = provider
        .template_code
        .as_deref()
        .or(provider.content.as_deref())
        .unwrap_or("Your verification code is %s");
    if template.contains("%s") {
        replace_first(template, "%s", code)
    } else if template.contains("{code}") {
        replace_first(template, "{code}", code)
    } else if template.trim().is_empty() {
        format!("Your verification code is {}", code)
    } else {
        format!("{} {}", template.trim(), code)
    }
}

fn replace_first(content: &str, from: &str, to: &str) -> String {
    content.replacen(from, to, 1)
}

fn strip_tagged_section(content: &str, start_tag: &str, end_tag: &str) -> String {
    if let Some(start) = content.find(start_tag) {
        if let Some(end) = content[start + start_tag.len()..].find(end_tag) {
            let end = start + start_tag.len() + end + end_tag.len();
            let mut result = String::with_capacity(content.len());
            result.push_str(&content[..start]);
            result.push_str(&content[end..]);
            return result;
        }
    }
    content.to_string()
}

fn store_captcha_challenge(captcha_id: &str, kind: CaptchaChallengeKind) -> AppResult<()> {
    let mut store = CAPTCHA_CHALLENGES
        .lock()
        .map_err(|_| AppError::Internal("Captcha store unavailable".to_string()))?;
    cleanup_expired_challenges(&mut store);
    store.insert(
        captcha_id.to_string(),
        StoredCaptchaChallenge {
            kind,
            expires_at: Utc::now() + Duration::minutes(CAPTCHA_TTL_MINUTES),
        },
    );
    Ok(())
}

fn take_captcha_challenge(captcha_id: &str) -> AppResult<Option<StoredCaptchaChallenge>> {
    let mut store = CAPTCHA_CHALLENGES
        .lock()
        .map_err(|_| AppError::Internal("Captcha store unavailable".to_string()))?;
    cleanup_expired_challenges(&mut store);
    Ok(store.remove(captcha_id))
}

fn cleanup_expired_challenges(store: &mut HashMap<String, StoredCaptchaChallenge>) {
    let now = Utc::now();
    store.retain(|_, challenge| challenge.expires_at > now);
}
