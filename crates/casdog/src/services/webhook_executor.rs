use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::error::{AppError, AppResult};

// ---------------------------------------------------------------------------
// Webhook payload
// ---------------------------------------------------------------------------

/// Payload sent to webhook endpoints when entity changes occur.
///
/// Handlers construct this after a successful create/update/delete and pass it
/// to [`WebhookExecutor::fire`].
///
/// ```ignore
/// WebhookExecutor::fire(&pool, WebhookPayload {
///     event: "user.created".to_string(),
///     action: "create".to_string(),
///     entity_type: "user".to_string(),
///     entity_id: user.id.clone(),
///     entity_name: user.name.clone(),
///     owner: user.owner.clone(),
///     timestamp: chrono::Utc::now().to_rfc3339(),
///     data: serde_json::to_value(&user).unwrap_or_default(),
/// }).await;
/// ```
#[derive(Debug, Serialize, Clone)]
pub struct WebhookPayload {
    /// Fully-qualified event name, e.g. "user.created", "update-user".
    pub event: String,
    /// Short verb: "create", "update", "delete".
    pub action: String,
    /// Kind of entity: "user", "organization", "application", etc.
    pub entity_type: String,
    /// Primary key of the affected entity.
    pub entity_id: String,
    /// Human-readable name of the affected entity.
    pub entity_name: String,
    /// Owner (typically the organization) of the affected entity.
    pub owner: String,
    /// ISO-8601 / RFC-3339 timestamp of when the event occurred.
    pub timestamp: String,
    /// The entity data itself (serialized to JSON value).
    pub data: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Internal row type for the query result
// ---------------------------------------------------------------------------

/// Subset of columns fetched from the `webhooks` table that the executor
/// needs in order to deliver a notification.
#[derive(Debug, sqlx::FromRow)]
struct WebhookInfo {
    id: String,
    name: String,
    url: String,
    method: String,
    content_type: String,
    headers: Option<String>, // JSON — either `["H: V", ...]` or `[{"name":"H","value":"V"}, ...]`
    events: Option<String>,  // JSON array of event type strings
    organization: String,
    is_user_extended: bool,
}

// ---------------------------------------------------------------------------
// Header helper
// ---------------------------------------------------------------------------

/// Casdoor-style header object (name/value pair stored in webhook JSON).
#[derive(Debug, serde::Deserialize)]
struct HeaderEntry {
    name: String,
    value: String,
}

/// Parse the `headers` JSON column into a vec of (name, value) pairs.
///
/// Supports two formats that the CRUD layer may produce:
///   1. Array of `{"name": "...", "value": "..."}` objects (Casdoor-compatible).
///   2. Array of plain strings such as `"X-Custom: foobar"` (simple format).
fn parse_headers(raw: &str) -> Vec<(String, String)> {
    // Try structured format first.
    if let Ok(entries) = serde_json::from_str::<Vec<HeaderEntry>>(raw) {
        return entries.into_iter().map(|h| (h.name, h.value)).collect();
    }

    // Fall back to plain string array ("Name: Value").
    if let Ok(strings) = serde_json::from_str::<Vec<String>>(raw) {
        return strings
            .into_iter()
            .filter_map(|s| {
                let mut parts = s.splitn(2, ':');
                let key = parts.next()?.trim().to_string();
                let val = parts.next().unwrap_or("").trim().to_string();
                if key.is_empty() {
                    None
                } else {
                    Some((key, val))
                }
            })
            .collect();
    }

    Vec::new()
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 (no extra crate — mirrors password_service.rs approach)
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256 and return the hex-encoded digest.
///
/// Uses the standard two-pass Sha256 construction so we don't need the `hmac`
/// crate as a direct dependency (it is already pulled in transitively but not
/// re-exported).
fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> String {
    const BLOCK_SIZE: usize = 64;

    // Normalise key to exactly BLOCK_SIZE bytes.
    let mut key_padded = vec![0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        key_padded[..hash.len()].copy_from_slice(&hash);
    } else {
        key_padded[..key.len()].copy_from_slice(key);
    }

    // Inner and outer pads.
    let mut ipad = vec![0x36u8; BLOCK_SIZE];
    let mut opad = vec![0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_padded[i];
        opad[i] ^= key_padded[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let outer_hash = outer.finalize();

    hex::encode(outer_hash)
}

// ---------------------------------------------------------------------------
// WebhookExecutor
// ---------------------------------------------------------------------------

/// Fires HTTP webhooks when entity mutations happen.
///
/// The executor is intentionally **fire-and-forget**: [`fire`](Self::fire)
/// spawns a Tokio task so the calling handler is never blocked.  Errors are
/// logged via `tracing` and do not propagate to the HTTP response.
pub struct WebhookExecutor;

impl WebhookExecutor {
    // -------------------------------------------------------------------
    // Public entry point
    // -------------------------------------------------------------------

    /// Spawn a background task that delivers matching webhooks for `payload`.
    ///
    /// This method returns immediately — it does **not** wait for the HTTP
    /// requests to complete.
    pub async fn fire(pool: &PgPool, payload: WebhookPayload) {
        let pool = pool.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::execute_webhooks(&pool, &payload).await {
                tracing::error!(event = %payload.event, "Webhook execution error: {:?}", e);
            }
        });
    }

    // -------------------------------------------------------------------
    // Core orchestration
    // -------------------------------------------------------------------

    /// Find every matching webhook and deliver the payload to each one.
    async fn execute_webhooks(pool: &PgPool, payload: &WebhookPayload) -> AppResult<()> {
        let webhooks = Self::find_matching_webhooks(pool, &payload.owner, &payload.event).await?;

        if webhooks.is_empty() {
            tracing::debug!(
                event = %payload.event,
                owner = %payload.owner,
                "No matching webhooks found"
            );
            return Ok(());
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| AppError::Internal(format!("HTTP client error: {}", e)))?;

        for webhook in &webhooks {
            // First attempt.
            let result = Self::send_webhook(&client, webhook, payload).await;

            match result {
                Ok(status) => {
                    tracing::info!(
                        webhook_name = %webhook.name,
                        webhook_id = %webhook.id,
                        status,
                        "Webhook fired successfully"
                    );
                }
                Err(ref first_err) => {
                    tracing::warn!(
                        webhook_name = %webhook.name,
                        webhook_id = %webhook.id,
                        error = %first_err,
                        "Webhook failed on first attempt, retrying once"
                    );

                    // Retry once after a short delay.
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                    match Self::send_webhook(&client, webhook, payload).await {
                        Ok(status) => {
                            tracing::info!(
                                webhook_name = %webhook.name,
                                webhook_id = %webhook.id,
                                status,
                                "Webhook succeeded on retry"
                            );
                        }
                        Err(retry_err) => {
                            tracing::error!(
                                webhook_name = %webhook.name,
                                webhook_id = %webhook.id,
                                first_error = %first_err,
                                retry_error = %retry_err,
                                "Webhook failed after retry"
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // -------------------------------------------------------------------
    // Query matching webhooks
    // -------------------------------------------------------------------

    /// Fetch all enabled webhooks whose `events` array contains `event` and
    /// whose `owner` or `organization` matches the payload owner.
    ///
    /// The `events` column is a JSON-encoded string array, e.g.
    /// `["signup","login","update-user"]`.  We use a `LIKE` check against the
    /// serialised text which is simple and sufficient — the event names are
    /// short well-known tokens that won't produce false-positive substring
    /// matches in practice.
    async fn find_matching_webhooks(
        pool: &PgPool,
        owner: &str,
        event: &str,
    ) -> AppResult<Vec<WebhookInfo>> {
        let rows: Vec<WebhookInfo> = sqlx::query_as(
            r#"
            SELECT id, name, url, method, content_type,
                   headers, events, organization, is_user_extended
            FROM webhooks
            WHERE is_enabled = true
              AND (owner = $1 OR organization = $1 OR owner = 'admin')
              AND (events IS NULL OR events::text LIKE '%' || $2 || '%')
            "#,
        )
        .bind(owner)
        .bind(event)
        .fetch_all(pool)
        .await?;

        // Second pass: exact match inside the JSON array.
        // The SQL LIKE is a coarse pre-filter; here we deserialise and
        // confirm the event is actually present as a discrete array element.
        let matched: Vec<WebhookInfo> = rows
            .into_iter()
            .filter(|w| {
                match &w.events {
                    None => true, // NULL events means "match everything"
                    Some(raw) => {
                        if let Ok(events) = serde_json::from_str::<Vec<String>>(raw) {
                            events.iter().any(|e| e == event)
                        } else {
                            // Unparseable — skip this webhook.
                            false
                        }
                    }
                }
            })
            .collect();

        Ok(matched)
    }

    // -------------------------------------------------------------------
    // HTTP delivery
    // -------------------------------------------------------------------

    /// Deliver the payload to a single webhook endpoint.
    ///
    /// Returns the HTTP status code on success, or a human-readable error
    /// string on failure.
    async fn send_webhook(
        client: &reqwest::Client,
        webhook: &WebhookInfo,
        payload: &WebhookPayload,
    ) -> Result<u16, String> {
        let body =
            serde_json::to_string(payload).map_err(|e| format!("Serialization error: {}", e))?;

        // Use the method from the webhook config (default POST).
        let method = match webhook.method.to_uppercase().as_str() {
            "GET" => reqwest::Method::GET,
            "PUT" => reqwest::Method::PUT,
            "PATCH" => reqwest::Method::PATCH,
            _ => reqwest::Method::POST,
        };

        let mut request = client
            .request(method, &webhook.url)
            .header("Content-Type", &webhook.content_type);

        // HMAC-SHA256 signature.
        //
        // Custom headers may include a "secret" that the receiver can use to
        // verify authenticity.  We also compute an X-Webhook-Signature header
        // when a header named "secret" is present.
        let custom_headers = webhook
            .headers
            .as_deref()
            .map(parse_headers)
            .unwrap_or_default();

        let mut secret_value: Option<String> = None;

        for (key, value) in &custom_headers {
            if key.eq_ignore_ascii_case("secret") {
                secret_value = Some(value.clone());
                // Don't forward the "secret" pseudo-header to the remote server.
                continue;
            }
            request = request.header(key.as_str(), value.as_str());
        }

        if let Some(ref secret) = secret_value {
            if !secret.is_empty() {
                let signature = compute_hmac_sha256(secret.as_bytes(), body.as_bytes());
                request = request.header("X-Webhook-Signature", format!("sha256={}", signature));
            }
        }

        let response = request
            .body(body)
            .send()
            .await
            .map_err(|e| format!("Request error: {}", e))?;

        let status = response.status().as_u16();

        // Read (and discard) the body so the connection can be reused.
        let _body = response.text().await.unwrap_or_default();

        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hmac_sha256() {
        // Known test vector: HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")
        let result = compute_hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            result,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn test_compute_hmac_sha256_empty() {
        // HMAC-SHA256("", "")
        let result = compute_hmac_sha256(b"", b"");
        assert_eq!(
            result,
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
    }

    #[test]
    fn test_parse_headers_structured() {
        let json =
            r#"[{"name":"Authorization","value":"Bearer abc"},{"name":"X-Custom","value":"val"}]"#;
        let headers = parse_headers(json);
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0],
            ("Authorization".to_string(), "Bearer abc".to_string())
        );
        assert_eq!(headers[1], ("X-Custom".to_string(), "val".to_string()));
    }

    #[test]
    fn test_parse_headers_plain_strings() {
        let json = r#"["Authorization: Bearer abc","X-Custom: val"]"#;
        let headers = parse_headers(json);
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0],
            ("Authorization".to_string(), "Bearer abc".to_string())
        );
        assert_eq!(headers[1], ("X-Custom".to_string(), "val".to_string()));
    }

    #[test]
    fn test_parse_headers_empty() {
        let headers = parse_headers("[]");
        assert!(headers.is_empty());
    }

    #[test]
    fn test_parse_headers_invalid() {
        let headers = parse_headers("not json at all");
        assert!(headers.is_empty());
    }
}
