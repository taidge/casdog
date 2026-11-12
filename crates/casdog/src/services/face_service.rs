//! Face biometric verification service.
//!
//! Implements a real face-embedding comparison flow:
//! 1. `begin` generates a one-time sign-in challenge (nonce).
//! 2. `finish` accepts a face embedding vector, compares it against stored
//!    embeddings for the user using cosine similarity, and returns a verdict.
//!
//! Embeddings are stored in the user's `properties.faceIds` field as a JSON
//! array of float arrays, matching Casdoor's storage convention.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{Application, User};
use crate::services::check_service::CheckService;

/// Default cosine-similarity threshold above which a face match is accepted.
const DEFAULT_SIMILARITY_THRESHOLD: f64 = 0.85;

/// Challenge TTL in seconds.
const CHALLENGE_TTL_SECS: i64 = 120;

// -- Public types ------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct FaceChallenge {
    pub challenge: String,
    pub expires_at: String,
    pub user: String,
    pub application: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct FaceVerifyRequest {
    /// The challenge nonce returned by `begin`.
    pub challenge: String,
    /// The face embedding vector captured from the camera.
    pub embedding: Vec<f64>,
}

#[derive(Debug, Serialize)]
pub struct FaceVerifyResult {
    pub matched: bool,
    pub similarity: f64,
    pub threshold: f64,
    pub user: String,
    pub application: Option<String>,
}

// -- Service -----------------------------------------------------------------

pub struct FaceService {
    pool: Pool<Postgres>,
}

impl FaceService {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    /// Begin a face-verification challenge for the given user.
    ///
    /// Stores a time-limited nonce in the user's `properties.face_challenge` field
    /// so that the subsequent `finish` call can consume the ceremony once.
    pub async fn begin(
        &self,
        owner: &str,
        name: &str,
        application: Option<&str>,
    ) -> AppResult<FaceChallenge> {
        let mut tx = self.pool.begin().await?;
        let user: User = sqlx::query_as(
            "SELECT * FROM users WHERE owner = $1 AND name = $2 AND NOT is_deleted AND NOT is_forbidden FOR UPDATE",
        )
        .bind(owner)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User {owner}/{name} not found")))?;

        let app = Self::check_policy(&mut tx, &user, application).await?;

        // Verify the user has at least one stored face embedding.
        let has_faces =
            !Self::collect_embeddings(user.properties.as_ref(), user.custom.as_ref()).is_empty();
        if !has_faces {
            return Err(AppError::Validation(
                "User does not have any enrolled face embeddings".to_string(),
            ));
        }

        // Generate a challenge nonce.
        let nonce = uuid::Uuid::new_v4().to_string();
        let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let expires_at = now + chrono::Duration::seconds(CHALLENGE_TTL_SECS);
        let expires_at_str = expires_at.to_rfc3339();

        // Store challenge in the user's properties for validation in `finish`.
        let challenge_value = serde_json::json!({
            "nonce": nonce,
            "expires_at": expires_at_str,
            "application": app.as_ref().map(|a| a.id.as_str()),
            "credential_stamp": Self::credential_stamp(user.properties.as_ref(), user.custom.as_ref()),
        });
        let mut props = user.properties.unwrap_or_else(|| serde_json::json!({}));
        props["face_challenge"] = challenge_value;
        sqlx::query("UPDATE users SET properties = $1, updated_at = NOW() WHERE id = $2")
            .bind(&props)
            .bind(&user.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        Ok(FaceChallenge {
            challenge: nonce,
            expires_at: expires_at_str,
            user: format!("{owner}/{name}"),
            application: application.map(ToString::to_string),
        })
    }

    /// Finish a face-verification challenge.
    ///
    /// Compares the submitted embedding against all stored embeddings for the
    /// user and returns whether the best match exceeds the similarity threshold.
    pub async fn finish(
        &self,
        owner: &str,
        name: &str,
        request: &FaceVerifyRequest,
    ) -> AppResult<FaceVerifyResult> {
        let mut tx = self.pool.begin().await?;
        let result = Self::finish_conn(&mut tx, owner, name, request).await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Keep the nonce consumption and the resulting MFA challenge/session in
    /// one transaction. Lock the account before reading its challenge.
    pub(crate) async fn finish_conn(
        conn: &mut PgConnection,
        owner: &str,
        name: &str,
        request: &FaceVerifyRequest,
    ) -> AppResult<FaceVerifyResult> {
        let user: User = sqlx::query_as(
            "SELECT * FROM users WHERE owner = $1 AND name = $2 AND NOT is_deleted AND NOT is_forbidden FOR UPDATE",
        )
        .bind(owner)
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User {owner}/{name} not found")))?;

        // Validate the challenge nonce.
        let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *conn)
            .await?;
        Self::validate_challenge(user.properties.as_ref(), &request.challenge, now)?;
        let challenge = &user.properties.as_ref().unwrap()["face_challenge"];
        let application = challenge["application"].as_str().map(str::to_owned);
        Self::check_policy(conn, &user, application.as_deref()).await?;
        if challenge["credential_stamp"].as_str()
            != Some(Self::credential_stamp(user.properties.as_ref(), user.custom.as_ref()).as_str())
        {
            return Err(AppError::Authentication(
                "Face enrollment changed during sign-in".into(),
            ));
        }

        // Collect all stored embeddings.
        let stored = Self::collect_embeddings(user.properties.as_ref(), user.custom.as_ref());
        if stored.is_empty() {
            return Err(AppError::Validation(
                "No face embeddings stored for this user".to_string(),
            ));
        }

        // Compare against each stored embedding and take the best match.
        let mut best_similarity = f64::NEG_INFINITY;
        for stored_embedding in &stored {
            let sim = cosine_similarity(&request.embedding, stored_embedding);
            if sim > best_similarity {
                best_similarity = sim;
            }
        }

        // Clear the challenge after use.
        if let Some(mut props) = user.properties {
            props.as_object_mut().map(|m| m.remove("face_challenge"));
            sqlx::query("UPDATE users SET properties = $1, updated_at = NOW() WHERE id = $2")
                .bind(&props)
                .bind(&user.id)
                .execute(&mut *conn)
                .await?;
        }

        let threshold = DEFAULT_SIMILARITY_THRESHOLD;
        Ok(FaceVerifyResult {
            matched: best_similarity >= threshold,
            similarity: best_similarity,
            threshold,
            user: format!("{owner}/{name}"),
            application,
        })
    }

    /// Enroll a new face embedding for a user.
    pub async fn enroll(&self, owner: &str, name: &str, embedding: Vec<f64>) -> AppResult<()> {
        let mut tx = self.pool.begin().await?;
        let (user_id, properties) = sqlx::query_as::<_, (String, Option<serde_json::Value>)>(
            "SELECT id, properties FROM users WHERE owner = $1 AND name = $2 AND is_deleted = FALSE FOR UPDATE",
        )
        .bind(owner)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User {owner}/{name} not found")))?;

        let mut props = properties.unwrap_or_else(|| serde_json::json!({}));
        let face_ids = props
            .as_object_mut()
            .and_then(|m| {
                m.entry("faceIds")
                    .or_insert_with(|| serde_json::json!([]))
                    .as_array_mut()
                    .cloned()
            })
            .unwrap_or_default();

        let mut face_ids = face_ids;
        face_ids.push(serde_json::json!(embedding));
        props["faceIds"] = serde_json::json!(face_ids);

        sqlx::query("UPDATE users SET properties = $1, updated_at = NOW() WHERE id = $2")
            .bind(&props)
            .bind(&user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    // -- Helpers -------------------------------------------------------------

    pub(crate) fn credential_stamp(
        properties: Option<&serde_json::Value>,
        custom: Option<&serde_json::Value>,
    ) -> String {
        crate::services::social_state_service::proof_hash(
            &serde_json::to_string(&Self::collect_embeddings(properties, custom))
                .unwrap_or_default(),
        )
    }

    async fn check_policy(
        conn: &mut PgConnection,
        user: &User,
        application: Option<&str>,
    ) -> AppResult<Option<Application>> {
        let enabled: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin)")
            .bind(&user.owner).fetch_one(&mut *conn).await?;
        if !enabled {
            return Err(AppError::Authentication(
                "Organization sign-in disabled".into(),
            ));
        }
        CheckService::check_signin_lockout(
            user.signin_wrong_times,
            user.last_signin_wrong_time.as_deref(),
            None,
            None,
        )?;
        if let Some(reference) = application {
            let app: Application = sqlx::query_as("SELECT * FROM applications WHERE NOT is_deleted AND organization=$2 AND (id=$1 OR owner||'/'||name=$1 OR (owner=$2 AND name=$1))")
                .bind(reference).bind(&user.owner).fetch_optional(&mut *conn).await?
                .ok_or_else(|| AppError::Authentication("Application unavailable".into()))?;
            CheckService::check_login_permission_conn(conn, &user.id, &app.id).await?;
            return Ok(Some(app));
        }
        Ok(None)
    }

    fn validate_challenge(
        properties: Option<&serde_json::Value>,
        nonce: &str,
        now: chrono::DateTime<Utc>,
    ) -> AppResult<()> {
        let challenge = properties
            .and_then(|p| p.get("face_challenge"))
            .ok_or_else(|| {
                AppError::Authentication("No active face challenge for this user".to_string())
            })?;

        let stored_nonce = challenge
            .get("nonce")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if stored_nonce != nonce {
            return Err(AppError::Authentication(
                "Face challenge nonce mismatch".to_string(),
            ));
        }

        let expires_at = challenge
            .get("expires_at")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        if expires_at.is_none_or(|expiry| now >= expiry) {
            return Err(AppError::Authentication(
                "Face challenge has expired".to_string(),
            ));
        }

        Ok(())
    }

    fn collect_embeddings(
        properties: Option<&serde_json::Value>,
        custom: Option<&serde_json::Value>,
    ) -> Vec<Vec<f64>> {
        let mut result = Vec::new();
        for source in [properties, custom].into_iter().flatten() {
            if let Some(face_ids) = source.get("faceIds").and_then(|v| v.as_array()) {
                for entry in face_ids {
                    if let Some(embedding) = parse_embedding(entry) {
                        result.push(embedding);
                    }
                }
            }
            // Also support a single `face_id` embedding.
            if let Some(face_id) = source.get("face_id") {
                if let Some(embedding) = parse_embedding(face_id) {
                    result.push(embedding);
                }
            }
        }
        result
    }
}

// -- Math helpers ------------------------------------------------------------

fn parse_embedding(value: &serde_json::Value) -> Option<Vec<f64>> {
    match value {
        serde_json::Value::Array(arr) => {
            let nums: Vec<f64> = arr.iter().filter_map(|v| v.as_f64()).collect();
            if nums.len() == arr.len() && !nums.is_empty() {
                Some(nums)
            } else {
                None
            }
        }
        serde_json::Value::String(s) => {
            // Support JSON-encoded embedding strings.
            serde_json::from_str::<Vec<f64>>(s).ok()
        }
        _ => None,
    }
}

fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let mag_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        return 0.0;
    }
    dot / (mag_a * mag_b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosine_similarity_identical() {
        let a = vec![1.0, 2.0, 3.0];
        let sim = cosine_similarity(&a, &a);
        assert!((sim - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-10);
    }

    #[test]
    fn test_cosine_similarity_opposite() {
        let a = vec![1.0, 0.0];
        let b = vec![-1.0, 0.0];
        let sim = cosine_similarity(&a, &b);
        assert!((sim - (-1.0)).abs() < 1e-10);
    }

    #[test]
    fn test_parse_embedding_array() {
        let val = serde_json::json!([0.1, 0.2, 0.3]);
        let emb = parse_embedding(&val).unwrap();
        assert_eq!(emb.len(), 3);
    }

    #[test]
    fn test_parse_embedding_string() {
        let val = serde_json::json!("[0.1, 0.2, 0.3]");
        let emb = parse_embedding(&val).unwrap();
        assert_eq!(emb.len(), 3);
    }
}
