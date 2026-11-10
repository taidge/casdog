//! Shared PostgreSQL OAuth state: separate pools represent independent server instances.
//! Explicitly run with CASDOG_TEST_DATABASE_URL and migrations 001-019, --ignored.
use casdog::services::social_state_service::*;
use serde_json::json;
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

struct Fixture {
    first: PgPool,
    second: PgPool,
    url: String,
    owner: String,
    provider: String,
    app: String,
    user: String,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("CASDOG_TEST_DATABASE_URL")
            .expect("Set disposable migrated test database URL");
        let first = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let second = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let owner = format!("state-{}", Uuid::new_v4());
        let provider = Uuid::new_v4().to_string();
        let app = Uuid::new_v4().to_string();
        let user = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'Shared state test')")
            .bind(Uuid::new_v4().to_string()).bind(&owner).execute(&first).await.unwrap();
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type) VALUES($1,$2,'provider','Provider','OAuth','Custom')")
            .bind(&provider).bind(&owner).execute(&first).await.unwrap();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris) VALUES($1,$2,'app','App',$2,$1,'test','https://client.example/callback')")
            .bind(&app).bind(&owner).execute(&first).await.unwrap();
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash) VALUES($1,$2,'alice','Alice','unused')")
            .bind(&user).bind(&owner).execute(&first).await.unwrap();
        Self {
            first,
            second,
            url,
            owner,
            provider,
            app,
            user,
        }
    }

    fn flow(&self) -> NewOAuthFlow {
        NewOAuthFlow {
            provider_id: self.provider.clone(),
            provider_name: "provider".into(),
            application_id: self.app.clone(),
            organization: self.owner.clone(),
            redirect_uri: "http://127.0.0.1:8000/api/auth/provider/callback".into(),
            purpose: "signin".into(),
            context: json!({"test":"cross-instance"}),
        }
    }

    fn completion(&self) -> NewCompletion {
        NewCompletion {
            user_id: self.user.clone(),
            provider_id: self.provider.clone(),
            provider_name: "provider".into(),
            application_id: self.app.clone(),
            organization: self.owner.clone(),
            context: json!({"test":"mfa"}),
        }
    }

    async fn cleanup(self) {
        for table in ["applications", "providers", "users", "organizations"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE owner=$1"))
                .bind(&self.owner)
                .execute(&self.second)
                .await
                .unwrap();
        }
        self.first.close().await;
        self.second.close().await;
    }
}

#[test]
fn persisted_proof_is_sha256_and_never_the_raw_secret() {
    assert_eq!(
        proof_hash("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-019"]
async fn oauth_flow_survives_instance_restart_and_is_bound_to_browser_provider() {
    let f = Fixture::new().await;
    let (state, browser) = create_flow(&f.first, &f.flow()).await.unwrap();
    assert_eq!(state.len(), 43);
    assert_eq!(browser.len(), 43);
    assert_ne!(state, browser);
    let stored: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(t) FROM social_oauth_flows t WHERE state_hash=$1")
            .bind(proof_hash(&state))
            .fetch_one(&f.second)
            .await
            .unwrap();
    assert!(!stored.to_string().contains(&state));
    assert!(!stored.to_string().contains(&browser));
    assert_eq!(stored["browser_hash"], proof_hash(&browser));
    assert!(
        consume_flow(&f.second, &state, &"a".repeat(43), "provider")
            .await
            .is_err()
    );
    assert!(
        consume_flow(&f.second, &state, &browser, "different-provider")
            .await
            .is_err()
    );
    f.first.close().await; // no in-process cache can survive a closed originating instance
    let restarted = PgPoolOptions::new()
        .max_connections(2)
        .connect(&f.url)
        .await
        .unwrap();
    let flow = consume_flow(&restarted, &state, &browser, "provider")
        .await
        .unwrap();
    assert_eq!(flow.application_id, f.app);
    assert_eq!(flow.organization, f.owner);
    assert_eq!(flow.context["test"], "cross-instance");
    assert!((flow.expires_at - flow.created_at).num_seconds() <= 300);
    assert!(
        consume_flow(&f.second, &state, &browser, "provider")
            .await
            .is_err()
    );
    restarted.close().await;
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-019"]
async fn oauth_flow_concurrent_callback_has_one_winner_and_expired_flow_is_rejected() {
    let f = Fixture::new().await;
    let (state, browser) = create_flow(&f.first, &f.flow()).await.unwrap();
    let (a, b) = tokio::join!(
        consume_flow(&f.first, &state, &browser, "provider"),
        consume_flow(&f.second, &state, &browser, "provider")
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let (expired, browser) = create_flow(&f.first, &f.flow()).await.unwrap();
    sqlx::query(
        "UPDATE social_oauth_flows SET expires_at=NOW()-INTERVAL '1 second' WHERE state_hash=$1",
    )
    .bind(proof_hash(&expired))
    .execute(&f.second)
    .await
    .unwrap();
    assert!(
        consume_flow(&f.first, &expired, &browser, "provider")
            .await
            .is_err()
    );
    let _new = create_flow(&f.second, &f.flow()).await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM social_oauth_flows WHERE state_hash=$1")
            .bind(proof_hash(&expired))
            .fetch_one(&f.second)
            .await
            .unwrap();
    assert_eq!(
        count, 0,
        "Creation removes expired state shared by all instances"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-019"]
async fn shared_completion_consumption_expiry_and_failed_attempt_budget() {
    let f = Fixture::new().await;
    let secret = create_completion(&f.first, &f.completion()).await.unwrap();
    let loaded = load_completion(&f.second, &secret).await.unwrap();
    assert_eq!(loaded.user_id, f.user);
    let (a, b) = tokio::join!(
        consume_completion(&f.first, &secret),
        consume_completion(&f.second, &secret)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(load_completion(&f.first, &secret).await.is_err());
    let limited = create_completion(&f.first, &f.completion()).await.unwrap();
    for attempts in 1..=MAX_COMPLETION_ATTEMPTS {
        record_failure(&f.second, &limited).await.unwrap();
        if attempts < MAX_COMPLETION_ATTEMPTS {
            assert_eq!(
                load_completion(&f.first, &limited).await.unwrap().attempts,
                attempts
            );
        }
    }
    assert!(load_completion(&f.first, &limited).await.is_err());
    assert!(consume_completion(&f.second, &limited).await.is_err());
    assert!(record_failure(&f.first, &limited).await.is_err());
    let expired = create_completion(&f.first, &f.completion()).await.unwrap();
    sqlx::query("UPDATE social_oauth_completions SET expires_at=NOW()-INTERVAL '1 second' WHERE secret_hash=$1")
        .bind(proof_hash(&expired)).execute(&f.second).await.unwrap();
    assert!(load_completion(&f.first, &expired).await.is_err());
    assert!(consume_completion(&f.second, &expired).await.is_err());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-019"]
async fn completion_proof_updates_and_consumption_follow_caller_transaction() {
    let f = Fixture::new().await;
    let secret = create_completion(&f.first, &f.completion()).await.unwrap();
    let mut tx = f.first.begin().await.unwrap();
    let loaded = load_completion_for_update(&mut tx, &secret).await.unwrap();
    assert_eq!(loaded.attempts, 0);
    record_failure_conn(&mut tx, &secret).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(
        load_completion(&f.second, &secret).await.unwrap().attempts,
        0
    );
    let mut tx = f.first.begin().await.unwrap();
    load_completion_for_update(&mut tx, &secret).await.unwrap();
    consume_completion_conn(&mut tx, &secret).await.unwrap();
    tx.rollback().await.unwrap();
    assert!(load_completion(&f.second, &secret).await.is_ok());
    let mut tx = f.second.begin().await.unwrap();
    load_completion_for_update(&mut tx, &secret).await.unwrap();
    consume_completion_conn(&mut tx, &secret).await.unwrap();
    tx.commit().await.unwrap();
    assert!(load_completion(&f.first, &secret).await.is_err());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-019"]
async fn shared_capacity_limit_cannot_be_bypassed_by_another_instance() {
    let f = Fixture::new().await;
    sqlx::query("INSERT INTO social_oauth_flows(state_hash,browser_hash,provider_id,provider_name,application_id,organization,redirect_uri,purpose) SELECT md5($1 || i::text),md5(i::text),$2,'provider',$3,$1,'https://example.test/callback','signin' FROM generate_series(1,1024) AS i")
        .bind(&f.owner).bind(&f.provider).bind(&f.app).execute(&f.first).await.unwrap();
    assert!(create_flow(&f.second, &f.flow()).await.is_err());
    sqlx::query(
        "UPDATE social_oauth_flows SET expires_at=NOW()-INTERVAL '1 second' WHERE organization=$1",
    )
    .bind(&f.owner)
    .execute(&f.second)
    .await
    .unwrap();
    assert!(create_flow(&f.first, &f.flow()).await.is_ok());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-019"]
async fn logout_waits_for_user_lock_then_commits_revocation_and_epoch_together() {
    use casdog::services::auth_service::AuthService;
    use std::time::Duration;

    let f = Fixture::new().await;
    let secret = create_completion(&f.first, &f.completion()).await.unwrap();
    let pending = load_completion(&f.second, &secret).await.unwrap();
    let fingerprint = proof_hash(&format!("session-{}", Uuid::new_v4()));
    let expires_at = chrono::Utc::now().timestamp() + 3600;
    sqlx::query("INSERT INTO tokens(id,owner,name,application,organization,user_id,access_token) VALUES($1,$2,'old-token','app',$2,$3,$1)")
        .bind(Uuid::new_v4().to_string()).bind(&f.owner).bind(&f.user).execute(&f.first).await.unwrap();
    sqlx::query("INSERT INTO sessions(id,owner,name,application,user_id,session_id) VALUES($1,$2,'old-session','app',$3,$1)")
        .bind(Uuid::new_v4().to_string()).bind(&f.owner).bind(&f.user).execute(&f.first).await.unwrap();

    // Simulate a binding/completion transaction holding the common user lock.
    let mut binding = f.first.begin().await.unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *binding)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(&f.user)
        .execute(&mut *binding)
        .await
        .unwrap();
    let logout_pool = f.second.clone();
    let logout_user = f.user.clone();
    let logout_fingerprint = fingerprint.clone();
    let logout = tokio::spawn(async move {
        AuthService::logout_session(
            &logout_pool,
            &logout_user,
            Some((&logout_fingerprint, expires_at)),
        )
        .await
    });

    // Observe a real database lock wait, rather than assuming a scheduled task
    // reached the lock merely because a short timer elapsed.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
            ).bind(blocker_pid).fetch_one(&f.first).await.unwrap();
            if blocked { break; }
            assert!(!logout.is_finished(), "Logout bypassed the user row lock");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("Logout should wait for the binding transaction's user lock");

    let snapshot = "SELECT EXISTS(SELECT 1 FROM revoked_session_tokens WHERE token_hash=$1), \
        EXISTS(SELECT 1 FROM user_session_epochs WHERE user_id=$2), \
        (SELECT COUNT(*) FROM tokens WHERE user_id=$2), \
        (SELECT COUNT(*) FROM sessions WHERE user_id=$2)";
    let before: (bool, bool, i64, i64) = sqlx::query_as(snapshot)
        .bind(&fingerprint)
        .bind(&f.user)
        .fetch_one(&f.first)
        .await
        .unwrap();
    assert_eq!(before, (false, false, 1, 1));
    assert!(!logout.is_finished());
    let released_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *binding)
        .await
        .unwrap();
    binding.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), logout)
        .await
        .expect("Logout should finish after the user lock is released")
        .unwrap()
        .unwrap();

    // One statement observes one committed snapshot of all four effects.
    let after: (bool, bool, i64, i64) = sqlx::query_as(snapshot)
        .bind(&fingerprint)
        .bind(&f.user)
        .fetch_one(&f.first)
        .await
        .unwrap();
    assert_eq!(after, (true, true, 0, 0));
    let cutoff: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT invalid_before FROM user_session_epochs WHERE user_id=$1")
            .bind(&f.user)
            .fetch_one(&f.first)
            .await
            .unwrap();
    assert!(
        cutoff >= released_at,
        "Epoch must use the time after acquiring the user lock"
    );
    assert!(
        pending.created_at <= cutoff,
        "The pending OAuth proof predates logout and must be rejected by session policy"
    );
    let stored_expiry: i64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM expires_at)::bigint FROM revoked_session_tokens WHERE token_hash=$1",
    ).bind(&fingerprint).fetch_one(&f.first).await.unwrap();
    assert_eq!(stored_expiry, expires_at);
    f.cleanup().await;
}
