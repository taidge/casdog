//! CASDOG_TEST_DATABASE_URL must point at an explicitly migrated disposable PostgreSQL.
use casdog::handlers::verification::{reset_email_or_phone, verify_code};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::json;
use sqlx::PgPool;

struct Identity {
    id: String,
    owner: String,
}
#[async_trait]
impl Handler for Identity {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.insert("user_id", self.id.clone());
        depot.insert("user_owner", self.owner.clone());
        ctrl.call_next(req, depot, res).await;
    }
}

#[tokio::test]
#[ignore = "requires explicitly migrated disposable PostgreSQL"]
async fn contact_change_rejects_other_user_tenant_purpose_expired_and_replayed_proofs() {
    let pg = PgPool::connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let org = format!("verification-{}", uuid::Uuid::new_v4().simple());
    let user = uuid::Uuid::new_v4().to_string();
    let other = uuid::Uuid::new_v4().to_string();
    let dest = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'Verification test')")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&org).execute(&pg).await.unwrap();
    for (id, name) in [(&user, "alice"), (&other, "bob")] {
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash) VALUES($1,$2,$3,$3,'unusable')")
            .bind(id).bind(&org).bind(name).execute(&pg).await.unwrap();
    }
    let service = Service::new(
        Router::with_path("api")
            .hoop(salvo::affix_state::AffixList::new().inject(pg.clone()))
            .hoop(Identity {
                id: user.clone(),
                owner: org.clone(),
            })
            .push(Router::with_path("reset-email-or-phone").post(reset_email_or_phone))
            .push(Router::with_path("verify-code").post(verify_code)),
    );
    for (index, owner, target, kind, age) in [
        (0, org.as_str(), other.as_str(), "contact:email", 0),
        (1, "other-tenant", user.as_str(), "contact:email", 0),
        (2, org.as_str(), user.as_str(), "email", 0),
        (3, org.as_str(), user.as_str(), "signup:email", 0),
        (4, org.as_str(), user.as_str(), "password-reset:email", 0),
        (5, org.as_str(), user.as_str(), "contact:email", 600),
        (6, org.as_str(), user.as_str(), "contact:phone", 0),
        (7, org.as_str(), user.as_str(), "contact:email", 0),
    ] {
        let code = format!("12345{index}");
        sqlx::query("INSERT INTO verifications(id,owner,name,type,user_id,provider,receiver,code,is_used,created_at) VALUES($1,$2,$1,$3,$4,'test',$5,$6,false,NOW()-make_interval(secs=>$7))")
            .bind(uuid::Uuid::new_v4().to_string()).bind(owner).bind(kind).bind(target).bind(&dest).bind(&code).bind(age as f64).execute(&pg).await.unwrap();
        let response = TestClient::post("http://localhost/api/reset-email-or-phone")
            .json(&json!({"type":"email","dest":dest,"code":code,"userId":other}))
            .send(&service)
            .await;
        assert_eq!(
            response.status_code.unwrap_or(StatusCode::OK),
            if index == 7 {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            },
            "proof case {index}"
        );
    }
    let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id=$1")
        .bind(&user)
        .fetch_one(&pg)
        .await
        .unwrap();
    assert_eq!(email.as_deref(), Some(dest.as_str()));
    let other_email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id=$1")
        .bind(&other)
        .fetch_one(&pg)
        .await
        .unwrap();
    assert!(other_email.is_none());
    let replay = TestClient::post("http://localhost/api/reset-email-or-phone")
        .json(&json!({"type":"email","dest":dest,"code":"123457"}))
        .send(&service)
        .await;
    assert_eq!(replay.status_code, Some(StatusCode::BAD_REQUEST));
    // A failed generic verification cannot burn another account's challenge.
    let mut response = TestClient::post("http://localhost/api/verify-code")
        .json(&json!({"type":"email","dest":dest,"code":"123450"}))
        .send(&service)
        .await;
    let result: serde_json::Value = response.take_json().await.unwrap();
    assert_eq!(result["success"], false);
    let used: bool = sqlx::query_scalar(
        "SELECT is_used FROM verifications WHERE user_id=$1 AND receiver=$2 AND code='123450'",
    )
    .bind(&other)
    .bind(&dest)
    .fetch_one(&pg)
    .await
    .unwrap();
    assert!(!used);
    let public = Service::new(
        Router::with_path("api/verify-code")
            .hoop(salvo::affix_state::AffixList::new().inject(pg.clone()))
            .post(verify_code),
    );
    let response = TestClient::post("http://localhost/api/verify-code")
        .json(&json!({"type":"email","dest":dest,"code":"123450"}))
        .send(&public)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    let nonce = "a".repeat(64);
    sqlx::query("INSERT INTO verifications(id,owner,name,type,user_id,provider,receiver,code,is_used) VALUES($1,$2,$1,'signup:email',$3,'test',$4,'234567',false)")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&org).bind(format!("signup:{nonce}")).bind(&dest).execute(&pg).await.unwrap();
    for (cookie, expected) in [
        (format!("casdog_signup_proof={}", "b".repeat(64)), false),
        (format!("casdog_signup_proof={nonce}"), true),
        (format!("casdog_signup_proof={nonce}"), false),
    ] {
        let mut response = TestClient::post("http://localhost/api/verify-code")
            .add_header("cookie", cookie, true)
            .json(&json!({"type":"email","dest":dest,"code":"234567"}))
            .send(&public)
            .await;
        let body: serde_json::Value = response.take_json().await.unwrap();
        assert_eq!(body["success"], expected);
    }
    sqlx::query("DELETE FROM verifications WHERE receiver=$1")
        .bind(&dest)
        .execute(&pg)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE owner=$1")
        .bind(&org)
        .execute(&pg)
        .await
        .unwrap();
    sqlx::query("DELETE FROM organizations WHERE name=$1")
        .bind(&org)
        .execute(&pg)
        .await
        .unwrap();
}
