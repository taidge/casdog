use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    models::CreatePricingRequest,
    services::{
        pricing_access_service::PricingAccessService as Access, pricing_service::PricingService,
    },
};
use jsonwebtoken::{EncodingKey, Header, encode};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

#[test]
fn invitation_rules_follow_current_usernames_and_never_treat_uuid_or_encoded_json_as_membership() {
    let user = json!({"id":"uuid-a","owner":"tenant","name":"Alice"});
    let mut pricing = json!({"owner":"tenant","is_invite_only":false,"users":[]});
    assert!(Access::allows_json(&pricing, None));
    pricing["is_invite_only"] = json!(true);
    assert!(!Access::allows_json(&pricing, None));
    assert!(Access::allows_json(&pricing, Some(&user)));
    assert!(!Access::allows_json(
        &pricing,
        Some(&json!({"owner":"other","name":"Alice"}))
    ));
    pricing["users"] = json!(["Alice", "future-user"]);
    assert!(Access::allows_json(&pricing, Some(&user)));
    for name in ["alice", "uuid-a", "tenant/Alice"] {
        assert!(!Access::allows_json(
            &pricing,
            Some(&json!({"owner":"tenant","name":name}))
        ));
    }
    for users in [
        Value::Null,
        json!("[]"),
        json!([null]),
        json!([42]),
        json!([""]),
    ] {
        pricing["users"] = users.clone();
        assert!(!Access::allows_json(&pricing, Some(&user)));
        let input = json!({"owner":"tenant","name":"p","display_name":"Pricing","isInviteOnly":true,"users":users});
        if users.as_array().is_some_and(|v| v == &vec![json!("")]) {
            let dto: CreatePricingRequest = serde_json::from_value(input).unwrap();
            assert!(Access::validate_users(&dto.users.unwrap()).is_err());
        } else {
            assert!(serde_json::from_value::<CreatePricingRequest>(input).is_err());
        }
    }
    assert!(
        serde_json::from_value::<CreatePricingRequest>(
            json!({"owner":"tenant","name":"p","display_name":"P","isInviteOnly":null})
        )
        .is_err()
    );
}
struct Fixture {
    pool: PgPool,
    service: Service,
    owner: String,
    other: String,
    admin: String,
    alice: String,
    bob: String,
}
impl Fixture {
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(create_diesel_pool(&url).await.unwrap()),
        );
        let owner = format!("pricing-access-{}", uuid::Uuid::new_v4());
        let other = format!("pricing-other-{}", uuid::Uuid::new_v4());
        let admin = uuid::Uuid::new_v4().to_string();
        let alice = uuid::Uuid::new_v4().to_string();
        let bob = uuid::Uuid::new_v4().to_string();
        for tenant in [&owner, &other] {
            sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'Pricing access')").bind(uuid::Uuid::new_v4().to_string()).bind(tenant).execute(&pool).await.unwrap();
        }
        for (id, name, is_admin) in [
            (&admin, "admin", true),
            (&alice, "Alice", false),
            (&bob, "Bob", false),
        ] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,$3,$3,'test-placeholder',$4)").bind(id).bind(&owner).bind(name).bind(is_admin).execute(&pool).await.unwrap();
        }
        Self {
            pool,
            service,
            owner,
            other,
            admin,
            alice,
            bob,
        }
    }
    fn token(&self) -> String {
        let now = chrono::Utc::now();
        encode(&Header::default(),&json!({"sub":self.admin,"owner":self.owner,"name":"admin","is_admin":true,"iat":now.timestamp(),"issued_at_ms":now.timestamp_millis(),"exp":now.timestamp()+3600,"iss":AppConfig::get().jwt.issuer}),&EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes())).unwrap()
    }
    async fn create(&self) -> String {
        let req:CreatePricingRequest=serde_json::from_value(json!({"owner":self.owner,"name":"private","display_name":"Private pricing","isInviteOnly":true,"users":["Alice","future-user"]})).unwrap();
        let pricing = PricingService::create(&self.pool, req).await.unwrap();
        assert!(pricing.is_invite_only);
        assert_eq!(pricing.users, vec!["Alice", "future-user"]);
        pricing.id
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL migrated through 044"]
async fn pricing_fields_roundtrip_and_current_access_revokes_on_name_account_or_pricing_changes_with_one_connection()
 {
    let f = Fixture::new().await;
    let id = f.create().await;
    {
        let mut tx = f.pool.begin().await.unwrap();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            Access::ensure_allowed_conn(&mut tx, &id, &f.alice, &f.owner),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(outcome.users, vec!["Alice", "future-user"]);
        assert!(
            Access::ensure_allowed_conn(&mut tx, &id, &f.bob, &f.owner)
                .await
                .is_err()
        );
        tx.commit().await.unwrap();
    }
    sqlx::query("UPDATE users SET name='Renamed' WHERE id=$1")
        .bind(&f.alice)
        .execute(&f.pool)
        .await
        .unwrap();
    {
        let mut conn = f.pool.acquire().await.unwrap();
        assert!(
            Access::ensure_allowed_conn(&mut conn, &id, &f.alice, &f.owner)
                .await
                .is_err()
        );
    }
    sqlx::query("UPDATE pricings SET users='[]' WHERE id=$1")
        .bind(&id)
        .execute(&f.pool)
        .await
        .unwrap();
    {
        let mut conn = f.pool.acquire().await.unwrap();
        Access::ensure_allowed_conn(&mut conn, &id, &f.bob, &f.owner)
            .await
            .unwrap();
        assert!(
            Access::ensure_allowed_conn(&mut conn, &id, &f.bob, &f.other)
                .await
                .is_err()
        );
    }
    sqlx::query("UPDATE users SET is_forbidden=true WHERE id=$1")
        .bind(&f.bob)
        .execute(&f.pool)
        .await
        .unwrap();
    {
        let mut conn = f.pool.acquire().await.unwrap();
        assert!(
            Access::ensure_allowed_conn(&mut conn, &id, &f.bob, &f.owner)
                .await
                .is_err()
        );
    }
    sqlx::query("UPDATE pricings SET is_enabled=false WHERE id=$1")
        .bind(&id)
        .execute(&f.pool)
        .await
        .unwrap();
    {
        let mut conn = f.pool.acquire().await.unwrap();
        assert!(
            Access::ensure_allowed_conn(&mut conn, &id, &f.alice, &f.owner)
                .await
                .is_err()
        );
    }
    let updated = PricingService::update(
        &f.pool,
        &id,
        serde_json::from_value(json!({"isInviteOnly":true,"users":["Renamed"],"is_enabled":true}))
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(updated.is_invite_only);
    assert_eq!(updated.users, vec!["Renamed"]);
    let preserved = PricingService::update(
        &f.pool,
        &id,
        serde_json::from_value(json!({"display_name":"Renamed pricing"})).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(preserved.users, vec!["Renamed"]);
    let cleared = PricingService::update(
        &f.pool,
        &id,
        serde_json::from_value(json!({"users":[],"isInviteOnly":false})).unwrap(),
    )
    .await
    .unwrap();
    assert!(!cleared.is_invite_only);
    assert!(cleared.users.is_empty());
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL migrated through 044"]
async fn native_and_legacy_pricing_crud_validate_whitelist_shape_without_requiring_future_users_to_exist()
 {
    let f = Fixture::new().await;
    let mut response=TestClient::post("http://localhost/api/pricings").bearer_auth(f.token()).json(&json!({"owner":f.owner,"name":"native","display_name":"Native","isInviteOnly":true,"users":["Alice","not-registered-yet"]})).send(&f.service).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let native: Value = response.take_json().await.unwrap();
    assert_eq!(native["users"], json!(["Alice", "not-registered-yet"]));
    let mut legacy=TestClient::post("http://localhost/api/add-pricing").bearer_auth(f.token()).json(&json!({"owner":f.owner,"name":"legacy","displayName":"Legacy","isInviteOnly":true,"users":["Bob","another-future-user"]})).send(&f.service).await;
    assert_eq!(legacy.status_code, Some(StatusCode::OK));
    let _: Value = legacy.take_json().await.unwrap();
    let mut get = TestClient::get(format!(
        "http://localhost/api/get-pricing?id={}/legacy",
        f.owner
    ))
    .bearer_auth(f.token())
    .send(&f.service)
    .await;
    let value: Value = get.take_json().await.unwrap();
    assert_eq!(value["data"]["isInviteOnly"], true);
    assert_eq!(
        value["data"]["users"],
        json!(["Bob", "another-future-user"])
    );
    for (index, users) in [
        Value::Null,
        json!("[\"Alice\"]"),
        json!([null]),
        json!([1]),
        json!([""]),
    ]
    .into_iter()
    .enumerate()
    {
        for path in ["/api/pricings", "/api/add-pricing"] {
            let response=TestClient::post(format!("http://localhost{path}")).bearer_auth(f.token()).json(&json!({"owner":f.owner,"name":format!("bad-{index}"),"display_name":"Bad","isInviteOnly":true,"users":users})).send(&f.service).await;
            assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        }
    }
    let id = f.create().await;
    for value in [
        json!(null),
        json!("[]"),
        json!([false]),
        json!([""]),
        json!(["x".repeat(101)]),
    ] {
        let result = sqlx::query("UPDATE pricings SET users=$2 WHERE id=$1")
            .bind(&id)
            .bind(value)
            .execute(&f.pool)
            .await;
        assert!(result.is_err());
    }
}
