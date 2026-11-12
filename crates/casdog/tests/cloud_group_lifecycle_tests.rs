//! Normal Group DELETE must retract its tenant-local JSON and managed ledgers.
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    models::{User, UserResponse},
    services::{AuthService, UserService},
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

struct Fixture {
    pool: PgPool,
    service: Service,
    owner: String,
    foreign: String,
    admin: String,
    token: String,
}
impl Fixture {
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let owner = format!("group-delete-{}", uuid::Uuid::new_v4().simple());
        let foreign = format!("group-foreign-{}", uuid::Uuid::new_v4().simple());
        sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin','built-in','Built in') ON CONFLICT(name) DO NOTHING").bind(uuid::Uuid::new_v4().to_string()).execute(&pool).await.unwrap();
        for org in [&owner, &foreign] {
            sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,'Group delete')").bind(uuid::Uuid::new_v4().to_string()).bind(org).execute(&pool).await.unwrap();
        }
        let admin = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,'built-in',$2,'Group delete administrator','fixture',true)").bind(&admin).bind(format!("group-admin-{}",uuid::Uuid::new_v4().simple())).execute(&pool).await.unwrap();
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id=$1")
            .bind(&admin)
            .fetch_one(&pool)
            .await
            .unwrap();
        let token = AuthService::new(UserService::new(diesel.clone()))
            .generate_token(&UserResponse::from(user))
            .unwrap();
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel),
        );
        Self {
            pool,
            service,
            owner,
            foreign,
            admin,
            token,
        }
    }
    async fn group(&self, name: &str) -> String {
        let mut response = TestClient::post("http://localhost/api/groups")
            .bearer_auth(&self.token)
            .json(&json!({"owner":self.owner,"name":name,"display_name":name}))
            .send(&self.service)
            .await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{body}");
        body["id"].as_str().unwrap().into()
    }
    async fn user(&self, owner: &str, name: &str, groups: &Value) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,groups) VALUES($1,$2,$3,$3,'fixture',$4)").bind(&id).bind(owner).bind(name).bind(groups).execute(&self.pool).await.unwrap();
        id
    }
    async fn groups(&self, id: &str) -> Value {
        sqlx::query_scalar("SELECT groups FROM users WHERE id=$1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn delete(&self, id: &str) -> Response {
        TestClient::delete(format!("http://localhost/api/groups/{id}"))
            .bearer_auth(&self.token)
            .send(&self.service)
            .await
    }
    async fn pair(&self, user: &str, group: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO user_groups(id,user_id,group_id) VALUES($1,$2,$3)")
            .bind(&id)
            .bind(user)
            .bind(group)
            .execute(&self.pool)
            .await
            .unwrap();
        id
    }
    async fn cleanup(self) {
        sqlx::query("DELETE FROM syncers WHERE owner=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM groups WHERE owner=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE owner=$1 OR owner=$2 OR id=$3")
            .bind(&self.owner)
            .bind(&self.foreign)
            .bind(&self.admin)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE name=$1 OR name=$2")
            .bind(&self.owner)
            .bind(&self.foreign)
            .execute(&self.pool)
            .await
            .unwrap();
    }
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL migrated through cloud group ledgers"]
async fn managed_group_delete_waits_for_syncer_then_cleans_manual_managed_json_and_cascades_ledgers()
 {
    let f = Fixture::new().await;
    let group = f.group("managed-team").await;
    let keep = f.group("keep-team").await;
    let qualified = format!("{}/managed-team", f.owner);
    let keep_value = format!("{}/keep-team", f.owner);
    let foreign_value = format!("{}/managed-team", f.foreign);
    let first = f
        .user(
            &f.owner,
            "managed-member",
            &json!([
                qualified,
                "managed-team",
                keep_value,
                foreign_value,
                "managed-team"
            ]),
        )
        .await;
    let manual = f
        .user(
            &f.owner,
            "manual-member",
            &json!([qualified, "managed-team", keep_value]),
        )
        .await;
    let json_only = f
        .user(
            &f.owner,
            "json-only",
            &json!([qualified, "managed-team", keep_value]),
        )
        .await;
    let malformed = json!({qualified.clone():true,"unrelated":[1,2]});
    let legacy = f.user(&f.owner, "legacy-object", &malformed).await;
    let foreign_json = json!([qualified, "managed-team", foreign_value]);
    let foreign = f.user(&f.foreign, "foreign-member", &foreign_json).await;
    let syncer = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO syncers(id,owner,name,organization,type,host,port,\"user\",password,is_read_only,is_enabled) VALUES($1,$2,'directory',$2,'Google Workspace','admin@directory.test',443,'service@directory.test','fixture',true,true)").bind(&syncer).bind(&f.owner).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO syncer_group_links(syncer_id,source_key,organization,group_id,group_name,remote_email) VALUES($1,'remote-group',$2,$3,'managed-team','team@directory.test')").bind(&syncer).bind(&f.owner).bind(&group).execute(&f.pool).await.unwrap();
    for (index, user, manual_preserved) in
        [(0, &first, false), (1, &manual, true), (2, &legacy, false)]
    {
        let pair = f.pair(user, &group).await;
        sqlx::query("INSERT INTO syncer_group_memberships(syncer_id,source_group_key,source_user_key,user_id,group_id,user_group_id,group_value,owns_user_group,owns_user_group_value,manual_preserved) VALUES($1,'remote-group',$2,$3,$4,$5,$6,true,true,$7)").bind(&syncer).bind(format!("remote-{index}")).bind(user).bind(&group).bind(&pair).bind(&qualified).bind(manual_preserved).execute(&f.pool).await.unwrap();
    }
    let response = {
        let mut running = f.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM syncers WHERE id=$1 FOR UPDATE")
            .bind(&syncer)
            .fetch_one(&mut *running)
            .await
            .unwrap();
        let deletion = f.delete(&group);
        tokio::pin!(deletion);
        tokio::select! {response=&mut deletion=>panic!("Group DELETE must wait for active Syncer, got {:?}",response.status_code),_=tokio::time::sleep(Duration::from_millis(200))=>{}}
        // A waiting delete must not hold Group or User locks in the reverse order.
        let mut probe = f.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM groups WHERE id=$1 FOR UPDATE NOWAIT")
            .bind(&group)
            .fetch_one(&mut *probe)
            .await
            .unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE NOWAIT")
            .bind(&first)
            .fetch_one(&mut *probe)
            .await
            .unwrap();
        probe.rollback().await.unwrap();
        running.commit().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), &mut deletion)
            .await
            .expect("normal delete must complete without a lock-order deadlock")
    };
    assert_eq!(response.status_code, Some(StatusCode::NO_CONTENT));
    assert_eq!(f.groups(&first).await, json!([keep_value, foreign_value]));
    assert_eq!(f.groups(&manual).await, json!([keep_value]));
    assert_eq!(f.groups(&json_only).await, json!([keep_value]));
    assert_eq!(f.groups(&legacy).await, malformed);
    assert_eq!(f.groups(&foreign).await, foreign_json);
    for table in [
        "user_groups",
        "syncer_group_links",
        "syncer_group_memberships",
    ] {
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE group_id=$1"))
                .bind(&group)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(count, 0, "{table} must cascade");
    }
    assert!(sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM groups WHERE id=$1) AND EXISTS(SELECT 1 FROM syncers WHERE id=$2)").bind(&keep).bind(&syncer).fetch_one(&f.pool).await.unwrap());
    // A later source-created group cannot inherit orphaned qualified references.
    let recreated = f.group("managed-team-next-run").await;
    assert_ne!(recreated, group);
    assert!(
        !f.groups(&first)
            .await
            .as_array()
            .unwrap()
            .contains(&json!(qualified))
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL migrated through cloud group ledgers"]
async fn ordinary_group_delete_cleans_only_matching_strings_and_preserves_foreign_and_unknown_json()
{
    let f = Fixture::new().await;
    let group = f.group("local-team").await;
    let qualified = format!("{}/local-team", f.owner);
    let foreign_qualified = format!("{}/local-team", f.foreign);
    let content = json!([qualified,"local-team","different-team",foreign_qualified,{"nested":"local-team"},42,null]);
    let user = f.user(&f.owner, "local-member", &content).await;
    f.pair(&user, &group).await;
    let foreign_json = json!([qualified, "local-team", foreign_qualified]);
    let foreign = f.user(&f.foreign, "foreign-member", &foreign_json).await;
    let object = json!({qualified.clone():"legacy","other":17});
    let malformed = f.user(&f.owner, "legacy-object", &object).await;
    let scalar = f
        .user(&f.owner, "legacy-scalar", &json!("local-team"))
        .await;
    assert_eq!(
        f.delete(&group).await.status_code,
        Some(StatusCode::NO_CONTENT)
    );
    assert_eq!(
        f.groups(&user).await,
        json!(["different-team",foreign_qualified,{"nested":"local-team"},42,null])
    );
    assert_eq!(f.groups(&foreign).await, foreign_json);
    assert_eq!(f.groups(&malformed).await, object);
    assert_eq!(f.groups(&scalar).await, json!("local-team"));
    f.cleanup().await;
}
