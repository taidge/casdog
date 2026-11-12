//! Explicit, real global review for disposable loopback delivery fixtures.
pub async fn approve_owner(pool: &sqlx::PgPool, owner: &str) {
    use casdog::{hoops::authz::Principal, models::Provider, services::provider_network_service};
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,'built-in',$1,'Fixture network reviewer','unused',true)")
        .bind(&id).execute(pool).await.unwrap();
    let actor = Principal {
        id: id.clone(),
        owner: "built-in".into(),
        name: id.clone(),
        admin: true,
        application_identity: false,
    };
    let providers: Vec<Provider> = sqlx::query_as("SELECT * FROM providers WHERE owner=$1")
        .bind(owner)
        .fetch_all(pool)
        .await
        .unwrap();
    for record in providers {
        if casdog::services::providers::http_delivery::is_custom_http(&record) {
            provider_network_service::approve(pool, &actor, &record.id)
                .await
                .unwrap();
        }
    }
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}
