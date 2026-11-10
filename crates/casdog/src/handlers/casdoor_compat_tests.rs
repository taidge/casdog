use super::*;
use salvo::test::{ResponseExt, TestClient};

#[handler]
async fn admin_identity(depot: &mut Depot) {
    depot.insert("user_owner", "built-in".to_string());
    depot.insert("user_name", "admin".to_string());
    depot.insert("is_admin", true);
}

fn columns() -> HashSet<String> {
    [
        "id",
        "name",
        "display_name",
        "created_at",
        "password_hash",
        "properties",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[test]
fn legacy_list_honors_casdoor_search_sort_and_pagination() {
    let req = TestClient::get("http://localhost/api/get-users?field=displayName&value=Alice&sortField=createdTime&sortOrder=descend&pageSize=10&p=3").build();
    let options = ListOptions::from_request(&req, &columns()).unwrap();
    assert_eq!(
        options.search,
        Some(("display_name".into(), "Alice".into()))
    );
    assert_eq!(options.sort_column.as_deref(), Some("created_at"));
    assert!(options.descending);
    assert_eq!(options.pagination, Some((10, 20)));
    let mut query = QueryBuilder::<Postgres>::new("SELECT * FROM users WHERE TRUE");
    options.append_search(&mut query);
    assert_eq!(
        query.sql(),
        "SELECT * FROM users WHERE TRUE AND CAST(\"display_name\" AS TEXT) LIKE $1"
    );
}

#[test]
fn legacy_list_rejects_bad_identifiers_secrets_and_overflow() {
    for query in [
        "field=name%3BDROP%20TABLE%20users&value=x",
        "field=passwordHash&value=hash",
        "sortField=passwordHash",
        "sortField=nonexistent",
        "sortOrder=DESC%3BDROP",
        "pageSize=-1",
        "pageSize=10&p=0",
        "pageSize=9223372036854775807&p=3",
        "pageSize=invalid",
    ] {
        let req = TestClient::get(format!("http://localhost/api/get-users?{query}")).build();
        assert!(
            ListOptions::from_request(&req, &columns()).is_err(),
            "{query}"
        );
    }
}

#[test]
fn legacy_user_responses_mask_credentials_and_preserve_custom_keys() {
    let data = resource_response(
        USERS,
        json!([{
            "name": "alice", "password_hash": "real-hash", "password_salt": "salt",
            "totp_secret": "totp", "recovery_codes": ["secret"], "original_token": "token",
            "managed_accounts": [{"password": "external-secret"}],
            "mfa_accounts": [{"secret_key": "mfa-secret"}],
            "properties": {"my_custom_key": "value", "oauth_github_accessToken": "token"}
        }]),
    );
    let user = &data[0];
    assert_eq!(user["password"], "***");
    for field in [
        "passwordHash",
        "passwordSalt",
        "totpSecret",
        "recoveryCodes",
        "originalToken",
    ] {
        assert!(user.get(field).is_none(), "{field}");
    }
    assert_eq!(user["managedAccounts"][0]["password"], "***");
    assert_eq!(user["mfaAccounts"][0]["secretKey"], "***");
    assert_eq!(user["properties"]["my_custom_key"], "value");
    assert_eq!(user["properties"]["oauth_github_accessToken"], "***");
}

#[test]
fn legacy_masked_password_roundtrip_does_not_replace_hash() {
    let data = prepare_body(
        USERS,
        json!({"name": "alice", "password": "***"}),
        &columns(),
    )
    .unwrap();
    assert!(!data.contains_key("password_hash"));
    assert!(!data.contains_key("password"));
}

#[tokio::test]
async fn legacy_policy_endpoints_accept_casdoor_arrays() {
    let router = Router::new().push(Router::with_path("api").push(routes()));
    let service = Service::new(router).hoop(admin_identity);
    let mut response = TestClient::post("http://localhost/api/add-policy")
        .json(&json!(["p", "parity-user", "parity-object", "read"]))
        .send(&service)
        .await;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["code"], 500, "{body}");
    let mut response = TestClient::get("http://localhost/api/get-policies")
        .send(&service)
        .await;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["code"], 500, "{body}");
    let policy = policy_from_value(&json!(["p", "parity-user", "parity-object", "read"])).unwrap();
    assert_eq!(
        (
            policy.ptype.as_str(),
            policy.v0.as_str(),
            policy.v1.as_str(),
            policy.v2.as_str()
        ),
        ("p", "parity-user", "parity-object", "read")
    );
}

#[tokio::test]
async fn legacy_access_is_tenant_scoped_and_self_updates_cannot_escalate() {
    let mut depot = Depot::new();
    depot.insert("user_owner", "tenant-a".to_string());
    depot.insert("user_name", "alice".to_string());
    depot.insert("user_id", "alice-id".to_string());
    depot.insert("is_admin", false);
    let req = TestClient::post("http://localhost/api/update-user?id=tenant-a/alice").build();
    let own = json!({"owner": "tenant-a", "name": "alice", "id": "alice-id"});
    assert!(
        authorize_legacy_object(&depot, &req, USERS, &own, "update")
            .await
            .unwrap()
    );
    assert!(validate_self_update(&json!({"display_name": "Alice"})).is_ok());
    assert!(validate_self_update(&json!({"is_admin": true})).is_err());
    assert!(validate_self_update(&json!({"password_hash": "known"})).is_err());
    assert!(
        authorize_legacy_object(
            &depot,
            &req,
            USERS,
            &json!({"owner": "tenant-a", "name": "bob"}),
            "update"
        )
        .await
        .is_err()
    );
    depot.insert("is_admin", true);
    assert!(
        authorize_legacy_object(
            &depot,
            &req,
            USERS,
            &json!({"owner": "tenant-b", "name": "bob"}),
            "update"
        )
        .await
        .is_err()
    );
    assert!(
        authorize_legacy_object(&depot, &req, USERS, &own, "update")
            .await
            .is_ok()
    );
    depot.insert("user_owner", "built-in".to_string());
    assert!(
        authorize_legacy_object(
            &depot,
            &req,
            USERS,
            &json!({"owner": "tenant-b", "name": "bob"}),
            "update"
        )
        .await
        .is_ok()
    );
}
