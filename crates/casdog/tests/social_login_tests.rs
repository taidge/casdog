//! End-to-end browser OAuth regressions with a local HTTP IdP and disposable PostgreSQL.
//! CASDOG_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:55489/casdog_parity
//! cargo test -p casdog --test social_login_tests -- --ignored
use casdog::{config::AppConfig, diesel_pool::create_diesel_pool, handlers::social_login::*};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn mock_provider() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0; 4096];
                    let count = stream.read(&mut chunk).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..count]);
                    if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                let (key, value) = line.split_once(':')?;
                                key.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(request).unwrap();
                let body = if request.starts_with("POST /token ") {
                    assert!(request.contains("code=good-code"));
                    assert!(request.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2Fapi%2Fauth%2F"));
                    json!({"access_token":"mock-access-token"})
                } else {
                    assert!(request.starts_with("GET /userinfo "));
                    assert!(request.to_lowercase().contains("authorization: bearer mock-access-token"));
                    json!({"sub":"subject-123", "preferred_username":"alice", "name":"Alice", "email":"unverified@example.test"})
                }.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            });
        }
    });
    (origin, task)
}

fn response_cookie(response: &Response, prefix: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find(|h| h.starts_with(prefix))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn start(service: &Service, app: &str, provider: &str) -> (String, String) {
    let mut response = TestClient::get(format!(
        "http://localhost/api/auth/{provider}?application={app}"
    ))
    .send(service)
    .await;
    assert_eq!(
        response.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        response.take_string().await.unwrap_or_default()
    );
    let cookie = response_cookie(&response, "casdog_oauth_browser=");
    assert!(
        response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("HttpOnly")
    );
    let body: Value = response.take_json().await.unwrap();
    let url = reqwest::Url::parse(body["url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .to_string();
    assert!(state.len() >= 43);
    (state, cookie)
}

#[tokio::test]
#[ignore = "requires explicitly migrated disposable PostgreSQL"]
async fn social_browser_flow_is_scoped_single_use_and_does_not_link_claimed_email() {
    AppConfig::load().unwrap();
    let url = std::env::var("CASDOG_TEST_DATABASE_URL").expect("set disposable DB URL");
    let pg = PgPool::connect(&url).await.unwrap();
    let diesel = create_diesel_pool(&url).await.unwrap();
    let (idp, mock) = mock_provider().await;
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let org = format!("social-{suffix}");
    let org_b = format!("social-b-{suffix}");
    let provider = format!("mock-{suffix}");
    let provider_id = uuid::Uuid::new_v4().to_string();
    let app_a = uuid::Uuid::new_v4().to_string();
    let app_b = uuid::Uuid::new_v4().to_string();
    let existing_id = uuid::Uuid::new_v4().to_string();
    for owner in [&org, &org_b] {
        sqlx::query("INSERT INTO organizations(id, owner, name, display_name) VALUES ($1, $2, $2, 'Social test')")
            .bind(uuid::Uuid::new_v4().to_string()).bind(owner).execute(&pg).await.unwrap();
    }
    sqlx::query("INSERT INTO providers(id, owner, name, display_name, category, type, client_id, client_secret, custom_auth_url, custom_token_url, custom_user_info_url) VALUES($1, $2, $3, 'Mock', 'OAuth', 'Mock', 'client', 'never-disclose-this-secret', $4, $5, $6)")
        .bind(&provider_id).bind(&org).bind(&provider).bind(format!("{idp}/authorize")).bind(format!("{idp}/token")).bind(format!("{idp}/userinfo")).execute(&pg).await.unwrap();
    for (id, owner) in [(&app_a, &org), (&app_b, &org_b)] {
        sqlx::query("INSERT INTO applications(id, owner, name, display_name, organization, enable_idp_signup, providers, client_id, client_secret, redirect_uris) VALUES($1, $2, 'social-app', 'Social app', $2, true, $3, $1, 'test-secret', '[]')")
            .bind(id).bind(owner).bind(json!([{"name":format!("{org}/{provider}"), "canSignIn":true,"canSignUp":true}])).execute(&pg).await.unwrap();
    }
    sqlx::query("INSERT INTO users(id,owner,name,password_hash,display_name,email,email_verified) VALUES($1,$2,'password-user','unusable','Password user','unverified@example.test',true)")
        .bind(&existing_id).bind(&org).execute(&pg).await.unwrap();
    let make_service = |pg: PgPool, diesel| {
        Service::new(
            Router::with_path("api/auth")
                .hoop(
                    salvo::affix_state::AffixList::new()
                        .inject(pg.clone())
                        .inject(diesel),
                )
                .push(Router::with_path("providers").get(list_social_providers))
                .push(Router::with_path("session").post(consume_social_session))
                .push(
                    Router::with_path("{provider}")
                        .get(get_provider_auth_url)
                        .push(Router::with_path("callback").get(provider_callback)),
                ),
        )
    };

    let service = make_service(pg.clone(), diesel.clone());
    let other_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let other_service = make_service(other_pool.clone(), diesel);

    let mut discovery = TestClient::get(format!(
        "http://localhost/api/auth/providers?application={app_a}"
    ))
    .send(&service)
    .await;
    let discovered = discovery.take_string().await.unwrap();
    assert!(discovered.contains(&provider));
    assert!(!discovered.contains("never-disclose-this-secret"));
    let forbidden = TestClient::get(format!(
        "http://localhost/api/auth/not-enabled?application={app_a}"
    ))
    .send(&service)
    .await;
    assert_eq!(forbidden.status_code, Some(StatusCode::FORBIDDEN));
    let mismatch = TestClient::get(format!("http://localhost/api/auth/{provider}?application={app_a}&redirect_uri=https://evil.example/callback")).send(&service).await;
    assert_eq!(mismatch.status_code, Some(StatusCode::BAD_REQUEST));

    let (state, browser) = start(&service, &app_a, &provider).await;
    let callback =
        format!("http://localhost/api/auth/{provider}/callback?code=good-code&state={state}");
    for (target, cookie) in [
        (callback.clone(), String::new()),
        (callback.clone(), "casdog_oauth_browser=attacker".into()),
        (format!("{callback}bad"), browser.clone()),
        (
            callback.replace(&provider, "other-provider"),
            browser.clone(),
        ),
    ] {
        let response = TestClient::get(target)
            .add_header("cookie", cookie, true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    }
    let mut response = TestClient::get(&callback)
        .add_header("cookie", &browser, true)
        .send(&other_service)
        .await;
    assert_eq!(
        response.status_code.unwrap_or(StatusCode::OK),
        StatusCode::SEE_OTHER,
        "{}",
        response.take_string().await.unwrap_or_default()
    );
    assert_eq!(
        response.headers().get("location").unwrap(),
        "/?social=complete"
    );
    let completion = response_cookie(&response, "casdog_oauth_completion=");
    let replay = TestClient::get(&callback)
        .add_header("cookie", &browser, true)
        .send(&service)
        .await;
    assert_eq!(replay.status_code, Some(StatusCode::UNAUTHORIZED));
    let wrong_origin = TestClient::post("http://localhost/api/auth/session")
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .add_header("cookie", &completion, true)
        .add_header("origin", "https://evil.example", true)
        .send(&service)
        .await;
    assert_eq!(wrong_origin.status_code, Some(StatusCode::UNAUTHORIZED));
    let mut session = TestClient::post("http://localhost/api/auth/session")
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .add_header("cookie", &completion, true)
        .add_header("origin", "http://127.0.0.1:8000", true)
        .send(&service)
        .await;
    assert_eq!(
        session.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK
    );
    let login: Value = session.take_json().await.unwrap();
    assert!(login["token"].as_str().unwrap().len() > 40);
    assert_eq!(login["user"]["owner"], org);
    let social_id = login["user"]["id"].as_str().unwrap().to_string();
    assert_ne!(social_id, existing_id);
    let verified: bool = sqlx::query_scalar("SELECT email_verified FROM users WHERE id=$1")
        .bind(&social_id)
        .fetch_one(&pg)
        .await
        .unwrap();
    assert!(!verified);
    let replay = TestClient::post("http://localhost/api/auth/session")
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .add_header("cookie", &completion, true)
        .send(&other_service)
        .await;
    assert_eq!(replay.status_code, Some(StatusCode::UNAUTHORIZED));

    // Same external subject and OAuth configuration must stay inside app B's tenant.
    let (state_b, browser_b) = start(&service, &app_b, &provider).await;
    let response = TestClient::get(format!(
        "http://localhost/api/auth/{provider}/callback?code=good-code&state={state_b}"
    ))
    .add_header("cookie", &browser_b, true)
    .send(&service)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    let completion_b = response_cookie(&response, "casdog_oauth_completion=");
    let mut session = TestClient::post("http://localhost/api/auth/session")
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .add_header("cookie", completion_b, true)
        .send(&service)
        .await;
    let other: Value = session.take_json().await.unwrap();
    assert_eq!(other["user"]["owner"], org_b);
    assert_ne!(other["user"]["id"], social_id);

    // MFA cannot be bypassed by the OAuth alternative sign-in route.
    sqlx::query("UPDATE users SET mfa_enabled=true,totp_secret='JBSWY3DPEHPK3PXP' WHERE id=$1")
        .bind(&social_id)
        .execute(&pg)
        .await
        .unwrap();
    let (state, browser) = start(&service, &app_a, &provider).await;
    let challenged = TestClient::get(format!(
        "http://localhost/api/auth/{provider}/callback?code=good-code&state={state}"
    ))
    .add_header("cookie", browser, true)
    .send(&service)
    .await;
    assert_eq!(challenged.status_code, Some(StatusCode::SEE_OTHER));
    let completion = response_cookie(&challenged, "casdog_oauth_completion=");
    let mut response = TestClient::post("http://localhost/api/auth/session")
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .add_header("cookie", completion, true)
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let challenge: Value = response.take_json().await.unwrap();
    assert_eq!(challenge["mfa_required"], true);
    assert_eq!(challenge["token"], "");
    // An account disabled after callback is rejected again before JWT handout.
    let (state, browser) = start(&service, &app_b, &provider).await;
    let response = TestClient::get(format!(
        "http://localhost/api/auth/{provider}/callback?code=good-code&state={state}"
    ))
    .add_header("cookie", browser, true)
    .send(&service)
    .await;
    let completion = response_cookie(&response, "casdog_oauth_completion=");
    sqlx::query("UPDATE users SET is_forbidden=true WHERE owner=$1")
        .bind(&org_b)
        .execute(&pg)
        .await
        .unwrap();
    let rejected = TestClient::post("http://localhost/api/auth/session")
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .add_header("cookie", completion, true)
        .send(&service)
        .await;
    assert_eq!(rejected.status_code, Some(StatusCode::UNAUTHORIZED));

    sqlx::query("DELETE FROM users WHERE owner=$1 OR owner=$2")
        .bind(&org)
        .bind(&org_b)
        .execute(&pg)
        .await
        .unwrap();
    sqlx::query("DELETE FROM applications WHERE id=$1 OR id=$2")
        .bind(&app_a)
        .bind(&app_b)
        .execute(&pg)
        .await
        .unwrap();
    sqlx::query("DELETE FROM providers WHERE id=$1")
        .bind(&provider_id)
        .execute(&pg)
        .await
        .unwrap();
    sqlx::query("DELETE FROM organizations WHERE name=$1 OR name=$2")
        .bind(&org)
        .bind(&org_b)
        .execute(&pg)
        .await
        .unwrap();
    drop(other_service);
    other_pool.close().await;
    mock.abort();
}
