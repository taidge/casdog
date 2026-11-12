//! SMTP mode negotiation over actual TCP, plus native/compatibility CRUD and delivery.
use casdog::{
    config::AppConfig,
    services::providers::email_provider::{
        EmailProviderTrait, SmtpEmailProvider, SmtpTlsMode, smtp_tls_mode,
    },
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

struct Wire {
    port: u16,
    trace: Arc<Mutex<Vec<u8>>>,
    auth: Arc<Mutex<usize>>,
    messages: Arc<Mutex<usize>>,
    task: tokio::task::JoinHandle<()>,
}
impl Wire {
    async fn start(implicit: bool, starttls: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let auth = Arc::new(Mutex::new(0));
        let messages = Arc::new(Mutex::new(0));
        let (seen, authenticated, delivered) = (trace.clone(), auth.clone(), messages.clone());
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            if implicit {
                let mut bytes = [0u8; 4096];
                let size = socket.read(&mut bytes).await.unwrap();
                seen.lock().unwrap().extend_from_slice(&bytes[..size]);
                return;
            }
            socket
                .get_mut()
                .write_all(b"220 local.test ESMTP\r\n")
                .await
                .unwrap();
            let mut data = false;
            loop {
                let mut line = String::new();
                if socket.read_line(&mut line).await.unwrap_or(0) == 0 {
                    break;
                }
                seen.lock().unwrap().extend_from_slice(line.as_bytes());
                if data {
                    if line == ".\r\n" {
                        data = false;
                        *delivered.lock().unwrap() += 1;
                        socket.get_mut().write_all(b"250 queued\r\n").await.unwrap();
                    }
                    continue;
                }
                let reply = if line.starts_with("EHLO") {
                    if starttls {
                        "250-local.test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n"
                    } else {
                        "250-local.test\r\n250 AUTH PLAIN\r\n"
                    }
                } else if line.starts_with("STARTTLS") {
                    socket
                        .get_mut()
                        .write_all(b"220 begin TLS\r\n")
                        .await
                        .unwrap();
                    let mut bytes = [0u8; 4096];
                    let size = socket.read(&mut bytes).await.unwrap();
                    seen.lock().unwrap().extend_from_slice(&bytes[..size]);
                    break;
                } else if line.starts_with("AUTH") {
                    *authenticated.lock().unwrap() += 1;
                    "235 accepted\r\n"
                } else if line.starts_with("DATA") {
                    data = true;
                    "354 end with dot\r\n"
                } else if line.starts_with("QUIT") {
                    socket.get_mut().write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    "250 accepted\r\n"
                };
                socket.get_mut().write_all(reply.as_bytes()).await.unwrap();
            }
        });
        Self {
            port,
            trace,
            auth,
            messages,
            task,
        }
    }
    async fn finish(self) -> (Vec<u8>, usize, usize) {
        let mut task = self.task;
        match tokio::time::timeout(std::time::Duration::from_secs(8), &mut task).await {
            Ok(result) => result.unwrap(),
            Err(_) => {
                task.abort();
                panic!("SMTP fixture did not finish");
            }
        }
        let result = (
            self.trace.lock().unwrap().clone(),
            *self.auth.lock().unwrap(),
            *self.messages.lock().unwrap(),
        );
        result
    }
}

#[test]
fn smtp_explicit_modes_and_legacy_defaults_have_distinct_port_policies() {
    use SmtpTlsMode::*;
    for port in [25, 465, 587, 2525] {
        assert_eq!(smtp_tls_mode(Some("Enable"), true, port).unwrap(), Implicit);
        assert_eq!(
            smtp_tls_mode(Some("Disable"), false, port).unwrap(),
            OpportunisticStarttls
        );
        assert_eq!(
            smtp_tls_mode(Some("Auto"), false, port).unwrap(),
            if port == 465 {
                Implicit
            } else {
                OpportunisticStarttls
            }
        );
        assert_eq!(
            smtp_tls_mode(None, false, port).unwrap(),
            if port == 465 {
                Implicit
            } else {
                RequiredStarttls
            }
        );
        assert_eq!(
            smtp_tls_mode(Some(""), false, port).unwrap(),
            smtp_tls_mode(None, false, port).unwrap()
        );
        assert_eq!(
            smtp_tls_mode(None, true, port).unwrap(),
            OpportunisticStarttls
        );
    }
    for invalid in ["auto", "None", "StartTLS", " Enable "] {
        assert!(smtp_tls_mode(Some(invalid), false, 587).is_err());
    }
}

#[tokio::test]
async fn smtp_wire_enable_uses_implicit_tls_and_all_starttls_modes_reject_failed_upgrades_without_auth()
 {
    for (mode, disable_ssl, implicit) in [
        (Some("Enable"), false, true),
        (Some("Enable"), true, true),
        (Some("Auto"), false, false),
        (Some("Disable"), false, false),
        (None, false, false),
        (None, true, false),
    ] {
        let wire = Wire::start(implicit, true).await;
        let provider = SmtpEmailProvider::new(
            "127.0.0.1".into(),
            wire.port,
            "smtp-user".into(),
            "smtp-secret".into(),
            "sender@example.test".into(),
            !disable_ssl,
        )
        .with_ssl_mode(mode)
        .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(6),
                provider.send_email("recipient@example.test", "TLS mode", "body")
            )
            .await
            .unwrap()
            .is_err()
        );
        let (trace, auth, messages) = wire.finish().await;
        assert_eq!((auth, messages), (0, 0));
        if implicit {
            assert_eq!(trace.first(), Some(&0x16));
        } else {
            assert!(trace.windows(10).any(|part| part == b"STARTTLS\r\n"));
            assert!(trace.contains(&0x16));
        }
    }
}

async fn request(
    service: &Service,
    token: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Response {
    let builder = match method {
        "GET" => TestClient::get(format!("http://localhost{path}")),
        "PUT" => TestClient::put(format!("http://localhost{path}")),
        _ => TestClient::post(format!("http://localhost{path}")),
    }
    .add_header("Authorization", format!("Bearer {token}"), true);
    if let Some(body) = body {
        builder.json(&body).send(service).await
    } else {
        builder.send(service).await
    }
}
async fn ok(
    service: &Service,
    token: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Value {
    let mut response = request(service, token, method, path, body).await;
    let status = response.status_code;
    let value: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{value}");
    value
}
async fn token(pool: &PgPool, owner: &str) -> (String, String) {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,$1,$1,'unused',true)").bind(&id).bind(owner).execute(pool).await.unwrap();
    let config = AppConfig::get();
    let now = chrono::Utc::now().timestamp();
    let token=jsonwebtoken::encode(&jsonwebtoken::Header::default(),&json!({"sub":id,"owner":owner,"name":id,"is_admin":true,"iat":now,"exp":now+3600,"issued_at_ms":now*1000,"iss":config.jwt.issuer}),&jsonwebtoken::EncodingKey::from_secret(config.jwt.secret.as_bytes())).unwrap();
    (id, token)
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn smtp_modes_native_legacy_crud_tenant_and_real_delivery() {
    AppConfig::load().unwrap();
    let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .unwrap();
    let owner = format!("smtp-mode-{}", uuid::Uuid::new_v4().simple());
    sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
    let (id, admin) = token(&pool, &owner).await;
    let foreign_owner = format!("{owner}-foreign");
    sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&foreign_owner)
        .execute(&pool)
        .await
        .unwrap();
    let (foreign_id, foreign) = token(&pool, &foreign_owner).await;
    let service = Service::new(casdog::routes::create_router()).hoop(
        salvo::affix_state::AffixList::new()
            .inject(pool.clone())
            .inject(casdog::diesel_pool::create_diesel_pool(&url).await.unwrap()),
    );
    for (index, mode, legacy_bool, success) in [
        (0, None, false, false),
        (1, Some("Auto"), false, true),
        (2, Some("Disable"), false, true),
        (3, None, true, true),
        (4, Some(""), false, false),
    ] {
        let wire = Wire::start(false, false).await;
        let name = format!("mode-{index}");
        let mut body = json!({"owner":owner,"name":name,"display_name":name,"category":"Email","type":"SMTP","host":"127.0.0.1","port":wire.port,"disable_ssl":legacy_bool,"client_id":"smtp-user","client_secret":"smtp-secret","client_id2":"sender@example.test"});
        if let Some(mode) = mode {
            body["ssl_mode"] = json!(mode);
        }
        if index == 2 {
            body["client_secret2"] = json!("Configured Sender");
        }
        let created = ok(&service, &admin, "POST", "/api/providers", Some(body)).await;
        let pid = created["id"].as_str().unwrap();
        assert_eq!(
            created["ssl_mode"],
            mode.map(Value::from).unwrap_or(Value::Null)
        );
        let mut delivered=request(&service,&admin,"POST","/api/send-email",Some(json!({"provider":pid,"to":"recipient@example.test","sender":"Request Sender","title":"Modes","content":"Real mode delivery"}))).await;
        if success {
            let status = delivered.status_code;
            let response: Value = delivered.take_json().await.unwrap();
            assert_eq!(status, Some(StatusCode::OK), "{response}");
        } else {
            assert_ne!(delivered.status_code, Some(StatusCode::OK));
        }
        let (trace, auth, messages) = wire.finish().await;
        assert_eq!((auth, messages), if success { (1, 1) } else { (0, 0) });
        if success {
            let expected = if index == 2 {
                "Configured Sender"
            } else {
                "Request Sender"
            };
            let message = String::from_utf8(trace).unwrap();
            assert!(
                message.lines().any(|line| line.starts_with("From: ")
                    && line.contains(expected)
                    && line.contains("<sender@example.test>")),
                "SMTP From header did not preserve the address and sender name"
            );
        }
        let denied = request(
            &service,
            &foreign,
            "GET",
            &format!("/api/providers/{pid}"),
            None,
        )
        .await;
        assert!(matches!(
            denied.status_code,
            Some(StatusCode::FORBIDDEN) | Some(StatusCode::NOT_FOUND)
        ));
        for invalid in ["auto", "bogus"] {
            let rejected = request(
                &service,
                &admin,
                "PUT",
                &format!("/api/providers/{pid}"),
                Some(json!({"ssl_mode":invalid})),
            )
            .await;
            assert_eq!(rejected.status_code, Some(StatusCode::BAD_REQUEST));
        }
        ok(
            &service,
            &admin,
            "POST",
            &format!("/api/update-provider?id={owner}/{name}"),
            Some(json!({"owner":owner,"name":name,"sslMode":"Enable"})),
        )
        .await;
        let legacy = ok(
            &service,
            &admin,
            "GET",
            &format!("/api/get-provider?id={owner}/{name}"),
            None,
        )
        .await;
        assert_eq!(legacy["data"]["sslMode"], "Enable");
        ok(
            &service,
            &admin,
            "PUT",
            &format!("/api/providers/{pid}"),
            Some(json!({"ssl_mode":"Disable"})),
        )
        .await;
        let legacy = ok(
            &service,
            &admin,
            "GET",
            &format!("/api/get-provider?id={owner}/{name}"),
            None,
        )
        .await;
        assert_eq!(legacy["data"]["sslMode"], "Disable");
    }
    let rejected=request(&service,&admin,"POST","/api/providers",Some(json!({"owner":owner,"name":"unsupported","display_name":"Unsupported","category":"Storage","type":"Local","ssl_mode":"Enable"}))).await;
    assert_eq!(rejected.status_code, Some(StatusCode::BAD_REQUEST));
    sqlx::query("DELETE FROM providers WHERE owner=$1")
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1 OR id=$2")
        .bind(id)
        .bind(foreign_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM organizations WHERE name=$1 OR name=$2")
        .bind(owner)
        .bind(foreign_owner)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
