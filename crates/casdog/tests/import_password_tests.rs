//! Casdoor credential vectors and real upload/add-user/login API regressions.
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    services::{password_service::PasswordService, user_import_service::parse_upload},
};
use jsonwebtoken::{EncodingKey, Header, encode};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::io::{Cursor, Write};

const BCRYPT: &str = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";
const ARGON: &str = "$argon2id$v=19$m=65536,t=3,p=2$Y2FzZG9vci12ZWN0b3IwMQ$e1S8o0jYWvHXjiiILQLJxKmeooGtKtXwEquWsuF27Yk";
const SHA256: &str = "92d690d4eb4a598d5362f7196dba110e3974a9ea58eb9363be73e987d738afc6";
const DJANGO: &str = "pbkdf2_sha256$260000$salt$BOAEc9gQ0CEXQRxBUdHBbIFI/Fh0OEwXzUsCN5cI+kQ=";

#[test]
fn casdoor_exported_hashes_keep_their_exact_semantics_and_verify_independent_vectors() {
    // Digest/PBKDF2 constants were independently calculated with Python hashlib.
    // ARGON uses argon2-cffi with alexedwards/Casdoor's m=64MiB,t=3,p=2.
    for (kind, salt, hash, password) in [
        ("bcrypt", None, BCRYPT, "correctbatteryhorsestapler"),
        ("argon2id", None, ARGON, "correctbatteryhorsestapler"),
        ("salt", Some("salt"), SHA256, "password"),
        (
            "md5-salt",
            Some("salt"),
            "d514dee5e76bbb718084294c835f312c",
            "password",
        ),
        (
            "sha512-salt",
            Some("salt"),
            "0a610f0bbf7a92accc7e962c53ef3ed7d7d2cabb16139ae169555a6685056b405fa4a3edb041f27e6d8c29bea70eb9bd89bad9fcfcdf05e23b1b8b99ad1256a5",
            "password",
        ),
        (
            "pbkdf2-salt",
            Some("c2FsdA=="),
            "p6XETX9kSIy9ZwWTiGafUdPW9KUJsfJSWQD9lWRuomav7bGCMfY03kxznJu2emdUprJ3DVemHMlpE5c0+dmsAA==",
            "password",
        ),
        ("pbkdf2-django", None, DJANGO, "password"),
    ] {
        let imported = PasswordService::import_credential(hash, Some(kind), salt, true).unwrap();
        assert_eq!(imported.hash, hash);
        assert_eq!(imported.password_type, kind);
        assert_eq!(imported.salt.as_deref(), salt);
        assert!(
            PasswordService::verify_password(
                password,
                &imported.hash,
                &imported.password_type,
                imported.salt.as_deref()
            )
            .unwrap()
        );
        assert!(
            !PasswordService::verify_password(
                "wrong",
                &imported.hash,
                &imported.password_type,
                imported.salt.as_deref()
            )
            .unwrap()
        );
    }
    assert_eq!(
        PasswordService::import_credential(BCRYPT, None, None, true)
            .unwrap()
            .password_type,
        "bcrypt"
    );
    assert!(PasswordService::import_credential(SHA256, None, None, true).is_err());
}
#[test]
fn encoded_credentials_are_never_double_hashed_and_masked_or_expensive_hashes_are_rejected() {
    assert!(PasswordService::import_credential(BCRYPT, None, None, false).is_err());
    for (kind, hash) in [
        (
            "argon2id",
            "$argon2id$v=19$m=4294967295,t=3,p=2$Y2FzZG9vci12ZWN0b3IwMQ$e1S8o0jYWvHXjiiILQLJxKmeooGtKtXwEquWsuF27Yk",
        ),
        (
            "bcrypt",
            "$2b$31$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie",
        ),
        (
            "pbkdf2-django",
            "pbkdf2_sha256$4294967295$salt$BOAEc9gQ0CEXQRxBUdHBbIFI/Fh0OEwXzUsCN5cI+kQ=",
        ),
        ("unsupported", BCRYPT),
    ] {
        assert!(PasswordService::import_credential(hash, Some(kind), None, true).is_err());
        assert!(!PasswordService::verify_password("password", hash, kind, None).unwrap());
    }
    for body in [
        json!({"password":"***","passwordType":"bcrypt"}),
        json!({"passwordHash":"***"}),
        json!({"password":BCRYPT,"passwordHash":"***","passwordType":"bcrypt"}),
        json!({"password":"***","passwordHash":BCRYPT,"passwordType":"bcrypt"}),
    ] {
        let mut records =
            parse_upload(&serde_json::to_vec(&json!([body])).unwrap(), "users.json").unwrap();
        assert!(PasswordService::normalize_import_fields(&mut records[0], false).is_err());
    }
    let mut masked =
        json!({"password":"***","password_type":"plain","password_salt":"replacement"})
            .as_object()
            .unwrap()
            .clone();
    PasswordService::normalize_import_fields(&mut masked, true).unwrap();
    assert!(masked.is_empty());
}
#[test]
fn csv_preserves_password_whitespace_quotes_and_newlines_and_normalizes_localized_headers() {
    let input = "用户名#Name,Password,PasswordType,DisplayName\r\n\"alice,team\",\"  p,\"\"q\"\"\nline  \",plain,\" Alice & Bob \"\r\n";
    let records = parse_upload(input.as_bytes(), "users.csv").unwrap();
    assert_eq!(records[0]["name"], "alice,team");
    assert_eq!(records[0]["password"], "  p,\"q\"\nline  ");
    assert_eq!(records[0]["display_name"], " Alice & Bob ");
    assert!(parse_upload(b"name,password\nalice,\"unterminated", "bad.csv").is_err());
    assert!(
        parse_upload(
            br#"[{"name":"alice","passwordType":"plain","password_type":"bcrypt"}]"#,
            "bad.json"
        )
        .is_err()
    );
    assert!(parse_upload(b"[42]", "bad.json").is_err());
}
fn workbook(sheet: &str, external: bool, dtd: bool) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, content) in [
        (
            "xl/workbook.xml",
            format!(
                "{}<workbook xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"Users\" sheetId=\"1\" r:id=\"users-sheet\"/></sheets></workbook>",
                if dtd {
                    "<!DOCTYPE workbook [<!ENTITY steal SYSTEM 'file:///C:/secret'>]>"
                } else {
                    ""
                }
            ),
        ),
        (
            "xl/_rels/workbook.xml.rels",
            format!(
                "<Relationships><Relationship Id=\"users-sheet\" Target=\"{}\" {}/></Relationships>",
                if external {
                    "https://evil.invalid/users"
                } else {
                    "worksheets/users.xml"
                },
                if external {
                    "TargetMode=\"External\""
                } else {
                    ""
                }
            ),
        ),
        ("xl/worksheets/users.xml", sheet.into()),
    ] {
        zip.start_file(name, options).unwrap();
        zip.write_all(content.as_bytes()).unwrap();
    }
    zip.finish().unwrap().into_inner()
}
fn sheet(rows: &[Vec<&str>]) -> String {
    let mut out = String::from("<worksheet><sheetData>");
    for (i, row) in rows.iter().enumerate() {
        out.push_str("<row>");
        for (j, value) in row.iter().enumerate() {
            let value = value
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            out.push_str(&format!(
                "<c r=\"{}{}\" t=\"inlineStr\"><is><t>{value}</t></is></c>",
                (b'A' + j as u8) as char,
                i + 1
            ));
        }
        out.push_str("</row>");
    }
    out.push_str("</sheetData></worksheet>");
    out
}
#[test]
fn official_xlsx_first_sheet_preserves_entities_and_rejects_formulas_external_parts_and_dtds() {
    let sheet = sheet(&[
        vec![
            "组织#Owner",
            "用户名#Name",
            "Password",
            "PasswordType",
            "DisplayName",
        ],
        vec!["tenant", "alice", BCRYPT, "bcrypt", "  Alice & <团队>  "],
    ]);
    let bytes = workbook(&sheet, false, false);
    let rows = parse_upload(&bytes, "users.xlsx").unwrap();
    assert_eq!(rows[0]["password"], BCRYPT);
    assert_eq!(rows[0]["password_type"], "bcrypt");
    assert_eq!(rows[0]["display_name"], "  Alice & <团队>  ");
    assert!(parse_upload(&workbook(&sheet, true, false), "users.xlsx").is_err());
    assert!(parse_upload(&workbook(&sheet, false, true), "users.xlsx").is_err());
    let formula = "<worksheet><sheetData><row><c r=\"A1\"><f>HYPERLINK(1)</f><v>name</v></c></row></sheetData></worksheet>";
    assert!(parse_upload(&workbook(formula, false, false), "users.xlsx").is_err());
    let duplicate = "<worksheet><sheetData><row><c r=\"A1\"><v>name</v></c><c r=\"A1\"><v>password</v></c></row></sheetData></worksheet>";
    assert!(parse_upload(&workbook(duplicate, false, false), "users.xlsx").is_err());
}

struct Fixture {
    pool: PgPool,
    service: Service,
    owner: String,
    other: String,
    admin: String,
    user: String,
    app: String,
}
impl Fixture {
    async fn restore(&self, rows: Value) -> Value {
        let mut response = TestClient::post(format!(
            "http://localhost/api/upload-users-with-mfa?owner={}",
            self.owner
        ))
        .add_header(
            "Authorization",
            format!("Bearer {}", self.token(true)),
            true,
        )
        .json(&rows)
        .send(&self.service)
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        response.take_json().await.unwrap()
    }
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel),
        );
        let owner = format!("imports-{}", uuid::Uuid::new_v4());
        let other = format!("imports-other-{}", uuid::Uuid::new_v4());
        let admin = uuid::Uuid::new_v4().to_string();
        let user = uuid::Uuid::new_v4().to_string();
        let app = uuid::Uuid::new_v4().to_string();
        for tenant in [&owner, &other] {
            sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'Import test')").bind(uuid::Uuid::new_v4().to_string()).bind(tenant).execute(&pool).await.unwrap();
        }
        for (id, name, is_admin) in [(&admin, "admin", true), (&user, "ordinary", false)] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,$3,$3,'test-only-placeholder',$4)").bind(id).bind(&owner).bind(name).bind(is_admin).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_password) VALUES($1,$2,'app','App',$2,$1,'secret','',true)").bind(&app).bind(&owner).execute(&pool).await.unwrap();
        Self {
            pool,
            service,
            owner,
            other,
            admin,
            user,
            app,
        }
    }
    fn token(&self, admin: bool) -> String {
        let now = chrono::Utc::now();
        encode(&Header::default(),&json!({"sub":if admin{&self.admin}else{&self.user},"owner":self.owner,"name":if admin{"admin"}else{"ordinary"},"is_admin":admin,"iat":now.timestamp(),"issued_at_ms":now.timestamp_millis(),"exp":now.timestamp()+3600,"iss":AppConfig::get().jwt.issuer}),&EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes())).unwrap()
    }
    async fn json_upload(&self, rows: Value, admin: bool) -> Response {
        TestClient::post("http://localhost/api/upload-users")
            .add_header(
                "Authorization",
                format!("Bearer {}", self.token(admin)),
                true,
            )
            .json(&rows)
            .send(&self.service)
            .await
    }
    async fn multipart(&self, filename: &str, content: &[u8], owner: Option<&str>) -> Response {
        let mut body = Vec::new();
        if let Some(owner) = owner {
            body.extend_from_slice(format!("--import-boundary\r\nContent-Disposition: form-data; name=\"owner\"\r\n\r\n{owner}\r\n").as_bytes());
        }
        body.extend_from_slice(format!("--import-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n--import-boundary--\r\n");
        TestClient::post("http://localhost/api/upload-users")
            .add_header(
                "Authorization",
                format!("Bearer {}", self.token(true)),
                true,
            )
            .add_header(
                "Content-Type",
                "multipart/form-data; boundary=import-boundary",
                true,
            )
            .body(body)
            .send(&self.service)
            .await
    }
    async fn login(&self, name: &str, password: &str) -> Response {
        TestClient::post("http://localhost/api/login")
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .json(&json!({"owner":self.owner,"name":name,"password":password,"clientId":self.app}))
            .send(&self.service)
            .await
    }
    async fn cleanup(self) {
        for table in [
            "tokens",
            "applications",
            "users",
            "providers",
            "organizations",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE owner=$1 OR owner=$2"))
                .bind(&self.owner)
                .bind(&self.other)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        drop(self.service);
        self.pool.close().await;
    }
}

fn restore_row(f: &Fixture, name: &str, secret: &str, codes: &[String]) -> Value {
    json!({"owner":f.owner,"name":name,"password":BCRYPT,"passwordType":"bcrypt","preferredMfaType":"app","totpSecret":secret,"recoveryCodes":codes,"mfaPhoneEnabled":false,"mfaEmailEnabled":false})
}
fn restore_cookie(response: &Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| {
            v.split(';')
                .next()
                .filter(|v| v.starts_with("casdog_password_mfa="))
                .map(str::to_owned)
        })
        .unwrap()
}

#[test]
fn trusted_mfa_backup_parser_validates_real_totp_and_keeps_uuid_recovery_codes_exact() {
    use casdog::services::mfa_restore_service::prepare;
    let mut row=json!({"preferred_mfa_type":"app","totp_secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","recovery_codes":["7e313cbb-b090-47db-b207-d097c15d4c28"]}).as_object().unwrap().clone();
    assert!(prepare(&mut row).unwrap().is_some());
    assert!(!row.contains_key("totp_secret"));
    let secret = totp_rs::Secret::Encoded("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into())
        .to_bytes()
        .unwrap();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        None,
        "vector".into(),
    )
    .unwrap();
    assert_eq!(totp.generate(59), "287082");
    for v in [
        json!({"preferred_mfa_type":"app"}),
        json!({"preferred_mfa_type":"radius","mfa_radius_enabled":true}),
        json!({"preferred_mfa_type":"app","totp_secret":"***"}),
        json!({"mfa_push_enabled":true}),
        json!({"preferred_mfa_type":"unknown"}),
        json!({"preferred_mfa_type":"app","totp_secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","recovery_codes":["duplicate","duplicate"]}),
    ] {
        assert!(prepare(&mut v.as_object().unwrap().clone()).is_err());
    }
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL including 041"]
async fn trusted_raw_backup_restores_totp_and_uuid_recovery_into_the_normal_browser_mfa_pipeline() {
    use casdog::services::mfa_service::MfaService;
    let f = Fixture::new().await;
    let (secret, _) = MfaService::initiate_totp_setup("restore", "Casdoor").unwrap();
    let codes = vec![
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
    ];
    let row = restore_row(&f, "restored", &secret, &codes);
    let mut ordinary = f.json_upload(json!([row.clone()]), true).await;
    let rejected: Value = ordinary.take_json().await.unwrap();
    assert_eq!(rejected["created"], 0);
    let report = f.restore(json!({"users":[row]})).await;
    assert_eq!(report["created"], 1);
    assert!(!report.to_string().contains(&secret));
    assert!(!report.to_string().contains(&codes[0]));
    let (id,enabled,kind,stored,codes_text):(String,bool,String,String,String)=sqlx::query_as("SELECT u.id,u.mfa_enabled,m.mfa_type,m.secret,m.recovery_codes FROM users u JOIN user_mfa m ON m.user_id=u.id WHERE u.owner=$1 AND u.name='restored'").bind(&f.owner).fetch_one(&f.pool).await.unwrap();
    assert!(enabled);
    assert_eq!(kind, "totp");
    assert_eq!(stored, secret);
    assert_eq!(
        serde_json::from_str::<Vec<String>>(&codes_text).unwrap(),
        codes
    );
    let (cutoff,step):(bool,i64)=sqlx::query_as("SELECT EXISTS(SELECT 1 FROM user_session_epochs WHERE user_id=$1),last_step FROM user_totp_steps WHERE user_id=$1").bind(&id).fetch_one(&f.pool).await.unwrap();
    assert!(cutoff);
    let db_step: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())/30)::bigint")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(step >= db_step);
    let mut pending = f.login("restored", "correctbatteryhorsestapler").await;
    let cookie = restore_cookie(&pending);
    let value: Value = pending.take_json().await.unwrap();
    assert_eq!(value["mfa_required"], true);
    assert_eq!(value["token"].as_str(), Some(""));
    let mut response = TestClient::post("http://localhost/api/auth/password/session")
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .add_header("Cookie", cookie, true)
        .json(&json!({"mfaType":"recovery","passcode":codes[0]}))
        .send(&f.service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let signed_in: Value = response.take_json().await.unwrap();
    assert!(
        signed_in["token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        !MfaService::verify_recovery_code(&f.pool, &id, &codes[0])
            .await
            .unwrap()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL including 041"]
async fn restored_credentials_are_atomic_across_pools_and_cannot_be_reimported_after_user_deletion()
{
    use casdog::services::mfa_service::MfaService;
    let f = Fixture::new().await;
    let (secret, _) = MfaService::initiate_totp_setup("restore", "Casdoor").unwrap();
    let code = uuid::Uuid::new_v4().to_string();
    let codes = vec![code.clone()];
    assert_eq!(
        f.restore(json!([restore_row(&f, "first", &secret, &codes)]))
            .await["created"],
        1
    );
    let id: String = sqlx::query_scalar("SELECT id FROM users WHERE owner=$1 AND name='first'")
        .bind(&f.owner)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        MfaService::verify_recovery_code(&f.pool, &id, &code),
        MfaService::verify_recovery_code(&pool, &id, &code)
    );
    assert_eq!(usize::from(a.unwrap()) + usize::from(b.unwrap()), 1);
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(&id)
        .execute(&f.pool)
        .await
        .unwrap();
    let report = f
        .restore(json!([restore_row(
            &f,
            "new-name",
            &secret,
            &[uuid::Uuid::new_v4().to_string()]
        )]))
        .await;
    assert_eq!(report["created"], 0);
    let (fresh, _) = MfaService::initiate_totp_setup("restore", "Casdoor").unwrap();
    let report = f
        .restore(json!([restore_row(&f, "new-code", &fresh, &codes)]))
        .await;
    assert_eq!(report["created"], 0);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM users WHERE owner=$1 AND name IN ('new-name','new-code')",
    )
    .bind(&f.owner)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL including 041"]
async fn masked_unsupported_cross_tenant_or_bad_binding_enrollments_reject_the_entire_restore_batch()
 {
    let f = Fixture::new().await;
    let (seed, _) =
        casdog::services::mfa_service::MfaService::initiate_totp_setup("r", "Casdoor").unwrap();
    for bad in [
        json!({"preferredMfaType":"app","totpSecret":""}),
        json!({"preferredMfaType":"push","mfaPushEnabled":true}),
        json!({"preferredMfaType":"email","mfaEmailEnabled":true,"email":"restore@example.org","emailVerified":true,"signupApplication":f.app}),
        json!({"webauthnCredentials":[{}]}),
        json!({"mfaAccounts":[{"secretKey":"***"}]}),
    ] {
        let mut badrow =
            json!({"owner":f.owner,"name":"bad-restore","password":BCRYPT,"passwordType":"bcrypt"});
        badrow
            .as_object_mut()
            .unwrap()
            .extend(bad.as_object().unwrap().clone());
        let report = f
            .restore(json!([restore_row(&f, "good-restore", &seed, &[]), badrow]))
            .await;
        assert_eq!(report["created"], 0);
        assert_eq!(report["failed"], 2);
    }
    let mut cross = restore_row(&f, "cross", &seed, &[]);
    cross["owner"] = json!(f.other);
    let response = TestClient::post(format!(
        "http://localhost/api/upload-users-with-mfa?owner={}",
        f.owner
    ))
    .add_header("Authorization", format!("Bearer {}", f.token(true)), true)
    .json(&json!([cross]))
    .send(&f.service)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let response = TestClient::post("http://localhost/api/upload-users-with-mfa")
        .add_header("Authorization", format!("Bearer {}", f.token(false)), true)
        .json(&json!([restore_row(&f, "ordinary", &seed, &[])]))
        .send(&f.service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL including 041"]
async fn email_sms_restore_requires_real_application_delivery_bindings_and_persists_one_global_recovery_set()
 {
    let f = Fixture::new().await;
    for (name, category) in [("restore-email", "Email"), ("restore-sms", "SMS")] {
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,endpoint,client_secret) VALUES($1,$2,$3,$3,$4,'Custom HTTP','http://127.0.0.1:9/not-sent','test-secret')").bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(name).bind(category).execute(&f.pool).await.unwrap();
    }
    sqlx::query("UPDATE applications SET providers=$2 WHERE id=$1").bind(&f.app).bind(json!([{"name":format!("{}/restore-email",f.owner),"rule":"MFA"},{"name":format!("{}/restore-sms",f.owner),"rule":"MFA"}])).execute(&f.pool).await.unwrap();
    let codes = vec![uuid::Uuid::new_v4().to_string()];
    sqlx::query("UPDATE providers SET endpoint=NULL WHERE owner=$1 AND name='restore-email'")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    let invalid=f.restore(json!([{"owner":f.owner,"name":"bad-endpoint","password":BCRYPT,"passwordType":"bcrypt","preferredMfaType":"email","mfaEmailEnabled":true,"email":"backup@example.org","emailVerified":true,"signupApplication":f.app}])).await;
    assert_eq!(invalid["created"], 0);
    sqlx::query("UPDATE providers SET endpoint='http://127.0.0.1:9/not-sent' WHERE owner=$1 AND name='restore-email'").bind(&f.owner).execute(&f.pool).await.unwrap();
    let report=f.restore(json!({"users":[{"owner":f.owner,"name":"contacts","password":BCRYPT,"passwordType":"bcrypt","preferredMfaType":"email","mfaEmailEnabled":true,"email":"backup@example.org","emailVerified":true,"mfaPhoneEnabled":true,"phone":"+15551234567","countryCode":"US","signupApplication":f.app,"recoveryCodes":codes}]})).await;
    assert_eq!(report["created"], 1);
    let user: casdog::models::User =
        sqlx::query_as("SELECT * FROM users WHERE owner=$1 AND name='contacts'")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let methods = casdog::services::mfa_service::MfaService::login_methods(&f.pool, &user)
        .await
        .unwrap();
    assert!(methods.contains(&"email".to_owned()));
    assert!(methods.contains(&"sms".to_owned()));
    assert!(methods.contains(&"recovery".to_owned()));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM user_mfa WHERE user_id=$1")
        .bind(&user.id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn multipart_casdoor_xlsx_and_json_hash_import_login_and_upgrade_without_double_hashing() {
    let f = Fixture::new().await;
    let sheet = sheet(&[
        vec!["Owner", "Name", "Password", "PasswordType", "DisplayName"],
        vec![&f.owner, "xlsx-bcrypt", BCRYPT, "bcrypt", "Uploaded user"],
    ]);
    let mut response = f
        .multipart(
            "users.xlsx",
            &workbook(&sheet, false, false),
            Some(&f.owner),
        )
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let receipt: Value = response.take_json().await.unwrap();
    assert_eq!(receipt["created"], 1);
    assert_eq!(receipt["failed"], 0);
    assert!(!receipt.to_string().contains(BCRYPT));
    let stored:(String,String,Option<String>)=sqlx::query_as("SELECT password_hash,password_type,password_salt FROM users WHERE owner=$1 AND name='xlsx-bcrypt'").bind(&f.owner).fetch_one(&f.pool).await.unwrap();
    assert_eq!(stored.0, BCRYPT);
    assert_eq!(stored.1, "bcrypt");
    assert!(stored.2.is_none());
    let mut login = f.login("xlsx-bcrypt", "correctbatteryhorsestapler").await;
    assert_eq!(login.status_code, Some(StatusCode::OK));
    let body: Value = login.take_json().await.unwrap();
    assert!(!body["token"].as_str().unwrap().is_empty());
    let stored:(String,String,Option<String>)=sqlx::query_as("SELECT password_hash,password_type,password_salt FROM users WHERE owner=$1 AND name='xlsx-bcrypt'").bind(&f.owner).fetch_one(&f.pool).await.unwrap();
    assert!(stored.0.starts_with("$argon2id$"));
    assert_eq!(stored.1, "argon2");
    assert!(stored.2.is_none());
    assert!(
        PasswordService::verify_password("correctbatteryhorsestapler", &stored.0, &stored.1, None)
            .unwrap()
    );
    let mut response=f.json_upload(json!({"users":[{"owner":f.owner,"name":"salted","password":SHA256,"passwordType":"salt","passwordSalt":"salt"}]}),true).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["created"], 1);
    let stored:(String,String,String)=sqlx::query_as("SELECT password_hash,password_type,password_salt FROM users WHERE owner=$1 AND name='salted'").bind(&f.owner).fetch_one(&f.pool).await.unwrap();
    assert_eq!(stored, (SHA256.into(), "salt".into(), "salt".into()));
    assert_eq!(
        f.login("salted", "password").await.status_code,
        Some(StatusCode::OK)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn import_rejects_ordinary_users_cross_tenant_rows_and_invalid_batches_without_partial_writes()
 {
    let f = Fixture::new().await;
    let row = json!([{"owner":f.owner,"name":"forbidden","password":"new-password","passwordType":"plain"}]);
    assert_eq!(
        f.json_upload(row.clone(), false).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let cross = json!([{"owner":f.owner,"name":"first","password":"new-password"},{"owner":f.other,"name":"cross","password":"new-password"}]);
    assert_eq!(
        f.json_upload(cross, true).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let csv = "name,password\nform-override,new-password\n";
    assert_eq!(
        f.multipart("users.csv", csv.as_bytes(), Some(&f.other))
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let mut response=f.json_upload(json!([{"owner":f.owner,"name":"valid-first","password":"new-password"},{"owner":f.owner,"name":"masked-second","password":"***","passwordType":"bcrypt"}]),true).await;
    let report: Value = response.take_json().await.unwrap();
    assert_eq!(report["created"], 0);
    assert_eq!(report["failed"], 2);
    assert!(!report["errors"].as_array().unwrap().is_empty());
    assert!(!report.to_string().contains("new-password"));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM users WHERE owner=$1 AND name NOT IN ('admin','ordinary')",
    )
    .bind(&f.owner)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn legacy_add_user_accepts_declared_hash_and_get_user_masked_update_preserves_credentials() {
    let f = Fixture::new().await;
    let mut response=TestClient::post("http://localhost/api/add-user").add_header("Authorization",format!("Bearer {}",f.token(true)),true).json(&json!({"owner":f.owner,"name":"legacy","displayName":"Legacy","password":DJANGO,"passwordType":"pbkdf2-django"})).send(&f.service).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let _: Value = response.take_json().await.unwrap();
    let mut get = TestClient::get(format!(
        "http://localhost/api/get-user?id={}/legacy",
        f.owner
    ))
    .add_header("Authorization", format!("Bearer {}", f.token(true)), true)
    .send(&f.service)
    .await;
    assert_eq!(get.status_code, Some(StatusCode::OK));
    let mut masked: Value = get.take_json().await.unwrap();
    assert_eq!(masked["data"]["password"], "***");
    assert!(!masked.to_string().contains(DJANGO));
    masked["data"]["displayName"] = json!("Updated");
    let update = TestClient::post(format!(
        "http://localhost/api/update-user?id={}/legacy",
        f.owner
    ))
    .add_header("Authorization", format!("Bearer {}", f.token(true)), true)
    .json(&masked["data"])
    .send(&f.service)
    .await;
    assert_eq!(update.status_code, Some(StatusCode::OK));
    let (hash, kind): (String, String) = sqlx::query_as(
        "SELECT password_hash,password_type FROM users WHERE owner=$1 AND name='legacy'",
    )
    .bind(&f.owner)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(hash, DJANGO);
    assert_eq!(kind, "pbkdf2-django");
    assert_eq!(
        f.login("legacy", "password").await.status_code,
        Some(StatusCode::OK)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn ordinary_csv_plain_password_is_preserved_exactly_but_a_masked_backup_cannot_restore_it() {
    let f = Fixture::new().await;
    let csv = "Name,Password,PasswordType\r\nspace-user,\"  literal,\"\"password\"\"  \",plain\r\n";
    let mut result = f.multipart("users.csv", csv.as_bytes(), None).await;
    assert_eq!(result.status_code, Some(StatusCode::OK));
    let report: Value = result.take_json().await.unwrap();
    assert_eq!(report["created"], 1);
    assert_eq!(
        f.login("space-user", "  literal,\"password\"  ")
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    assert_eq!(
        f.login("space-user", "literal,\"password\"")
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let mut masked = f
        .json_upload(
            json!([{"owner":f.owner,"name":"restore","password":"***","passwordType":"argon2"}]),
            true,
        )
        .await;
    let report: Value = masked.take_json().await.unwrap();
    assert_eq!(report["created"], 0);
    assert_eq!(report["failed"], 1);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn csv_enabled_mfa_is_not_discarded_and_directory_bindings_preserve_real_legacy_ids() {
    let f = Fixture::new().await;
    for flag in [
        "mfaEnabled",
        "mfaPhoneEnabled",
        "mfaEmailEnabled",
        "mfaRadiusEnabled",
        "mfaPushEnabled",
    ] {
        let csv = format!("Name,Password,{flag}\nneeds-mfa,new-password,true\n");
        let mut response = f.multipart("users.csv", csv.as_bytes(), None).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let report: Value = response.take_json().await.unwrap();
        assert_eq!(report["created"], 0);
        assert_eq!(report["failed"], 1);
        assert!(report["errors"].to_string().contains("MFA"));
        assert!(!report.to_string().contains("new-password"));
    }
    for owner in [&f.owner, &f.other] {
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type) VALUES($1,$2,'directory','Directory','LDAP','LDAP')")
        .bind(uuid::Uuid::new_v4().to_string()).bind(owner).execute(&f.pool).await.unwrap();
    }
    let id = format!(
        "app:legacy-import-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let reference = format!("{}/directory", f.owner);
    let mut response=f.json_upload(json!([{"id":id,"owner":f.owner,"name":"directory-user","password":BCRYPT,"passwordType":"bcrypt","ldap":reference}]),true).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let report: Value = response.take_json().await.unwrap();
    assert_eq!(report["created"], 1);
    let stored: (String, String) =
        sqlx::query_as("SELECT id,ldap FROM users WHERE owner=$1 AND name='directory-user'")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(stored, (id.clone(), reference));
    let mut login = f
        .login("directory-user", "correctbatteryhorsestapler")
        .await;
    assert_eq!(login.status_code, Some(StatusCode::OK));
    let account: Value = login.take_json().await.unwrap();
    assert_eq!(account["user"]["id"], id);
    assert_eq!(account["user"]["is_admin"], false);
    let token = account["token"].as_str().unwrap();
    let profile = TestClient::get(format!("http://localhost/api/users/{id}"))
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&f.service)
        .await;
    assert_eq!(
        profile.status_code,
        Some(StatusCode::OK),
        "a real legacy ID prefix must not become a virtual application identity"
    );
    let mut cross=f.json_upload(json!([{"owner":f.owner,"name":"wrong-directory","password":"plain-password","ldap":format!("{}/directory",f.other)}]),true).await;
    let report: Value = cross.take_json().await.unwrap();
    assert_eq!(report["created"], 0);
    assert_eq!(report["failed"], 1);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn masked_casdoor_mfa_markers_never_become_password_only_accounts_or_partially_import() {
    let f = Fixture::new().await;
    for (index, marker) in [
        json!({"preferredMfaType":"app","totpSecret":"","recoveryCodes":null}),
        json!({"preferred_mfa_type":"app","totp_secret":"","recovery_codes":[]}),
        json!({"preferredMfaType":"unknown-future-factor"}),
        json!({"preferredMfaType":" "}),
        json!({"preferredMfaType":true}),
        json!({"mfaRadiusEnabled":true}),
        json!({"mfa_push_enabled":true}),
        json!({"mfaRadiusEnabled":"true"}),
        json!({"mfaPushEnabled":1}),
    ]
    .into_iter()
    .enumerate()
    {
        // Ordinary get-users strips TOTP/recovery secrets. Even if an operator
        // supplies a valid replacement password, its MFA marker must survive
        // as a rejection, rather than disappearing from the inserted profile.
        let mut blocked = json!({"owner":f.owner,"name":format!("blocked-mfa-{index}"),"password":BCRYPT,"passwordType":"bcrypt"});
        blocked
            .as_object_mut()
            .unwrap()
            .extend(marker.as_object().unwrap().clone());
        let mut response=f.json_upload(json!([
            {"owner":f.owner,"name":format!("companion-mfa-{index}"),"password":BCRYPT,"passwordType":"bcrypt"},
            blocked
        ]),true).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let report: Value = response.take_json().await.unwrap();
        assert_eq!(report["created"], 0);
        assert_eq!(report["failed"], 2);
        assert!(report["errors"].to_string().contains("MFA"));
        assert!(!report.to_string().contains(BCRYPT));
    }
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM users WHERE owner=$1 AND (name LIKE 'blocked-mfa-%' OR name LIKE 'companion-mfa-%')").bind(&f.owner).fetch_one(&f.pool).await.unwrap();
    assert_eq!(
        count, 0,
        "a blocked MFA row must roll back every row in the upload"
    );
    let mut response=f.json_upload(json!([{"owner":f.owner,"name":"actually-no-mfa","password":BCRYPT,"passwordType":"bcrypt","preferredMfaType":"","mfaEnabled":false,"mfaPhoneEnabled":false,"mfaEmailEnabled":false,"mfaRadiusEnabled":false,"mfaPushEnabled":false}]),true).await;
    let report: Value = response.take_json().await.unwrap();
    assert_eq!(report["created"], 1);
    assert_eq!(
        f.login("actually-no-mfa", "correctbatteryhorsestapler")
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    f.cleanup().await;
}
