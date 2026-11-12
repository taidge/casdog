use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    handlers::parity_resources::marketplace::{self as themes, validate_theme},
    hoops::authz::Principal,
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

fn theme() -> Value {
    json!({"themeData":{"themeType":"dark","colorPrimary":"#123456","borderRadius":12,"isCompact":true,"isEnabled":true},"formOffset":3,"formCss":".login { color: red; }","formCssMobile":".login { color: blue; }","formSideHtml":"<div><strong>Welcome</strong></div>","footerHtml":"<p>Theme footer</p>","formBackgroundUrl":"/theme.png","formBackgroundUrlMobile":"/mobile.png"})
}
#[test]
fn safe_theme_styles_and_html_have_explicit_tenant_and_global_url_boundaries() {
    validate_theme(&theme(), false).unwrap();
    let mut links = theme();
    links["footerHtml"] = json!(
        "<a href='https://casdoor.org/'>Casdoor</a><a href='mailto:help@example.org'>Help</a>"
    );
    validate_theme(&links, false).unwrap();
    let mut external = theme();
    external["formCss"] = json!("div { background:url(https://example.org/theme.png); }");
    assert!(validate_theme(&external, false).is_err());
    validate_theme(&external, true).unwrap();
    for css in [
        "input[value^=a]{background:url(https://evil.invalid/a)}",
        "@import 'https://evil.invalid/x.css';",
        "@import '/unvalidated.css';",
        "a{background:u\\72l(https://evil.invalid)}",
        "a{background:image-set('https://evil.invalid/x')}",
        "a{background:url(https://cdn.casdoor.com/%2e%2e/evil)}",
    ] {
        let mut v = theme();
        v["formCss"] = json!(css);
        assert!(validate_theme(&v, false).is_err(), "{css}");
    }
    for html in [
        "<img src=x onerror=alert(1)>",
        "<script>alert(1)</script>",
        "<form action='/api/login'></form>",
        "<iframe src='/api/login'></iframe>",
        "<svg><style><img src=x onerror=alert(1)></style></svg>",
        "<a href='&#106;avascript:alert(1)'>click</a>",
    ] {
        let mut v = theme();
        v["footerHtml"] = json!(html);
        assert!(validate_theme(&v, true).is_err(), "{html}");
    }
    let mut unknown = theme();
    unknown["themeData"]["untrustedCss"] = json!("x");
    assert!(validate_theme(&unknown, false).is_err());
    let rendered=themes::render(&json!({"manifest":{"variables":[{"name":"label","required":true}]},"files":{"theme.json":{"footerHtml":"<p>{{label}}</p>"}}}),&json!({"variables":{"label":"<Team & Co>"}}),"theme.json").unwrap();
    assert_eq!(rendered["footerHtml"], "<p>&lt;Team &amp; Co&gt;</p>");
    validate_theme(&rendered, false).unwrap();
}
struct Fixture {
    pool: PgPool,
    service: Service,
    owner: String,
    other: String,
    app: String,
    admin: String,
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
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(create_diesel_pool(&url).await.unwrap()),
        );
        let owner = format!("themes-{}", uuid::Uuid::new_v4());
        let other = format!("themes-other-{}", uuid::Uuid::new_v4());
        let app = uuid::Uuid::new_v4().to_string();
        let admin = uuid::Uuid::new_v4().to_string();
        for tenant in [&owner, &other] {
            sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'Theme tenant')").bind(uuid::Uuid::new_v4().to_string()).bind(tenant).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,'admin','Admin','test-placeholder',true)").bind(&admin).bind(&owner).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,form_css,form_css_mobile,form_side_html,footer_html,form_background_url_mobile) VALUES($1,$2,'app','Themed App',$2,$1,'must-not-leak','',NULL,'','.old','',NULL)").bind(&app).bind(&owner).execute(&pool).await.unwrap();
        // Use valid HTML in the pre-theme snapshot, preserving its exact string.
        sqlx::query("UPDATE applications SET form_side_html='<p>old</p>' WHERE id=$1")
            .bind(&app)
            .execute(&pool)
            .await
            .unwrap();
        Self {
            pool,
            service,
            owner,
            other,
            app,
            admin,
        }
    }
    fn principal(&self) -> Principal {
        Principal {
            id: self.admin.clone(),
            owner: self.owner.clone(),
            name: "admin".into(),
            admin: true,
            application_identity: false,
        }
    }
    fn request(&self, name: &str) -> Value {
        json!({"owner":self.owner,"name":name,"application":self.app})
    }
    async fn install(&self, name: &str, value: Value) -> Result<Value, casdog::error::AppError> {
        themes::install(&self.pool,&self.principal(),&self.request(name),&json!({"name":{"en":"Theme"}}),&json!({"manifest":{"type":"theme","id":"test/theme","version":"1.0.0"},"files":{"theme.json":value}})).await
    }
    async fn snapshot(&self) -> Value {
        sqlx::query_scalar("SELECT jsonb_build_object('themeData',theme_data,'formOffset',form_offset,'formCss',form_css,'formCssMobile',form_css_mobile,'formSideHtml',form_side_html,'footerHtml',footer_html,'formBackgroundUrl',form_background_url,'formBackgroundUrlMobile',form_background_url_mobile) FROM applications WHERE id=$1").bind(&self.app).fetch_one(&self.pool).await.unwrap()
    }
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL with migrations 001-040"]
async fn theme_install_public_branding_and_uninstall_restore_all_eight_fields_including_null() {
    let f = Fixture::new().await;
    let before = f.snapshot().await;
    let installed = f.install("theme", theme()).await.unwrap();
    assert_eq!(installed["type"], "theme");
    assert_eq!(f.snapshot().await, theme());
    for reference in [&f.app, &format!("{}/app", f.owner)] {
        let mut response = TestClient::get(format!(
            "http://localhost/api/auth/branding?application={reference}"
        ))
        .send(&f.service)
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let value: Value = response.take_json().await.unwrap();
        assert_eq!(value["data"]["themeData"], theme()["themeData"]);
        assert_eq!(value["data"]["application"], format!("{}/app", f.owner));
        assert!(!value.to_string().contains("must-not-leak"));
        assert!(value["data"].get("providers").is_none());
    }
    assert!(f.install("second", theme()).await.is_err());
    assert!(
        themes::uninstall(&f.pool, &f.principal(), &f.owner, "theme")
            .await
            .unwrap()
    );
    assert_eq!(f.snapshot().await, before);
    f.install("reinstall", theme()).await.unwrap();
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL with migrations 001-040"]
async fn concurrent_themes_have_one_winner_and_unauthorized_or_bad_templates_leave_no_writes() {
    let f = Fixture::new().await;
    let before = f.snapshot().await;
    let mut bad = theme();
    bad["footerHtml"] = json!("<script>bad</script>");
    assert!(f.install("bad", bad).await.is_err());
    assert_eq!(f.snapshot().await, before);
    let mut stale = f.principal();
    stale.owner = f.other.clone();
    assert!(
        themes::install(
            &f.pool,
            &stale,
            &f.request("wrong"),
            &json!({}),
            &json!({"manifest":{"type":"theme"},"files":{"theme.json":theme()}})
        )
        .await
        .is_err()
    );
    let mut virtual_admin = f.principal();
    virtual_admin.application_identity = true;
    assert!(
        themes::install(
            &f.pool,
            &virtual_admin,
            &f.request("virtual"),
            &json!({}),
            &json!({"manifest":{"type":"theme"},"files":{"theme.json":theme()}})
        )
        .await
        .is_err()
    );
    let (a, b) = tokio::join!(f.install("one", theme()), f.install("two", theme()));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM casdoor_objects WHERE kind='integration' AND owner=$1",
    )
    .bind(&f.owner)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL with migrations 001-040"]
async fn branding_rechecks_live_policy_and_never_serves_unsafe_direct_application_edits() {
    let f = Fixture::new().await;
    f.install("theme", theme()).await.unwrap();
    sqlx::query("UPDATE applications SET form_css='div{background:url(https://evil.invalid/a)}' WHERE id=$1").bind(&f.app).execute(&f.pool).await.unwrap();
    assert!(themes::public_branding(&f.pool, &f.app).await.is_err());
    sqlx::query("UPDATE applications SET form_css=NULL WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET is_admin=false WHERE id=$1")
        .bind(&f.admin)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        themes::uninstall(&f.pool, &f.principal(), &f.owner, "theme")
            .await
            .is_err()
    );
    sqlx::query("UPDATE organizations SET disable_signin=true WHERE name=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(themes::public_branding(&f.pool, &f.app).await.is_err());
}
