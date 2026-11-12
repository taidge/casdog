use super::service::{authorize, identity, random_secret, text};
use crate::error::{AppError, AppResult};
use crate::hoops::authz::Principal;
use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::Duration;

const DEFAULT_MARKETPLACE: &str = "https://cdn.jsdelivr.net/gh/casdoor/casdoor-integrations@dist";
const THEME_FIELDS: [&str; 8] = [
    "themeData",
    "formOffset",
    "formCss",
    "formCssMobile",
    "formSideHtml",
    "footerHtml",
    "formBackgroundUrl",
    "formBackgroundUrlMobile",
];

fn theme_snapshot(app: &Value) -> Value {
    json!({"themeData":app["theme_data"],"formOffset":app["form_offset"],"formCss":app["form_css"],"formCssMobile":app["form_css_mobile"],"formSideHtml":app["form_side_html"],"footerHtml":app["footer_html"],"formBackgroundUrl":app["form_background_url"],"formBackgroundUrlMobile":app["form_background_url_mobile"]})
}
fn theme_error() -> AppError {
    AppError::Validation("Unsafe or invalid application theme".into())
}
fn trusted_url(value: &str, global: bool, font: bool) -> bool {
    if value.is_empty() {
        return true;
    }
    if value
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || ['\\', '<', '>', '\"', '\''].contains(&c))
    {
        return false;
    }
    let lowered = value.to_ascii_lowercase();
    if ["..", "%2e", "%2f", "%5c"]
        .iter()
        .any(|v| lowered.contains(v))
    {
        return false;
    }
    if value.starts_with('#') {
        return !font;
    }
    if value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains("..")
        && !value.contains('%')
    {
        return !font;
    }
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    if global && !font {
        return true;
    }
    let fonts = [
        "https://fonts.googleapis.com/",
        "https://fonts.gstatic.com/",
        "https://cdn.jsdelivr.net/npm/@fontsource/",
        "https://cdn.jsdelivr.net/npm/@fontsource-variable/",
    ];
    let trusted = [
        "https://cdn.jsdelivr.net/gh/casdoor/",
        "https://cdn.casbin.org/",
        "https://cdn.casdoor.com/",
        "https://cdn.casvisor.com/",
    ];
    let canonical = url.as_str();
    if fonts.iter().any(|p| canonical.starts_with(p)) {
        return true;
    }
    if font {
        return false;
    }
    if trusted.iter().any(|p| canonical.starts_with(p)) {
        return true;
    }
    if let Ok(origin) = super::super::social_login::public_origin() {
        if let Ok(origin) = reqwest::Url::parse(&origin) {
            if url.origin() == origin.origin() {
                return true;
            }
        }
    }
    false
}
pub fn validate_theme_css(css: &str, global: bool) -> AppResult<()> {
    if css.len() > 128 * 1024 {
        return Err(theme_error());
    }
    let lower = css.to_ascii_lowercase();
    if [
        "\\",
        "<",
        "/*",
        "*/",
        "image(",
        "image-set(",
        "cross-fade(",
        "element(",
        "src(",
        "expression(",
        "-moz-binding",
        "behavior:",
        "@namespace",
    ]
    .iter()
    .any(|v| lower.contains(v))
    {
        return Err(theme_error());
    }
    let urls = regex::Regex::new(r#"url\(\s*(?:"([^"]*)"|'([^']*)'|([^'"()\s]*))\s*\)"#).unwrap();
    let captures: Vec<_> = urls.captures_iter(&lower).collect();
    if captures.len() != lower.matches("url(").count() {
        return Err(theme_error());
    }
    for capture in captures {
        let value = (1..=3).find_map(|i| capture.get(i)).unwrap().as_str();
        if !trusted_url(value, global, false) {
            return Err(theme_error());
        }
    }
    let imports = regex::Regex::new(r#"@import\s+(?:url\(\s*)?(?:"([^"]*)"|'([^']*)')"#).unwrap();
    let captures: Vec<_> = imports.captures_iter(&lower).collect();
    if captures.len() != lower.matches("@import").count() {
        return Err(theme_error());
    }
    for capture in captures {
        if !trusted_url(
            (1..=2).find_map(|i| capture.get(i)).unwrap().as_str(),
            false,
            true,
        ) {
            return Err(theme_error());
        }
    }
    Ok(())
}
pub fn validate_theme_html(html: &str, global: bool) -> AppResult<()> {
    use html5ever::tendril::TendrilSink;
    use markup5ever_rcdom::{Handle, NodeData, RcDom};
    if html.len() > 128 * 1024 {
        return Err(theme_error());
    }
    let dom = html5ever::parse_document(RcDom::default(), Default::default()).one(html);
    fn walk(node: &Handle, global: bool, depth: usize, count: &mut usize) -> AppResult<()> {
        *count += 1;
        if depth > 32 || *count > 5000 {
            return Err(theme_error());
        }
        match &node.data {
            NodeData::Document | NodeData::Text { .. } => (),
            NodeData::Element { name, attrs, .. } => {
                let namespace: &str = name.ns.as_ref();
                if namespace != "http://www.w3.org/1999/xhtml" {
                    return Err(theme_error());
                }
                let tag = name.local.as_ref();
                if ![
                    "html", "head", "body", "div", "span", "p", "a", "img", "br", "hr", "strong",
                    "b", "em", "i", "small", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li",
                    "section", "header", "footer", "article", "main", "aside", "style",
                ]
                .contains(&tag)
                {
                    return Err(theme_error());
                }
                for attr in attrs.borrow().iter() {
                    let namespace: &str = attr.name.ns.as_ref();
                    if !namespace.is_empty() {
                        return Err(theme_error());
                    }
                    let key = attr.name.local.as_ref();
                    let value = attr.value.as_ref();
                    match key {
                        "style" => validate_theme_css(value, global)?,
                        "href" => {
                            if tag != "a"
                                || value
                                    .chars()
                                    .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
                            {
                                return Err(theme_error());
                            }
                            let safe = match reqwest::Url::parse(value) {
                                Ok(url) => {
                                    matches!(url.scheme(), "http" | "https" | "mailto" | "tel")
                                        && url.username().is_empty()
                                        && url.password().is_none()
                                }
                                Err(_) => !value.contains(':') && !value.starts_with("//"),
                            };
                            if !safe {
                                return Err(theme_error());
                            }
                        }
                        "src" => {
                            if tag != "img" || !trusted_url(value, global, false) {
                                return Err(theme_error());
                            }
                        }
                        "class" | "id" | "title" | "alt" | "width" | "height" | "role"
                        | "aria-label" | "rel" => (),
                        "target" => {
                            if !["_blank", "_self"].contains(&value) {
                                return Err(theme_error());
                            }
                        }
                        _ => return Err(theme_error()),
                    }
                }
                if tag == "style" {
                    for child in node.children.borrow().iter() {
                        match &child.data {
                            NodeData::Text { contents } => {
                                validate_theme_css(&contents.borrow(), global)?
                            }
                            _ => return Err(theme_error()),
                        }
                    }
                }
            }
            _ => return Err(theme_error()),
        }
        for child in node.children.borrow().iter() {
            walk(child, global, depth + 1, count)?;
        }
        Ok(())
    }
    walk(&dom.document, global, 0, &mut 0)
}
fn theme_digest(theme: &Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(theme).expect("theme JSON"))
    )
}
pub fn validate_theme(theme: &Value, global: bool) -> AppResult<()> {
    let object = theme.as_object().ok_or_else(theme_error)?;
    if object.keys().any(|k| !THEME_FIELDS.contains(&k.as_str())) {
        return Err(theme_error());
    }
    if let Some(value) = object.get("formOffset").filter(|v| !v.is_null()) {
        if !value.as_i64().is_some_and(|n| (0..=4).contains(&n)) {
            return Err(theme_error());
        }
    }
    if let Some(value) = object.get("themeData").filter(|v| !v.is_null()) {
        let object = value.as_object().ok_or_else(theme_error)?;
        for (key, value) in object {
            let valid = match key.as_str() {
                "themeType" => value
                    .as_str()
                    .is_some_and(|v| ["", "default", "light", "dark"].contains(&v)),
                "colorPrimary" => value.as_str().is_some_and(|v| {
                    v.is_empty()
                        || ((v.len() == 7 || v.len() == 4)
                            && v.starts_with('#')
                            && v[1..].bytes().all(|c| c.is_ascii_hexdigit()))
                }),
                "borderRadius" => value.as_u64().is_some_and(|v| v <= 100),
                "isCompact" | "isEnabled" => value.is_boolean(),
                _ => false,
            };
            if !valid {
                return Err(theme_error());
            }
        }
    }
    for field in &THEME_FIELDS[2..] {
        let Some(value) = object.get(*field).filter(|v| !v.is_null()) else {
            continue;
        };
        let value = value.as_str().ok_or_else(theme_error)?;
        match *field {
            "formCss" | "formCssMobile" => validate_theme_css(value, global)?,
            "formSideHtml" | "footerHtml" => validate_theme_html(value, global)?,
            _ => {
                if value.len() > 512 || !trusted_url(value, global, false) {
                    return Err(theme_error());
                }
            }
        }
    }
    Ok(())
}
async fn theme_admin(conn: &mut sqlx::PgConnection, p: &Principal, owner: &str) -> AppResult<()> {
    authorize(p, owner)?;
    if !p.admin || p.is_application() {
        return Err(super::service::denied());
    }
    let current:Option<bool>=sqlx::query_scalar("SELECT true FROM users WHERE id=$1 AND owner=$2 AND name=$3 AND is_admin AND NOT is_deleted AND NOT is_forbidden FOR SHARE").bind(&p.id).bind(&p.owner).bind(&p.name).fetch_optional(&mut *conn).await?;
    if current != Some(true) {
        return Err(super::service::denied());
    }
    Ok(())
}
async fn write_theme(conn: &mut sqlx::PgConnection, id: &str, theme: &Value) -> AppResult<()> {
    sqlx::query("UPDATE applications SET theme_data=$2,form_offset=$3,form_css=$4,form_css_mobile=$5,form_side_html=$6,footer_html=$7,form_background_url=$8,form_background_url_mobile=$9,updated_at=clock_timestamp() WHERE id=$1")
        .bind(id).bind(theme.get("themeData").filter(|v|!v.is_null())).bind(theme["formOffset"].as_i64().unwrap_or(0) as i32)
        .bind(theme["formCss"].as_str()).bind(theme["formCssMobile"].as_str()).bind(theme["formSideHtml"].as_str()).bind(theme["footerHtml"].as_str()).bind(theme["formBackgroundUrl"].as_str()).bind(theme["formBackgroundUrlMobile"].as_str()).execute(conn).await?;
    Ok(())
}
async fn install_theme(
    pool: &PgPool,
    p: &Principal,
    request: &Value,
    item: &Value,
    bundle: &Value,
) -> AppResult<Value> {
    let owner = text(request, "owner");
    let name = text(request, "name");
    let reference = text(request, "application");
    if reference.is_empty() {
        return Err(AppError::Validation(
            "Choose an application to theme".into(),
        ));
    }
    let mut theme = render(bundle, request, "theme.json")?;
    validate_theme(&theme, p.global_admin())?;
    if theme.get("formOffset").is_none_or(Value::is_null) {
        theme["formOffset"] = json!(2);
    }
    let mut tx = pool.begin().await?;
    theme_admin(&mut tx, p, owner).await?;
    let apps:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(a) FROM applications a JOIN organizations o ON o.name=a.organization WHERE a.organization=$1 AND (a.id=$2 OR a.owner||'/'||a.name=$2 OR a.name=$2) AND NOT a.is_deleted AND NOT o.is_deleted AND NOT o.disable_signin LIMIT 2 FOR UPDATE OF a").bind(owner).bind(reference).fetch_all(&mut *tx).await?;
    if apps.len() != 1 {
        return Err(AppError::Validation(
            "Unambiguous application in target organization required".into(),
        ));
    }
    let app = &apps[0];
    let id = text(app, "id");
    // Never successfully install a theme whose exact backup this principal
    // would be forbidden to restore. This also fences unsupported legacy CSS.
    validate_theme(&theme_snapshot(app), p.global_admin())?;
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM casdoor_objects WHERE kind='integration' AND document->>'type'='theme' AND document->>'resourceId'=$1)").bind(id).fetch_one(&mut *tx).await?;
    if active {
        return Err(AppError::Conflict(
            "Uninstall the application's current theme first".into(),
        ));
    }
    // Fill omitted optional values with explicit NULL for stable snapshots and
    // approval fingerprints; global approval cannot survive later field edits.
    for field in THEME_FIELDS {
        if theme.get(field).is_none() {
            theme[field] = Value::Null;
        }
    }
    let document = json!({"owner":owner,"name":name,"displayName":item["name"]["en"].as_str().unwrap_or(name),"type":"theme","integrationId":bundle["manifest"]["id"],"version":bundle["manifest"]["version"],"application":format!("{}/{}",text(app,"owner"),text(app,"name")),"resourceId":id,"backup":theme_snapshot(app),"themeTrustedGlobal":p.global_admin(),"themeFingerprint":theme_digest(&theme),"createdTime":Utc::now().to_rfc3339(),"updatedTime":Utc::now().to_rfc3339()});
    sqlx::query(
        "INSERT INTO casdoor_objects(kind,owner,name,document) VALUES('integration',$1,$2,$3)",
    )
    .bind(owner)
    .bind(name)
    .bind(&document)
    .execute(&mut *tx)
    .await?;
    write_theme(&mut tx, id, &theme).await?;
    tx.commit().await?;
    Ok(super::service::masked(
        super::service::Kind::Integration,
        document,
        false,
    ))
}
async fn uninstall_theme(
    pool: &PgPool,
    p: &Principal,
    owner: &str,
    name: &str,
    initial: &Value,
) -> AppResult<bool> {
    let mut tx = pool.begin().await?;
    theme_admin(&mut tx, p, owner).await?;
    let id = text(initial, "resourceId");
    let app: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(a) FROM applications a WHERE id=$1 AND organization=$2 FOR UPDATE",
    )
    .bind(id)
    .bind(owner)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(app) = app else {
        return Err(AppError::Conflict(
            "Theme application unavailable; manual review required".into(),
        ));
    };
    let current:Option<Value>=sqlx::query_scalar("SELECT document FROM casdoor_objects WHERE kind='integration' AND owner=$1 AND name=$2 FOR UPDATE").bind(owner).bind(name).fetch_optional(&mut *tx).await?;
    let Some(current) = current else {
        return Ok(false);
    };
    if current != *initial
        || text(&current, "type") != "theme"
        || text(&current, "resourceId") != id
    {
        return Err(AppError::Conflict("Theme binding changed".into()));
    }
    // Restore the exact snapshot, including NULL versus empty string. A tenant
    // must not regain trusted custom code through another admin's old backup.
    let backup = &current["backup"];
    validate_theme(backup, p.global_admin())?;
    if text(&app, "id") != id {
        return Err(theme_error());
    }
    write_theme(&mut tx, id, backup).await?;
    sqlx::query("DELETE FROM casdoor_objects WHERE kind='integration' AND owner=$1 AND name=$2")
        .bind(owner)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}
pub async fn public_branding(pool: &PgPool, reference: &str) -> AppResult<Value> {
    if reference.is_empty() || reference.len() > 256 {
        return Err(theme_error());
    }
    let apps:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(a) FROM applications a JOIN organizations o ON o.name=a.organization WHERE (a.id=$1 OR a.owner||'/'||a.name=$1 OR a.client_id=$1) AND NOT a.is_deleted AND NOT o.is_deleted AND NOT o.disable_signin LIMIT 2").bind(reference).fetch_all(pool).await?;
    if apps.len() != 1 {
        return Err(AppError::NotFound(
            "Application branding unavailable".into(),
        ));
    }
    let app = &apps[0];
    let mut theme = theme_snapshot(app);
    let global:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM casdoor_objects WHERE kind='integration' AND document->>'type'='theme' AND document->>'resourceId'=$1 AND document->'themeTrustedGlobal'='true'::jsonb AND document->>'themeFingerprint'=$2)").bind(text(app,"id")).bind(theme_digest(&theme)).fetch_one(pool).await?;
    validate_theme(&theme, global)?;
    for key in ["logo"] {
        if let Some(value) = app[key].as_str() {
            if !trusted_url(value, true, false) {
                return Err(theme_error());
            }
        }
    }
    let object = theme.as_object_mut().unwrap();
    object.insert(
        "application".into(),
        json!(format!("{}/{}", text(app, "owner"), text(app, "name"))),
    );
    for (out, key) in [
        ("applicationId", "id"),
        ("organization", "organization"),
        ("displayName", "display_name"),
        ("logo", "logo"),
    ] {
        object.insert(out.into(), app[key].clone());
    }
    Ok(json!({"status":"ok","data":theme}))
}
pub fn base_url() -> String {
    std::env::var("CASDOG_MARKETPLACE_URL")
        .unwrap_or_else(|_| DEFAULT_MARKETPLACE.into())
        .trim_end_matches('/')
        .to_string()
}

pub async fn fetch(url: &str) -> AppResult<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AppError::Internal("HTTP client unavailable".into()))?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| AppError::Validation(format!("Remote catalog unavailable: {e}")))?;
    if !response.status().is_success() {
        return Err(AppError::Validation(format!(
            "Remote catalog returned {}",
            response.status()
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AppError::Validation("Cannot read remote response".into()))?
    {
        if bytes.len() + chunk.len() > 10 * 1024 * 1024 {
            return Err(AppError::Validation("Remote catalog exceeds 10 MiB".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub async fn index(base: &str) -> AppResult<Value> {
    let mut data: Value = serde_json::from_slice(&fetch(&format!("{base}/index.json")).await?)
        .map_err(|_| AppError::Validation("Invalid marketplace index".into()))?;
    if !data.get("integrations").is_some_and(Value::is_array) {
        return Err(AppError::Validation(
            "Marketplace integrations array missing".into(),
        ));
    }
    data["baseUrl"] = json!(base);
    for item in data["integrations"].as_array_mut().unwrap() {
        if let Some(logo) = item
            .get("logo")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty() && !v.starts_with("https://") && !v.starts_with("http://"))
        {
            item["logo"] = json!(format!("{base}/{}", logo.trim_start_matches('/')));
        }
        if let Some(screenshots) = item.get_mut("screenshots").and_then(Value::as_array_mut) {
            for image in screenshots {
                if let Some(path) = image
                    .as_str()
                    .filter(|v| !v.starts_with("https://") && !v.starts_with("http://"))
                {
                    *image = json!(format!("{base}/{}", path.trim_start_matches('/')));
                }
            }
        }
    }
    Ok(data)
}
pub fn validate_bundle(
    index: &Value,
    id: &str,
    version: &str,
    bytes: &[u8],
) -> AppResult<(Value, Value)> {
    let item = index["integrations"]
        .as_array()
        .and_then(|items| items.iter().find(|item| text(item, "id") == id))
        .ok_or_else(|| AppError::NotFound("Integration not in marketplace".into()))?;
    let version = if version.is_empty() {
        text(item, "latest")
    } else {
        version
    };
    if index["revoked"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|v| text(v, "id") == id && text(v, "version") == version)
    }) {
        return Err(AppError::Validation(
            "Integration version was withdrawn".into(),
        ));
    }
    let release = item["versions"]
        .as_array()
        .and_then(|items| items.iter().find(|v| text(v, "version") == version))
        .ok_or_else(|| AppError::NotFound("Integration version not found".into()))?;
    if !hex::encode(Sha256::digest(bytes)).eq_ignore_ascii_case(text(release, "sha256")) {
        return Err(AppError::Validation(
            "Marketplace bundle checksum mismatch".into(),
        ));
    }
    let bundle: Value = serde_json::from_slice(bytes)
        .map_err(|_| AppError::Validation("Invalid marketplace bundle JSON".into()))?;
    if text(&bundle["manifest"], "id") != id
        || text(&bundle["manifest"], "version") != version
        || text(&bundle["manifest"], "type") != text(item, "type")
        || !bundle["files"].is_object()
    {
        return Err(AppError::Validation(
            "Bundle manifest does not match catalog".into(),
        ));
    }
    Ok((item.clone(), bundle))
}
pub async fn bundle(base: &str, id: &str, version: &str) -> AppResult<(Value, Value)> {
    let index = index(base).await?;
    let item = index["integrations"]
        .as_array()
        .and_then(|items| items.iter().find(|item| text(item, "id") == id))
        .ok_or_else(|| AppError::NotFound("Integration not in marketplace".into()))?;
    let version = if version.is_empty() {
        text(item, "latest")
    } else {
        version
    };
    let release = item["versions"]
        .as_array()
        .and_then(|items| items.iter().find(|v| text(v, "version") == version))
        .ok_or_else(|| AppError::NotFound("Integration version not found".into()))?;
    let root = reqwest::Url::parse(&format!("{base}/"))
        .map_err(|_| AppError::Validation("Invalid marketplace base URL".into()))?;
    let url = root
        .join(text(release, "url"))
        .map_err(|_| AppError::Validation("Invalid bundle URL".into()))?;
    if url.origin() != root.origin() || !url.path().starts_with(root.path()) {
        return Err(AppError::Validation(
            "Bundle URL must stay inside the configured marketplace".into(),
        ));
    }
    let bytes = fetch(url.as_str()).await?;
    validate_bundle(&index, id, version, &bytes)
}

pub fn render(bundle: &Value, request: &Value, file: &str) -> AppResult<Value> {
    let mut variables = serde_json::Map::new();
    if let Some(fields) = bundle["manifest"]["variables"].as_array() {
        for field in fields {
            let key = text(field, "name");
            let mut value = text(&request["variables"], key).trim().to_string();
            if field["required"] == true && value.is_empty() {
                return Err(AppError::Validation(format!("Variable {key} is required")));
            }
            if !value.is_empty() {
                match text(field, "type") {
                    "url" => {
                        let url = reqwest::Url::parse(&value).map_err(|_| {
                            AppError::Validation(format!("Invalid URL variable {key}"))
                        })?;
                        if !matches!(url.scheme(), "https" | "http")
                            || url.host_str().is_none()
                            || value.chars().any(|c| {
                                c.is_whitespace() || ['\"', '\'', '<', '>', '`'].contains(&c)
                            })
                        {
                            return Err(AppError::Validation(format!(
                                "Invalid URL variable {key}"
                            )));
                        }
                        value = value.trim_end_matches('/').into();
                    }
                    "color" => {
                        if value.len() != 7
                            || !value.starts_with('#')
                            || !value[1..].bytes().all(|b| b.is_ascii_hexdigit())
                        {
                            return Err(AppError::Validation(format!(
                                "Invalid color variable {key}"
                            )));
                        }
                    }
                    _ => {
                        if value.len() > 500 {
                            return Err(AppError::Validation(format!("Variable {key} too long")));
                        }
                    }
                }
            }
            variables.insert(key.into(), json!(value));
        }
    }
    let mut data = bundle["files"]
        .get(file)
        .cloned()
        .ok_or_else(|| AppError::Validation(format!("Bundle has no {file}")))?;
    if data.is_string() {
        data = serde_json::from_str(data.as_str().unwrap())
            .map_err(|_| AppError::Validation("Invalid template JSON".into()))?;
    }
    fn replace(
        value: &mut Value,
        variables: &serde_json::Map<String, Value>,
        theme: bool,
        html: bool,
    ) {
        match value {
            Value::String(s) => {
                let re = regex::Regex::new(r"\{\{\s*([a-zA-Z][a-zA-Z0-9]*)\s*\}\}").unwrap();
                *s = re
                    .replace_all(s, |caps: &regex::Captures| {
                        let value = variables
                            .get(&caps[1])
                            .and_then(Value::as_str)
                            .unwrap_or(&caps[0])
                            .to_string();
                        if html {
                            value
                                .replace('&', "&amp;")
                                .replace('<', "&lt;")
                                .replace('>', "&gt;")
                                .replace('"', "&quot;")
                                .replace('\'', "&#39;")
                        } else {
                            value
                        }
                    })
                    .into_owned();
            }
            Value::Object(map) => {
                for (key, value) in map.iter_mut() {
                    replace(
                        value,
                        variables,
                        theme,
                        theme && matches!(key.as_str(), "formSideHtml" | "footerHtml"),
                    )
                }
            }
            Value::Array(array) => {
                for value in array {
                    replace(value, variables, theme, html)
                }
            }
            _ => {}
        }
    }
    replace(&mut data, &variables, file == "theme.json", false);
    Ok(data)
}

pub async fn install(
    pool: &PgPool,
    principal: &Principal,
    request: &Value,
    item: &Value,
    bundle: &Value,
) -> AppResult<Value> {
    let owner = text(request, "owner");
    let name = text(request, "name");
    authorize(principal, owner)?;
    identity(owner, name)?;
    if text(&bundle["manifest"], "type") == "app"
        && (principal.is_application() || !principal.admin || name.starts_with("dcr_"))
    {
        return Err(AppError::Authorization(
            "A real administrator must create a static application integration".into(),
        ));
    }
    if item["requiresGlobalAdmin"] == true && !principal.global_admin() {
        return Err(super::service::denied());
    }
    let kind = text(&bundle["manifest"], "type");
    if kind == "theme" {
        return install_theme(pool, principal, request, item, bundle).await;
    }
    if !["app", "provider"].contains(&kind) {
        return Err(AppError::Validation("Only application and provider integrations are currently supported; theme installation is not implemented".into()));
    }
    let template = render(
        bundle,
        request,
        if kind == "app" {
            "application.json"
        } else {
            "provider.json"
        },
    )?;
    let display = item["name"]["en"].as_str().unwrap_or(name);
    let resource_id = uuid::Uuid::new_v4().to_string();
    let mut document = json!({"owner":owner,"name":name,"displayName":display,"createdTime":Utc::now().to_rfc3339(),"updatedTime":Utc::now().to_rfc3339(),"integrationId":text(&bundle["manifest"],"id"),"type":kind,"version":text(&bundle["manifest"],"version"),"logo":text(item,"logo"),"variables":request.get("variables").cloned().unwrap_or_else(||json!({})),"bundle":bundle.to_string(),"resourceId":resource_id});
    let mut tx = pool.begin().await?;
    // The envelope is inserted in the same transaction as its resource and application linkage.
    sqlx::query(
        "INSERT INTO casdoor_objects(kind,owner,name,document) VALUES('integration',$1,$2,$3)",
    )
    .bind(owner)
    .bind(name)
    .bind(&document)
    .execute(&mut *tx)
    .await?;
    if kind == "app" {
        let redirects = template
            .get("redirectUris")
            .cloned()
            .unwrap_or_else(|| json!([]));
        if !redirects
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string))
        {
            return Err(AppError::Validation(
                "redirectUris must be string array".into(),
            ));
        }
        for redirect in redirects.as_array().unwrap() {
            let url = reqwest::Url::parse(redirect.as_str().unwrap())
                .map_err(|_| AppError::Validation("Invalid redirect URI".into()))?;
            if !matches!(url.scheme(), "http" | "https") || url.fragment().is_some() {
                return Err(AppError::Validation("Invalid redirect URI".into()));
            }
        }
        let grants = template
            .get("grantTypes")
            .cloned()
            .unwrap_or_else(|| json!(["authorization_code", "refresh_token"]));
        if !grants.as_array().is_some_and(|values| {
            values.iter().all(|v| {
                v.as_str().is_some_and(|s| {
                    [
                        "authorization_code",
                        "refresh_token",
                        "client_credentials",
                        "password",
                        "urn:ietf:params:oauth:grant-type:device_code",
                    ]
                    .contains(&s)
                })
            })
        }) {
            return Err(AppError::Validation("Invalid grantTypes".into()));
        }
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,logo,homepage_url,organization,client_id,client_secret,redirect_uris,grant_types,token_format) VALUES($1,$2,$3,$4,$5,$6,$2,$7,$8,$9,$10,$11)")
            .bind(&resource_id).bind(owner).bind(name).bind(display).bind(text(item,"logo")).bind(text(&request["variables"],"appUrl")).bind(random_secret()).bind(random_secret()).bind(redirects.to_string()).bind(grants).bind(template.get("tokenFormat").and_then(Value::as_str).filter(|s|!s.is_empty()).unwrap_or("JWT")).execute(&mut *tx).await?;
        crate::services::key_credentials_service::mark_static_application_conn(
            &mut tx,
            &resource_id,
            principal,
        )
        .await?;
        document["application"] = json!(name);
    } else {
        if text(request, "clientId").is_empty() || text(request, "clientSecret").is_empty() {
            return Err(AppError::Validation(
                "clientId and clientSecret are required".into(),
            ));
        }
        if text(&template, "category").is_empty() || text(&template, "type").is_empty() {
            return Err(AppError::Validation(
                "Provider category and type are required".into(),
            ));
        }
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,method,client_id,client_secret,scopes,custom_auth_url,custom_token_url,custom_user_info_url,issuer_url,provider_url,custom_logo) VALUES($1,$2,$3,$4,$5,$6,'Normal',$7,$8,$9,$10,$11,$12,$13,$14,$15)")
            .bind(&resource_id).bind(owner).bind(name).bind(display).bind(text(&template,"category")).bind(text(&template,"type")).bind(text(request,"clientId")).bind(text(request,"clientSecret")).bind(text(&template,"scopes")).bind(text(&template,"customAuthUrl")).bind(text(&template,"customTokenUrl")).bind(text(&template,"customUserInfoUrl")).bind(text(&template,"issuerUrl")).bind(text(&template,"providerUrl")).bind(text(item,"logo")).execute(&mut *tx).await?;
        document["provider"] = json!(name);
        let app = text(request, "application");
        if !app.is_empty() {
            let app_name = app.split_once('/').map(|(_, n)| n).unwrap_or(app);
            let app_id:Option<String>=sqlx::query_scalar("SELECT id FROM applications WHERE organization=$1 AND name=$2 AND NOT is_deleted FOR UPDATE").bind(owner).bind(app_name).fetch_optional(&mut *tx).await?;
            let app_id = app_id.ok_or_else(|| {
                AppError::Validation("Application does not belong to this organization".into())
            })?;
            let entry = json!([{"owner":owner,"name":name,"canSignUp":true,"canSignIn":true,"canUnlink":true,"rule":"None"}]);
            sqlx::query("UPDATE applications SET providers=COALESCE(providers,'[]'::jsonb)||$2::jsonb,updated_at=NOW() WHERE id=$1").bind(app_id).bind(entry).execute(&mut *tx).await?;
            document["application"] = json!(app_name);
        }
    }
    sqlx::query(
        "UPDATE casdoor_objects SET document=$3 WHERE kind='integration' AND owner=$1 AND name=$2",
    )
    .bind(owner)
    .bind(name)
    .bind(&document)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(super::service::masked(
        super::service::Kind::Integration,
        document,
        false,
    ))
}

pub async fn uninstall(
    pool: &PgPool,
    principal: &Principal,
    owner: &str,
    name: &str,
) -> AppResult<bool> {
    authorize(principal, owner)?;
    let theme:Option<Value>=sqlx::query_scalar("SELECT document FROM casdoor_objects WHERE kind='integration' AND owner=$1 AND name=$2 AND document->>'type'='theme'").bind(owner).bind(name).fetch_optional(pool).await?;
    if let Some(theme) = theme {
        return uninstall_theme(pool, principal, owner, name, &theme).await;
    }
    let mut tx = pool.begin().await?;
    let document:Option<Value>=sqlx::query_scalar("SELECT document FROM casdoor_objects WHERE kind='integration' AND owner=$1 AND name=$2 FOR UPDATE").bind(owner).bind(name).fetch_optional(&mut *tx).await?;
    let Some(document) = document else {
        return Ok(false);
    };
    let resource = text(&document, "resourceId");
    match text(&document, "type") {
        "app" => {
            sqlx::query("DELETE FROM tokens WHERE owner=$1 AND application=$2")
                .bind(owner)
                .bind(text(&document, "application"))
                .execute(&mut *tx)
                .await?;
            // Installation creates a new resource; remove that exact resource so
            // its unique owner/name becomes available for a later reinstall.
            sqlx::query("DELETE FROM applications WHERE id=$1 AND organization=$2")
                .bind(resource)
                .bind(owner)
                .execute(&mut *tx)
                .await?;
        }
        "provider" => {
            sqlx::query("UPDATE applications SET providers=(SELECT COALESCE(jsonb_agg(p),'[]'::jsonb) FROM jsonb_array_elements(COALESCE(providers,'[]'::jsonb)) p WHERE NOT(p->>'owner'=$2 AND p->>'name'=$3)),updated_at=NOW() WHERE organization=$1")
                .bind(owner).bind(owner).bind(text(&document,"provider")).execute(&mut *tx).await?;
            sqlx::query("DELETE FROM providers WHERE id=$1 AND owner=$2")
                .bind(resource)
                .bind(owner)
                .execute(&mut *tx)
                .await?;
        }
        _ => {
            return Err(AppError::Validation(
                "Unsupported installed integration type".into(),
            ));
        }
    }
    sqlx::query("DELETE FROM casdoor_objects WHERE kind='integration' AND owner=$1 AND name=$2")
        .bind(owner)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}
