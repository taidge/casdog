//! Casdoor XLSX uploads and explicit JSON/CSV extensions. Credentials are never
//! trimmed, unquoted heuristically, logged, or rehashed after declaring a type.
use crate::{
    error::{AppError, AppResult},
    hoops::authz::{Principal, validate_references},
    services::password_service::PasswordService,
};
use quick_xml::{Reader, XmlVersion, events::Event};
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Postgres, QueryBuilder};
use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Read},
};

pub const MAX_UPLOAD: usize = 8 * 1024 * 1024;
const MAX_ROWS: usize = 1000;
const MAX_COLS: usize = 128;
fn invalid(message: &str) -> AppError {
    AppError::Validation(message.into())
}
#[derive(Default)]
struct Node {
    name: String,
    attrs: HashMap<String, String>,
    text: String,
    children: Vec<Node>,
}
impl Node {
    fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|n| n.name == name)
    }
    fn text(&self) -> String {
        if self.name == "t" {
            return self.text.clone();
        }
        self.children
            .iter()
            .filter(|c| c.name != "rPh")
            .map(Node::text)
            .collect()
    }
}
fn xml(bytes: &[u8]) -> AppResult<Node> {
    let content = std::str::from_utf8(bytes).map_err(|_| invalid("XLSX XML must use UTF-8"))?;
    let mut reader = Reader::from_str(content);
    let mut stack = vec![Node::default()];
    let mut count = 0;
    loop {
        match reader
            .read_event()
            .map_err(|_| invalid("Invalid XLSX XML"))?
        {
            event @ (Event::Start(_) | Event::Empty(_)) => {
                let empty = matches!(&event, Event::Empty(_));
                let e = match event {
                    Event::Start(e) | Event::Empty(e) => e,
                    _ => unreachable!(),
                };
                let mut node = Node {
                    name: e.local_name().as_ref().into(),
                    ..Default::default()
                };
                for attr in e.attributes() {
                    let attr = attr.map_err(|_| invalid("Invalid XLSX attributes"))?;
                    node.attrs.insert(
                        attr.key.as_ref().into(),
                        attr.normalized_value(XmlVersion::Implicit1_0)
                            .map_err(|_| invalid("Invalid XLSX entity"))?
                            .into_owned(),
                    );
                }
                count += 1;
                if count > 200_000 || stack.len() > 32 {
                    return Err(invalid("XLSX XML structure exceeds limits"));
                }
                if empty {
                    stack.last_mut().unwrap().children.push(node);
                } else {
                    stack.push(node);
                }
            }
            Event::End(_) => {
                if stack.len() <= 1 {
                    return Err(invalid("Invalid XLSX nesting"));
                }
                let node = stack.pop().unwrap();
                stack.last_mut().unwrap().children.push(node);
            }
            Event::Text(text) => stack
                .last_mut()
                .unwrap()
                .text
                .push_str(&text.xml10_content()),
            Event::CData(text) => stack
                .last_mut()
                .unwrap()
                .text
                .push_str(&text.xml10_content()),
            Event::GeneralRef(reference) => {
                let text = if let Some(ch) = reference
                    .resolve_char_ref()
                    .map_err(|_| invalid("Invalid XLSX entity"))?
                {
                    ch.to_string()
                } else {
                    quick_xml::escape::resolve_predefined_entity(reference.as_ref())
                        .ok_or_else(|| invalid("Custom XML entities are not supported"))?
                        .into()
                };
                stack.last_mut().unwrap().text.push_str(&text);
            }
            Event::DocType(_) => {
                return Err(invalid("XML DTDs and external entities are forbidden"));
            }
            Event::Eof => break,
            _ => (),
        }
    }
    if stack.len() != 1 || stack[0].children.len() != 1 {
        return Err(invalid("Invalid XLSX document"));
    }
    Ok(stack.pop().unwrap().children.pop().unwrap())
}
fn xlsx(bytes: &[u8]) -> AppResult<Vec<Vec<String>>> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| invalid("Invalid XLSX archive"))?;
    if archive.len() > 128 {
        return Err(invalid("XLSX has too many ZIP entries"));
    }
    let mut total = 0u64;
    let mut names = HashSet::new();
    for i in 0..archive.len() {
        let file = archive
            .by_index(i)
            .map_err(|_| invalid("Invalid XLSX entry"))?;
        total = total
            .checked_add(file.size())
            .ok_or_else(|| invalid("XLSX size overflow"))?;
        if file.size() > MAX_UPLOAD as u64
            || total > 32 * 1024 * 1024
            || !names.insert(file.name().to_owned())
        {
            return Err(invalid(
                "XLSX expanded size or duplicate entry exceeds limits",
            ));
        }
    }
    fn part(archive: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str) -> AppResult<Vec<u8>> {
        let file = archive
            .by_name(name)
            .map_err(|_| invalid("XLSX required worksheet part is missing"))?;
        let mut bytes = Vec::new();
        file.take((MAX_UPLOAD + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid("Could not read XLSX part"))?;
        if bytes.len() > MAX_UPLOAD {
            return Err(invalid("XLSX part exceeds limits"));
        }
        Ok(bytes)
    }
    let workbook = xml(&part(&mut archive, "xl/workbook.xml")?)?;
    let sheet = workbook
        .child("sheets")
        .and_then(|n| n.children.iter().find(|n| n.name == "sheet"))
        .ok_or_else(|| invalid("XLSX has no worksheet"))?;
    let id = sheet
        .attrs
        .iter()
        .find(|(key, _)| key.rsplit(':').next() == Some("id"))
        .map(|(_, value)| value)
        .ok_or_else(|| invalid("XLSX sheet relationship is missing"))?;
    let relations = xml(&part(&mut archive, "xl/_rels/workbook.xml.rels")?)?;
    let relation = relations
        .children
        .iter()
        .find(|n| n.attrs.get("Id") == Some(id))
        .ok_or_else(|| invalid("XLSX sheet relationship is invalid"))?;
    let target = relation
        .attrs
        .get("Target")
        .ok_or_else(|| invalid("XLSX sheet target is missing"))?;
    if relation
        .attrs
        .get("TargetMode")
        .is_some_and(|v| v == "External")
        || target.contains("..")
        || target.contains('\\')
        || target.contains(':')
    {
        return Err(invalid("External or unsafe XLSX worksheet target"));
    }
    let path = if let Some(path) = target.strip_prefix("/xl/") {
        format!("xl/{path}")
    } else {
        format!("xl/{target}")
    };
    let strings = if names.contains("xl/sharedStrings.xml") {
        let root = xml(&part(&mut archive, "xl/sharedStrings.xml")?)?;
        if root.children.len() > 50_000 {
            return Err(invalid("Too many XLSX shared strings"));
        }
        root.children
            .iter()
            .filter(|n| n.name == "si")
            .map(Node::text)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let sheet = xml(&part(&mut archive, &path)?)?;
    let data = sheet
        .child("sheetData")
        .ok_or_else(|| invalid("XLSX sheetData is missing"))?;
    let mut rows = Vec::new();
    let mut decoded_size = 0usize;
    for row in data.children.iter().filter(|n| n.name == "row") {
        if rows.len() > MAX_ROWS {
            return Err(invalid("Too many uploaded users"));
        }
        let mut values = Vec::new();
        let mut columns_seen = HashSet::new();
        for cell in row.children.iter().filter(|n| n.name == "c") {
            let column = if let Some(reference) = cell.attrs.get("r") {
                let mut column = 0usize;
                for byte in reference.bytes().take_while(u8::is_ascii_alphabetic) {
                    column = column
                        .checked_mul(26)
                        .and_then(|n| {
                            n.checked_add((byte.to_ascii_uppercase() - b'A' + 1) as usize)
                        })
                        .ok_or_else(|| invalid("Invalid XLSX column"))?;
                }
                column
                    .checked_sub(1)
                    .ok_or_else(|| invalid("Invalid XLSX cell reference"))?
            } else {
                values.len()
            };
            if column >= MAX_COLS {
                return Err(invalid("Too many XLSX columns"));
            }
            if !columns_seen.insert(column) {
                return Err(invalid("Duplicate XLSX cell reference"));
            }
            if cell.child("f").is_some() {
                return Err(invalid("Formula cells cannot be imported as user data"));
            }
            let raw = cell.child("v").map(|n| n.text.as_str()).unwrap_or_default();
            let value = match cell.attrs.get("t").map(String::as_str) {
                Some("s") => strings
                    .get(
                        raw.parse::<usize>()
                            .map_err(|_| invalid("Invalid shared string index"))?,
                    )
                    .ok_or_else(|| invalid("Missing shared string"))?
                    .clone(),
                Some("inlineStr") => cell.child("is").map(Node::text).unwrap_or_default(),
                Some("e") => return Err(invalid("Excel error cells cannot be imported")),
                _ => raw.into(),
            };
            if value.len() > 65_536 {
                return Err(invalid("Uploaded cell is too large"));
            }
            decoded_size = decoded_size
                .checked_add(value.len())
                .ok_or_else(|| invalid("XLSX decoded size overflow"))?;
            if decoded_size > MAX_UPLOAD {
                return Err(invalid("XLSX decoded cell text exceeds 8 MiB"));
            }
            if values.len() <= column {
                values.resize(column + 1, String::new());
            }
            values[column] = value;
        }
        rows.push(values);
    }
    Ok(rows)
}
fn separated(content: &str) -> AppResult<Vec<Vec<String>>> {
    let delimiter = if content.lines().next().unwrap_or_default().contains('\t') {
        '\t'
    } else {
        ','
    };
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut closed = false;
    let mut chars = content.chars().peekable();
    while let Some(ch) = chars.next() {
        if quoted {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    cell.push('"');
                } else {
                    quoted = false;
                    closed = true;
                }
            } else {
                cell.push(ch);
            }
        } else {
            match ch {
                '"' if cell.is_empty() && !closed => quoted = true,
                ch if ch == delimiter => {
                    row.push(std::mem::take(&mut cell));
                    closed = false;
                }
                '\n' | '\r' => {
                    if ch == '\r' && chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    row.push(std::mem::take(&mut cell));
                    rows.push(std::mem::take(&mut row));
                    closed = false;
                }
                _ if closed => return Err(invalid("Invalid characters after CSV closing quote")),
                '"' => return Err(invalid("Invalid CSV quote")),
                _ => cell.push(ch),
            }
        }
        if rows.len() > MAX_ROWS + 1 || row.len() > MAX_COLS || cell.len() > 65_536 {
            return Err(invalid("CSV upload exceeds row, column or cell limits"));
        }
    }
    if quoted {
        return Err(invalid("Unclosed CSV quote"));
    }
    if !cell.is_empty() || !row.is_empty() || closed {
        row.push(cell);
        rows.push(row);
    }
    Ok(rows)
}
fn key(value: &str) -> String {
    let value = value.split_once('#').map_or(value, |(_, key)| key).trim();
    let mut out = String::new();
    for (i, ch) in value.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i > 0 && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}
pub fn parse_upload(bytes: &[u8], filename: &str) -> AppResult<Vec<Map<String, Value>>> {
    if bytes.len() > MAX_UPLOAD {
        return Err(invalid("User upload exceeds 8 MiB"));
    }
    if bytes.starts_with(b"PK") || filename.to_ascii_lowercase().ends_with(".xlsx") {
        return table_records(xlsx(bytes)?);
    }
    let content = std::str::from_utf8(bytes)
        .map_err(|_| invalid("Upload must be XLSX or UTF-8 JSON/CSV"))?
        .trim_start_matches('\u{feff}');
    if matches!(content.trim_start().chars().next(), Some('[' | '{')) {
        let value: Value =
            serde_json::from_str(content).map_err(|_| invalid("Invalid JSON user upload"))?;
        let values = value
            .as_array()
            .or_else(|| value.get("users").and_then(Value::as_array))
            .ok_or_else(|| invalid("JSON upload needs an array or users array"))?;
        if values.len() > MAX_ROWS {
            return Err(invalid("Too many uploaded users"));
        }
        return values
            .iter()
            .map(|value| {
                let object = value
                    .as_object()
                    .ok_or_else(|| invalid("Each imported user must be an object"))?;
                let mut normalized = Map::new();
                for (name, value) in object {
                    if normalized.insert(key(name), value.clone()).is_some() {
                        return Err(invalid("Duplicate normalized JSON field"));
                    }
                }
                Ok(normalized)
            })
            .collect();
    }
    table_records(separated(content)?)
}
fn table_records(rows: Vec<Vec<String>>) -> AppResult<Vec<Map<String, Value>>> {
    let mut rows = rows.into_iter();
    let headers = rows.next().ok_or_else(|| invalid("Upload is empty"))?;
    if headers.len() > MAX_COLS {
        return Err(invalid("Too many user columns"));
    }
    let headers: Vec<_> = headers.iter().map(|s| key(s)).collect();
    let mut seen = HashSet::new();
    if headers.iter().any(|s| s.is_empty() || !seen.insert(s)) {
        return Err(invalid("Empty or duplicate upload headers"));
    }
    rows.filter(|row| row.iter().any(|s| !s.trim().is_empty()))
        .map(|row| {
            if row.len() > headers.len() {
                return Err(invalid("Row contains more fields than the header"));
            }
            let mut object = Map::new();
            for (i, name) in headers.iter().enumerate() {
                let value = row.get(i).cloned().unwrap_or_default();
                if value.is_empty()
                    && !matches!(
                        name.as_str(),
                        "password" | "password_hash" | "password_salt"
                    )
                {
                    continue;
                }
                let value = if matches!(
                    name.as_str(),
                    "is_admin"
                        | "is_forbidden"
                        | "email_verified"
                        | "is_verified"
                        | "need_update_password"
                        | "mfa_enabled"
                        | "mfa_email_enabled"
                        | "mfa_phone_enabled"
                ) {
                    match value.to_ascii_lowercase().as_str() {
                        "1" | "true" | "yes" => json!(true),
                        "0" | "false" | "no" => json!(false),
                        _ => return Err(invalid("Invalid boolean user field")),
                    }
                } else {
                    json!(value)
                };
                object.insert(name.clone(), value);
            }
            Ok(object)
        })
        .collect()
}

/// Insert a validated batch atomically. Any failure leaves every row untouched,
/// and the report never includes uploaded values or SQL diagnostic text.
pub async fn import_users(
    pool: &PgPool,
    principal: &Principal,
    owner: Option<&str>,
    records: Vec<Map<String, Value>>,
) -> AppResult<crate::handlers::upload::BulkUploadResponse> {
    if !principal.admin || principal.is_application() {
        return Err(AppError::Authorization(
            "A real administrator is required for user import".into(),
        ));
    }
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND owner=$2 AND name=$3 AND is_admin AND NOT is_deleted AND NOT is_forbidden)")
        .bind(&principal.id).bind(&principal.owner).bind(&principal.name).fetch_one(pool).await?;
    if !active {
        return Err(AppError::Authorization(
            "Current administrator unavailable".into(),
        ));
    }
    if records.is_empty() || records.len() > MAX_ROWS {
        return Err(invalid("Import needs between 1 and 1000 users"));
    }
    if !principal.global_admin() && owner.is_some_and(|owner| owner != principal.owner) {
        return Err(AppError::Authorization(
            "Cannot import into another tenant".into(),
        ));
    }
    let total = records.len();
    let mut prepared = Vec::new();
    let mut seen = HashSet::new();
    let mut ids = HashSet::new();
    let mut errors = Vec::new();
    for (index, mut object) in records.into_iter().enumerate() {
        let prepare=async {
            let row_owner=object.get("owner").and_then(Value::as_str).filter(|s|!s.is_empty()).or(owner).unwrap_or(&principal.owner).to_owned();
            if (!principal.global_admin() && row_owner!=principal.owner) || owner.is_some_and(|owner|owner!=row_owner) {return Err(AppError::Authorization("Cannot import a row into another tenant".into()));}
            let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE name=$1 AND NOT is_deleted)").bind(&row_owner).fetch_one(pool).await?;
            if !exists {return Err(invalid("Target organization does not exist"));}
            let name=object.get("name").and_then(Value::as_str).map(str::trim).filter(|s|!s.is_empty()&&s.len()<=100).ok_or_else(||invalid("A valid user name is required"))?.to_owned();
            if !seen.insert((row_owner.clone(),name.clone())) {return Err(invalid("Duplicate user identity in upload"));}
            let id=object.get("id").and_then(Value::as_str).filter(|s|!s.is_empty()).map(str::to_owned).unwrap_or_else(||uuid::Uuid::new_v4().to_string());
            if id.len()>36 || !ids.insert(id.clone()) {return Err(invalid("Invalid or duplicate user ID"));}
            PasswordService::normalize_import_fields(&mut object,false)?;
            if !object.contains_key("password_hash") {object.insert("password_hash".into(),json!(""));object.insert("password_type".into(),json!("argon2"));}
            for field in ["totp_secret","recovery_codes","mfa_items","mfa_accounts","webauthn_credentials"] {
                if object.get(field).is_some_and(|v|!v.is_null() && v!=&json!("") && v!=&json!([])) {return Err(invalid("Credential enrollment import is not supported; do not silently discard MFA credentials"));}
            }
            if ["mfa_enabled","mfa_email_enabled","mfa_phone_enabled"].iter().any(|field|object.get(*field)==Some(&json!(true))) {return Err(invalid("Enabled MFA accounts require a dedicated enrollment migration"));}
            if let Some(ldap)=object.get("ldap").filter(|value|!value.is_null()) {
                let reference=ldap.as_str().ok_or_else(||invalid("LDAP binding must be a string"))?;
                if !reference.is_empty() {
                    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM providers WHERE owner=$1 AND category='LDAP' AND (id=$2 OR name=$2 OR owner||'/'||name=$2))")
                        .bind(&row_owner).bind(reference).fetch_one(pool).await?;
                    if !valid {return Err(invalid("LDAP binding must reference an LDAP provider in the imported user's tenant"));}
                }
            }
            object.insert("id".into(),json!(id));object.insert("owner".into(),json!(row_owner));object.insert("name".into(),json!(name));
            if !object.contains_key("display_name") {object.insert("display_name".into(),object["name"].clone());}
            validate_references(pool,principal,&Value::Object(object.clone())).await?;
            Ok(object)
        }.await;
        match prepare {
            Ok(object) => prepared.push(object),
            Err(AppError::Authorization(message)) => return Err(AppError::Authorization(message)),
            Err(AppError::Validation(message)) => {
                errors.push(format!("row {}: {message}", index + 2))
            }
            Err(_) => errors.push(format!(
                "row {}: invalid user profile or database reference",
                index + 2
            )),
        }
    }
    if !errors.is_empty() {
        errors.push("No users were created; the complete batch was rejected".into());
        return Ok(crate::handlers::upload::BulkUploadResponse {
            total,
            created: 0,
            failed: total,
            errors,
        });
    }
    const ALLOWED: &[&str] = &[
        "id",
        "owner",
        "name",
        "password_hash",
        "password_type",
        "password_salt",
        "display_name",
        "first_name",
        "last_name",
        "email",
        "email_verified",
        "phone",
        "country_code",
        "avatar",
        "region",
        "location",
        "affiliation",
        "tag",
        "language",
        "gender",
        "birthday",
        "education",
        "bio",
        "homepage",
        "user_type",
        "is_admin",
        "is_forbidden",
        "is_verified",
        "need_update_password",
        "external_id",
        "ldap",
        "properties",
        "custom",
        "address",
        "signup_application",
        "register_type",
        "register_source",
    ];
    let mut tx = pool.begin().await?;
    for (index, object) in prepared.into_iter().enumerate() {
        let columns: Vec<_> = ALLOWED
            .iter()
            .filter(|name| object.contains_key(**name))
            .copied()
            .collect();
        let mut query = QueryBuilder::<Postgres>::new("INSERT INTO users (");
        query
            .push(columns.join(","))
            .push(") SELECT ")
            .push(columns.join(","))
            .push(" FROM jsonb_populate_record(NULL::users,")
            .push_bind(Value::Object(object))
            .push("::jsonb)");
        if query.build().execute(&mut *tx).await.is_err() {
            tx.rollback().await?;
            return Ok(crate::handlers::upload::BulkUploadResponse {
                total,
                created: 0,
                failed: total,
                errors: vec![format!(
                    "row {}: database conflict or invalid field; no users were created",
                    index + 2
                )],
            });
        }
    }
    tx.commit().await?;
    Ok(crate::handlers::upload::BulkUploadResponse {
        total,
        created: total,
        failed: 0,
        errors: Vec::new(),
    })
}
