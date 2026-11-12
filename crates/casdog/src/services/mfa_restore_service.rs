//! Explicit trusted-backup migration. No browser proof or remembered session is
//! restored, and no factor is silently replaced with a weaker factor.
use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    models::{Application, Provider, User},
};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use std::collections::HashSet;

pub struct Enrollment {
    secret: Option<String>,
    preferred: String,
    email: bool,
    sms: bool,
    codes: Vec<String>,
}
fn invalid() -> AppError {
    AppError::Validation("Invalid, masked or unsupported MFA backup enrollment".into())
}
fn flag(row: &Map<String, Value>, name: &str) -> AppResult<bool> {
    match row.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(v)) => Ok(*v),
        Some(Value::String(v)) => match v.as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" | "" => Ok(false),
            _ => Err(invalid()),
        },
        _ => Err(invalid()),
    }
}
fn nonempty(value: Option<&Value>) -> bool {
    value.is_some_and(|v| !v.is_null() && v != &json!("") && v != &json!([]))
}
pub fn prepare(row: &mut Map<String, Value>) -> AppResult<Option<Enrollment>> {
    for field in ["mfa_items", "mfa_accounts", "webauthn_credentials"] {
        if nonempty(row.get(field)) {
            return Err(invalid());
        }
    }
    if flag(row, "mfa_radius_enabled")? || flag(row, "mfa_push_enabled")? {
        return Err(invalid());
    }
    for field in [
        "mfa_radius_username",
        "mfa_radius_provider",
        "mfa_push_receiver",
        "mfa_push_provider",
        "multi_factor_auths",
    ] {
        if nonempty(row.get(field)) {
            return Err(invalid());
        }
    }
    let preferred = match row.get("preferred_mfa_type") {
        None | Some(Value::Null) => "",
        Some(Value::String(v)) => v,
        _ => return Err(invalid()),
    }
    .to_owned();
    let secret = match row.get("totp_secret") {
        None | Some(Value::Null) => None,
        Some(Value::String(v)) if v.is_empty() => None,
        Some(Value::String(v)) => {
            if v.len() > 100 || v == "***" {
                return Err(invalid());
            }
            let bytes = totp_rs::Secret::Encoded(v.to_ascii_uppercase())
                .to_bytes()
                .map_err(|_| invalid())?;
            // The actual Casdoor SHA1 enrollment generates twenty bytes. Accept
            // compatible >=128-bit seeds supported by the existing verifier.
            totp_rs::TOTP::new(
                totp_rs::Algorithm::SHA1,
                6,
                1,
                30,
                bytes,
                None,
                "restore".into(),
            )
            .map_err(|_| invalid())?;
            Some(v.to_ascii_uppercase())
        }
        _ => return Err(invalid()),
    };
    let email = flag(row, "mfa_email_enabled")?;
    let sms = flag(row, "mfa_phone_enabled")?;
    let mut codes = Vec::new();
    let mut seen = HashSet::new();
    match row.get("recovery_codes") {
        None | Some(Value::Null) => (),
        Some(Value::Array(values)) => {
            if values.len() > 100 {
                return Err(invalid());
            }
            for value in values {
                let code = value.as_str().ok_or_else(invalid)?;
                if code.is_empty()
                    || code.len() > 256
                    || code.trim().is_empty()
                    || code == "***"
                    || !seen.insert(code.to_owned())
                {
                    return Err(invalid());
                }
                codes.push(code.to_owned());
            }
        }
        _ => return Err(invalid()),
    }
    let active = secret.is_some() || email || sms;
    if row.get("mfa_enabled").is_some_and(|v| !v.is_null()) && flag(row, "mfa_enabled")? != active {
        return Err(invalid());
    }
    if !active {
        if !preferred.is_empty() || !codes.is_empty() || flag(row, "mfa_enabled")? {
            return Err(invalid());
        }
    } else if !match preferred.as_str() {
        "app" => secret.is_some(),
        "email" => email,
        "sms" => sms,
        _ => false,
    } {
        return Err(invalid());
    }
    if email {
        let email = row.get("email").and_then(Value::as_str).unwrap_or_default();
        if !email
            .parse::<lettre::message::Mailbox>()
            .is_ok_and(|mailbox| mailbox.name.is_none())
            || email.len() > 254
            || email.chars().any(char::is_whitespace)
            || !flag(row, "email_verified")?
        {
            return Err(invalid());
        }
    }
    if sms {
        let phone = row.get("phone").and_then(Value::as_str).unwrap_or_default();
        if !phone.strip_prefix('+').is_some_and(|digits| {
            (7..=15).contains(&digits.len()) && digits.bytes().all(|c| c.is_ascii_digit())
        }) {
            return Err(invalid());
        }
    }
    for field in [
        "totp_secret",
        "recovery_codes",
        "preferred_mfa_type",
        "mfa_enabled",
        "mfa_email_enabled",
        "mfa_phone_enabled",
        "mfa_radius_enabled",
        "mfa_push_enabled",
    ] {
        row.remove(field);
    }
    Ok(active.then_some(Enrollment {
        secret,
        preferred,
        email,
        sms,
        codes,
    }))
}
fn recovery_fingerprint(key: &[u8], owner: &str, code: &str) -> String {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    hmac.update(b"casdog.mfa-restore.recovery.v1\0");
    hmac.update(owner.as_bytes());
    hmac.update(&[0]);
    hmac.update(code.as_bytes());
    hex::encode(hmac.finalize().into_bytes())
}
async fn receipt(
    conn: &mut PgConnection,
    p: &Principal,
    user: &User,
    kind: &str,
    fingerprint: String,
) -> AppResult<()> {
    let added=sqlx::query("INSERT INTO mfa_restore_receipts(organization,kind,fingerprint,restored_user_id,restored_by) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING").bind(&user.owner).bind(kind).bind(fingerprint).bind(&user.id).bind(&p.id).execute(conn).await?.rows_affected();
    if added != 1 {
        return Err(AppError::Validation(
            "Enrollment was already restored; consumed credentials must not be revived".into(),
        ));
    }
    Ok(())
}
async fn validate_delivery(
    conn: &mut PgConnection,
    user: &User,
    enrollment: &Enrollment,
) -> AppResult<()> {
    if !enrollment.email && !enrollment.sms {
        return Ok(());
    }
    let reference = user
        .signup_application
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            AppError::Validation("Email/SMS restore requires signupApplication binding".into())
        })?;
    let apps:Vec<Application>=sqlx::query_as("SELECT a.* FROM applications a JOIN organizations o ON o.name=a.organization WHERE a.organization=$1 AND (a.id=$2 OR a.owner||'/'||a.name=$2 OR a.name=$2) AND NOT a.is_deleted AND NOT o.is_deleted AND NOT o.disable_signin LIMIT 2 FOR SHARE OF a,o").bind(&user.owner).bind(reference).fetch_all(&mut *conn).await?;
    if apps.len() != 1 {
        return Err(invalid());
    }
    let app = &apps[0];
    for (needed, category) in [(enrollment.email, "Email"), (enrollment.sms, "SMS")] {
        if !needed {
            continue;
        }
        let mut selected = None;
        for item in app
            .providers
            .as_ref()
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(reference) = item["name"].as_str() else {
                continue;
            };
            let rule = item["rule"].as_str().unwrap_or_default().trim();
            if !rule.is_empty()
                && !rule.eq_ignore_ascii_case("all")
                && !rule.eq_ignore_ascii_case("mfa")
            {
                continue;
            }
            if category == "SMS"
                && item["countryCodes"].as_array().is_some_and(|codes| {
                    !codes.is_empty()
                        && !codes
                            .iter()
                            .any(|v| v.as_str() == user.country_code.as_deref())
                })
            {
                continue;
            }
            let provider:Option<Provider>=sqlx::query_as("SELECT * FROM providers WHERE category=$1 AND owner=$2 AND (owner||'/'||name=$3 OR (owner=$4 AND name=$3)) FOR SHARE").bind(category).bind(&user.owner).bind(reference).bind(&app.owner).fetch_optional(&mut *conn).await?;
            if let Some(provider) = provider {
                selected = Some(provider);
                break;
            }
        }
        let provider = selected.ok_or_else(|| {
            AppError::Validation(
                "Configure a tenant-owned application MFA delivery provider before restoration"
                    .into(),
            )
        })?;
        crate::services::provider_dispatch_service::validate_mfa_delivery_provider(&provider)?;
    }
    Ok(())
}
pub async fn restore(
    conn: &mut PgConnection,
    p: &Principal,
    id: &str,
    enrollment: Option<Enrollment>,
) -> AppResult<()> {
    let user: User = sqlx::query_as("SELECT * FROM users WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin)").bind(&user.owner).fetch_one(&mut *conn).await?;
    if !active {
        return Err(invalid());
    }
    // Even a restored UUID cannot revive older JWTs from a previous deployment.
    sqlx::query("INSERT INTO user_session_epochs(user_id,invalid_before) VALUES($1,clock_timestamp()) ON CONFLICT(user_id) DO UPDATE SET invalid_before=GREATEST(user_session_epochs.invalid_before,EXCLUDED.invalid_before)").bind(id).execute(&mut *conn).await?;
    let Some(enrollment) = enrollment else {
        return Ok(());
    };
    validate_delivery(conn, &user, &enrollment).await?;
    if let Some(secret) = &enrollment.secret {
        let bytes = totp_rs::Secret::Encoded(secret.clone())
            .to_bytes()
            .map_err(|_| invalid())?;
        let fingerprint = hex::encode(Sha256::digest(bytes));
        receipt(conn, p, &user, "totp", fingerprint.clone()).await?;
        // No source last-used counter exists: fence the entire currently
        // acceptable skew window. Use recovery immediately, or wait <=60 sec.
        sqlx::query("INSERT INTO user_totp_steps(user_id,secret_hash,last_step) VALUES($1,$2,floor(extract(epoch FROM clock_timestamp())/30)::bigint+1) ON CONFLICT(user_id,secret_hash) DO UPDATE SET last_step=GREATEST(user_totp_steps.last_step,EXCLUDED.last_step)").bind(id).bind(fingerprint).execute(&mut *conn).await?;
    }
    if !enrollment.codes.is_empty() {
        use rand::RngCore;
        let mut candidate = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut candidate);
        sqlx::query("INSERT INTO mfa_restore_hmac_key(singleton,secret) VALUES(true,$1) ON CONFLICT DO NOTHING").bind(candidate.as_slice()).execute(&mut *conn).await?;
        let key: Vec<u8> =
            sqlx::query_scalar("SELECT secret FROM mfa_restore_hmac_key WHERE singleton FOR SHARE")
                .fetch_one(&mut *conn)
                .await?;
        for code in &enrollment.codes {
            receipt(
                conn,
                p,
                &user,
                "recovery",
                recovery_fingerprint(&key, &user.owner, code),
            )
            .await?;
        }
    }
    let carrier = if enrollment.secret.is_some() {
        "totp"
    } else {
        enrollment.preferred.as_str()
    };
    sqlx::query("INSERT INTO user_mfa(id,user_id,mfa_type,secret,recovery_codes,is_enabled) VALUES($1,$2,$3,$4,$5,true)").bind(uuid::Uuid::new_v4().to_string()).bind(id).bind(carrier).bind(&enrollment.secret).bind(json!(enrollment.codes).to_string()).execute(&mut *conn).await?;
    sqlx::query("UPDATE users SET mfa_enabled=true,preferred_mfa_type=$2,mfa_email_enabled=$3,mfa_phone_enabled=$4 WHERE id=$1").bind(id).bind(enrollment.preferred).bind(enrollment.email).bind(enrollment.sms).execute(conn).await?;
    Ok(())
}
