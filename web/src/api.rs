use gloo_net::http::{Request, RequestBuilder};
use serde_json::Value;

pub fn build_url(api_base: &str, endpoint: &str) -> String {
    let base = api_base.trim_end_matches('/');
    let path = endpoint.trim_start_matches('/');

    if base.is_empty() {
        format!("/{}", path)
    } else {
        format!("{}/{}", base, path)
    }
}

pub fn item_id(value: &Value) -> Option<String> {
    value
        .get("id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

pub fn item_title(value: &Value) -> String {
    for key in ["display_name", "displayName", "name", "subject", "id"] {
        if let Some(title) = value.get(key).and_then(Value::as_str) {
            if !title.is_empty() {
                return title.to_string();
            }
        }
    }

    "Untitled".to_string()
}

pub fn item_subtitle(value: &Value) -> String {
    let mut fragments = Vec::new();

    for key in [
        "owner",
        "organization",
        "application",
        "rule_type",
        "status",
    ] {
        if let Some(text) = value.get(key).and_then(Value::as_str) {
            if !text.is_empty() {
                fragments.push(text.to_string());
            }
        }
    }

    fragments.join(" · ")
}

pub fn extract_collection(value: Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items,
        Value::Object(map) => map
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

pub fn pretty_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

pub fn filter_matches(value: &Value, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    let flattened = value.to_string().to_lowercase();
    flattened.contains(needle)
}

pub async fn request_json(
    method: &str,
    url: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> Result<Value, String> {
    let response = match method {
        "GET" => with_auth(Request::get(url), token)
            .send()
            .await
            .map_err(|err| err.to_string())?,
        "DELETE" => with_auth(Request::delete(url), token)
            .send()
            .await
            .map_err(|err| err.to_string())?,
        "POST" => {
            let request = with_auth(Request::post(url), token)
                .header("Content-Type", "application/json")
                .body(body.unwrap_or(Value::Null).to_string())
                .map_err(|err| err.to_string())?;
            request.send().await.map_err(|err| err.to_string())?
        }
        "PUT" => {
            let request = with_auth(Request::put(url), token)
                .header("Content-Type", "application/json")
                .body(body.unwrap_or(Value::Null).to_string())
                .map_err(|err| err.to_string())?;
            request.send().await.map_err(|err| err.to_string())?
        }
        unsupported => {
            return Err(format!("Unsupported method: {unsupported}"));
        }
    };

    let status = response.status();
    let text = response.text().await.map_err(|err| err.to_string())?;

    if !(200..300).contains(&status) {
        return Err(parse_error_message(status, &text));
    }

    if text.trim().is_empty() {
        Ok(serde_json::json!({ "status": "ok" }))
    } else {
        let value =
            serde_json::from_str(&text).map_err(|err| format!("Invalid JSON response: {err}"))?;
        validate_response(value)
    }
}

// Casdoor compatibility endpoints can report failures inside an HTTP 200 envelope.
fn validate_response(value: Value) -> Result<Value, String> {
    if value.get("status").and_then(Value::as_str) == Some("error") {
        return Err(value
            .get("msg")
            .and_then(Value::as_str)
            .filter(|message| !message.trim().is_empty())
            .unwrap_or("The server rejected this request.")
            .to_string());
    }
    Ok(value)
}

#[derive(Debug, PartialEq)]
pub enum LoginOutcome {
    Challenge(Vec<String>),
    Authenticated {
        token: String,
        user: Value,
        password_expired: bool,
    },
}

pub fn parse_login_response(value: Value) -> Result<LoginOutcome, String> {
    let value = validate_response(value)?;
    // A challenge must never create a browser session, even if a token is present.
    if value.get("mfa_required").and_then(Value::as_bool) == Some(true) {
        let methods = value
            .get("mfa_types")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|method| matches!(*method, "app" | "totp" | "sms" | "email" | "recovery"))
            .map(str::to_string)
            .collect();
        return Ok(LoginOutcome::Challenge(methods));
    }
    let token = value
        .get("token")
        .and_then(Value::as_str)
        .filter(|token| !token.trim().is_empty())
        .ok_or("Login failed: no token returned.")?
        .to_string();
    let user = value
        .get("user")
        .filter(|user| user.is_object())
        .ok_or("Login failed: no account returned.")?
        .clone();
    Ok(LoginOutcome::Authenticated {
        token,
        user,
        password_expired: value
            .get("password_expired")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

pub fn parse_mfa_verification(value: Value) -> Result<Vec<String>, String> {
    let value = validate_response(value)?;
    if value.get("success").and_then(Value::as_bool) != Some(true) {
        return Err("The verification code is invalid or expired. Try the current code from your authenticator.".into());
    }
    Ok(value
        .get("recovery_codes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn failed_mfa_verification_never_enables_the_ui() {
        assert!(parse_mfa_verification(json!({"success": false, "recovery_codes": null})).is_err());
        assert!(parse_mfa_verification(json!({"status": "ok"})).is_err());
        assert_eq!(
            parse_mfa_verification(json!({"success": true, "recovery_codes": ["one-use-code"]}))
                .unwrap(),
            vec!["one-use-code"]
        );
    }

    #[test]
    fn challenge_never_authenticates_an_empty_or_present_token() {
        for token in ["", "unexpected-token"] {
            assert_eq!(
                parse_login_response(json!({"token": token, "mfa_required": true,
                "mfa_types": ["app", "unknown"]}))
                .unwrap(),
                LoginOutcome::Challenge(vec!["app".into()])
            );
        }
    }

    #[test]
    fn login_requires_a_nonempty_token_and_account() {
        assert!(parse_login_response(json!({"token": " ", "user": {}})).is_err());
        assert!(parse_login_response(json!({"token": "jwt"})).is_err());
        assert!(matches!(
            parse_login_response(json!({"token": "jwt", "user": {"name":"alice"},
            "password_expired": true}))
            .unwrap(),
            LoginOutcome::Authenticated {
                password_expired: true,
                ..
            }
        ));
    }

    #[test]
    fn casdoor_errors_are_not_successful_mutations() {
        assert_eq!(
            validate_response(json!({"status":"error", "msg":"Access denied"})),
            Err("Access denied".into())
        );
        assert!(validate_response(json!({"status":"ok", "data":[]})).is_ok());
    }
}

fn with_auth(mut request: RequestBuilder, token: Option<&str>) -> RequestBuilder {
    if let Some(token) = token {
        request = request.header("Authorization", &format!("Bearer {token}"));
    }

    request
}

fn parse_error_message(status: u16, text: &str) -> String {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        for key in ["msg", "message", "error"] {
            if let Some(message) = value.get(key).and_then(Value::as_str) {
                return format!("{status}: {message}");
            }
        }

        if let Some(message) = value
            .get("error")
            .and_then(|value| value.get("message"))
            .and_then(Value::as_str)
        {
            return format!("{status}: {message}");
        }
    }

    if text.trim().is_empty() {
        format!("Request failed with status {status}")
    } else {
        format!("{status}: {}", text.trim())
    }
}
