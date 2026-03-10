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
        serde_json::from_str(&text).map_err(|err| format!("Invalid JSON response: {err}"))
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
