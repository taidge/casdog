use dioxus::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{build_url, request_json};

const AUTHORIZE_PAGE_CSS: &str = r#"
.authorize-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
}

.authorize-box {
  width: 100%;
  max-width: 440px;
  padding: 36px;
  border: 1px solid var(--line);
  border-radius: 28px;
  background: var(--surface);
  box-shadow: var(--shadow);
  backdrop-filter: blur(18px);
  animation: fade-up 320ms ease;
}

.authorize-app-header {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 20px;
}

.authorize-app-logo {
  width: 56px;
  height: 56px;
  border-radius: 14px;
  object-fit: contain;
  background: var(--surface-soft);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
  font-weight: 700;
  color: var(--accent);
  flex-shrink: 0;
}

.authorize-app-logo img {
  width: 100%;
  height: 100%;
  border-radius: 14px;
  object-fit: contain;
}

.authorize-app-info h2 {
  margin: 0 0 4px;
  font-size: 24px;
  font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
}

.authorize-app-info p {
  margin: 0;
  color: var(--text-soft);
  font-size: 14px;
}

.authorize-scopes {
  margin: 20px 0;
  padding: 16px;
  border-radius: 16px;
  background: var(--surface-soft);
}

.authorize-scopes h4 {
  margin: 0 0 10px;
  font-size: 14px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text-soft);
}

.scope-list {
  display: grid;
  gap: 8px;
}

.scope-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.7);
  font-size: 14px;
}

.scope-check {
  color: var(--success);
  font-weight: 700;
}

.authorize-identity {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  border-radius: 14px;
  background: rgba(35, 123, 86, 0.08);
  margin-bottom: 20px;
  font-size: 14px;
}

.authorize-identity strong {
  color: var(--text);
}

.authorize-actions {
  display: flex;
  gap: 12px;
}

.authorize-actions button {
  flex: 1;
}
"#;

#[derive(Debug, Clone, Default, Deserialize)]
struct AppInfo {
    name: String,
    display_name: Option<String>,
    logo: Option<String>,
    homepage_url: Option<String>,
}

/// OAuth authorization page that shows the requesting application,
/// requested scopes, and allow/deny buttons.
///
/// Props:
/// * `api_base` - Signal with the API base URL.
/// * `token` - The current user's auth token.
/// * `client_id` - The OAuth client_id requesting authorization.
/// * `redirect_uri` - Where to redirect after authorization.
/// * `response_type` - OAuth response type (code, token).
/// * `scope` - Space-separated scopes.
/// * `state` - OAuth state parameter.
/// * `user_display_name` - Display name of the current user.
#[component]
pub fn AuthorizePage(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
    #[props(default)] client_id: String,
    #[props(default)] redirect_uri: String,
    #[props(default = "code".to_string())] response_type: String,
    #[props(default)] scope: String,
    #[props(default)] state: String,
    #[props(default = "User".to_string())] user_display_name: String,
) -> Element {
    let mut app_info = use_signal(AppInfo::default);
    let mut loading = use_signal(|| false);
    let mut authorizing = use_signal(|| false);
    let mut error_message = use_signal(|| None::<String>);

    let scopes: Vec<String> = scope
        .split_whitespace()
        .map(String::from)
        .filter(|s| !s.is_empty())
        .collect();

    // Fetch application info
    {
        let api_base_val = api_base();
        let token_val = token();
        let cid = client_id.clone();
        let mut app_info = app_info;
        let mut loading = loading;
        use_effect(move || {
            if cid.is_empty() {
                return;
            }
            loading.set(true);
            let api_base_val = api_base_val.clone();
            let token_val = token_val.clone();
            let cid = cid.clone();
            spawn(async move {
                let url = build_url(&api_base_val, &format!("/api/applications?client_id={cid}"));
                if let Ok(value) = request_json("GET", &url, token_val.as_deref(), None).await {
                    let app_list = value
                        .get("data")
                        .and_then(|d| d.as_array())
                        .or_else(|| value.as_array())
                        .cloned()
                        .unwrap_or_default();

                    if let Some(first) = app_list.into_iter().next() {
                        if let Ok(info) = serde_json::from_value::<AppInfo>(first) {
                            app_info.set(info);
                        }
                    }
                }
                loading.set(false);
            });
        });
    }

    let info = app_info();
    let app_display = info
        .display_name
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| info.name.clone());
    let has_logo = info.logo.as_ref().is_some_and(|l| !l.is_empty());
    let first_letter = app_display.chars().next().unwrap_or('A').to_uppercase().to_string();

    let do_authorize = move |allow: bool| {
        let api_base_val = api_base();
        let token_val = token();
        let cid = client_id.clone();
        let ruri = redirect_uri.clone();
        let rtype = response_type.clone();
        let sc = scope.clone();
        let st = state.clone();
        let mut authorizing = authorizing;
        let mut error_message = error_message;

        spawn(async move {
            authorizing.set(true);
            error_message.set(None);

            let payload = json!({
                "client_id": cid,
                "redirect_uri": ruri,
                "response_type": rtype,
                "scope": sc,
                "state": st,
                "approved": allow,
            });

            let url = build_url(&api_base_val, "/api/login/oauth/authorize");
            match request_json("POST", &url, token_val.as_deref(), Some(payload)).await {
                Ok(value) => {
                    // Server should return a redirect URL
                    if let Some(redirect) = value
                        .get("redirect_uri")
                        .or_else(|| value.get("redirect"))
                        .and_then(|r| r.as_str())
                    {
                        document::eval(&format!("window.location.assign('{}')", redirect.replace('\'', "\\'")));
                    } else if !allow {
                        // Denied - redirect back with error
                        let deny_url = if ruri.contains('?') {
                            format!("{ruri}&error=access_denied&state={st}")
                        } else {
                            format!("{ruri}?error=access_denied&state={st}")
                        };
                        document::eval(&format!("window.location.assign('{}')", deny_url.replace('\'', "\\'")));
                    } else {
                        error_message.set(Some("Unexpected response from authorization server.".to_string()));
                    }
                }
                Err(err) => {
                    error_message.set(Some(err));
                }
            }

            authorizing.set(false);
        });
    };

    rsx! {
        style { "{AUTHORIZE_PAGE_CSS}" }

        div { class: "authorize-page",
            div { class: "authorize-box",
                if loading() {
                    div { class: "inline-message neutral", "Loading application details..." }
                } else {
                    // App header
                    div { class: "authorize-app-header",
                        div { class: "authorize-app-logo",
                            if has_logo {
                                img { src: "{info.logo.as_deref().unwrap_or(\"\")}", alt: "{app_display}" }
                            } else {
                                "{first_letter}"
                            }
                        }
                        div { class: "authorize-app-info",
                            h2 { "{app_display}" }
                            p { "wants to access your account" }
                        }
                    }

                    // Identity
                    div { class: "authorize-identity",
                        span { "Signed in as " }
                        strong { "{user_display_name}" }
                    }

                    // Scopes
                    if !scopes.is_empty() {
                        div { class: "authorize-scopes",
                            h4 { "Requested permissions" }
                            div { class: "scope-list",
                                {scopes.iter().map(|s| {
                                    let display = scope_display_name(s);
                                    rsx! {
                                        div { class: "scope-item", key: "{s}",
                                            span { class: "scope-check", "+" }
                                            span { "{display}" }
                                        }
                                    }
                                })}
                            }
                        }
                    }

                    // Error
                    if let Some(err) = error_message() {
                        div { class: "inline-message error", "{err}" }
                    }

                    // Actions
                    div { class: "authorize-actions",
                        button {
                            class: "primary-button",
                            disabled: authorizing(),
                            onclick: move |_| do_authorize(true),
                            if authorizing() { "Authorizing..." } else { "Allow" }
                        }
                        button {
                            class: "danger-button",
                            disabled: authorizing(),
                            onclick: move |_| do_authorize(false),
                            "Deny"
                        }
                    }
                }
            }
        }
    }
}

fn scope_display_name(scope: &str) -> String {
    match scope {
        "openid" => "OpenID Connect identity".to_string(),
        "profile" => "View your profile information".to_string(),
        "email" => "View your email address".to_string(),
        "phone" => "View your phone number".to_string(),
        "address" => "View your address".to_string(),
        "offline_access" => "Maintain access when you are not present".to_string(),
        "read" => "Read access to your data".to_string(),
        "write" => "Write access to your data".to_string(),
        "admin" => "Full administrative access".to_string(),
        other => other.to_string(),
    }
}
