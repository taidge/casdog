use dioxus::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{build_url, request_json};

const LOGIN_PAGE_CSS: &str = r#"
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
}

.login-box {
  width: 100%;
  max-width: 420px;
  padding: 36px;
  border: 1px solid var(--line);
  border-radius: 28px;
  background: var(--surface);
  box-shadow: var(--shadow);
  backdrop-filter: blur(18px);
  animation: fade-up 320ms ease;
}

.login-box h2 {
  margin: 0 0 8px;
  font-size: 32px;
  font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
}

.login-box .subtitle {
  margin: 0 0 24px;
  color: var(--text-soft);
  line-height: 1.5;
}

.login-form {
  display: grid;
  gap: 16px;
}

.login-field {
  display: grid;
  gap: 6px;
}

.login-field label {
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.04em;
}

.login-field .required-mark {
  color: var(--danger);
}

.login-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-top: 8px;
}

.login-links {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: 20px;
  font-size: 14px;
  color: var(--text-soft);
}

.login-links button {
  background: none;
  border: none;
  color: var(--accent);
  cursor: pointer;
  font: inherit;
  font-weight: 600;
  padding: 0;
}

.login-links button:hover {
  text-decoration: underline;
}

.social-divider {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 24px 0 16px;
  color: var(--text-soft);
  font-size: 13px;
}

.social-divider::before,
.social-divider::after {
  content: "";
  flex: 1;
  height: 1px;
  background: var(--line);
}

.social-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.social-button {
  flex: 1;
  min-width: 100px;
  padding: 10px 14px;
  border: 1px solid var(--line);
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.7);
  color: var(--text);
  cursor: pointer;
  font: inherit;
  font-size: 13px;
  text-align: center;
  transition: background 160ms ease, transform 160ms ease;
}

.social-button:hover {
  background: rgba(255, 255, 255, 0.95);
  transform: translateY(-1px);
}
"#;

#[derive(Debug, Deserialize)]
struct OAuthProvider {
    name: String,
    display_name: Option<String>,
    #[serde(rename = "type")]
    provider_type: Option<String>,
}

/// Full login page component with organization, username/password fields,
/// social login providers, and links to sign-up / forgot password.
///
/// Props:
/// * `api_base` - Signal with the API base URL.
/// * `token` - Signal that stores the auth token once login succeeds.
/// * `on_login` - Called with (token_string, user_json) after successful login.
/// * `on_navigate` - Called with a page name ("signup", "forgot_password") when links are clicked.
/// * `application` - Optional application slug that may restrict OAuth providers.
#[component]
pub fn LoginPage(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
    on_login: EventHandler<(String, Value)>,
    on_navigate: EventHandler<String>,
    #[props(default)] application: String,
) -> Element {
    let mut organization = use_signal(|| "admin".to_string());
    let mut username = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut loading = use_signal(|| false);
    let mut error_message = use_signal(|| None::<String>);
    let mut show_password = use_signal(|| false);

    // Social / OAuth providers
    let providers = use_signal(Vec::<OAuthProvider>::new);

    // Fetch available OAuth providers on mount
    {
        let api_base_val = api_base();
        let app = application.clone();
        let mut providers = providers;
        use_effect(move || {
            let api_base_val = api_base_val.clone();
            let app = app.clone();
            spawn(async move {
                let endpoint = if app.is_empty() {
                    "/api/providers".to_string()
                } else {
                    format!("/api/providers?application={app}")
                };
                let url = build_url(&api_base_val, &endpoint);
                if let Ok(value) = request_json("GET", &url, None, None).await {
                    let list = value
                        .get("data")
                        .and_then(|d| d.as_array())
                        .or_else(|| value.as_array())
                        .cloned()
                        .unwrap_or_default();

                    let oauth_providers: Vec<OAuthProvider> = list
                        .into_iter()
                        .filter_map(|v| serde_json::from_value(v).ok())
                        .filter(|p: &OAuthProvider| {
                            p.provider_type
                                .as_deref()
                                .map(|t| !matches!(t, "Email" | "SMS" | "Payment" | "Storage" | "Captcha"))
                                .unwrap_or(true)
                        })
                        .collect();

                    providers.set(oauth_providers);
                }
            });
        });
    }

    let do_login = move |_| {
        let api_base_val = api_base();
        let org = organization();
        let user = username();
        let pass = password();
        let app = application.clone();
        let mut loading = loading;
        let mut error_message = error_message;

        spawn(async move {
            loading.set(true);
            error_message.set(None);

            let mut payload = json!({
                "owner": org,
                "name": user,
                "password": pass,
            });

            if !app.is_empty() {
                payload
                    .as_object_mut()
                    .unwrap()
                    .insert("application".to_string(), Value::String(app));
            }

            let url = build_url(&api_base_val, "/api/login");
            match request_json("POST", &url, None, Some(payload)).await {
                Ok(value) => {
                    let tok = value
                        .get("token")
                        .and_then(|t| t.as_str())
                        .unwrap_or("")
                        .to_string();

                    if tok.is_empty() {
                        error_message.set(Some(
                            value
                                .get("msg")
                                .and_then(|m| m.as_str())
                                .unwrap_or("Login failed: no token returned.")
                                .to_string(),
                        ));
                    } else {
                        let user_val = value.get("user").cloned().unwrap_or(Value::Null);
                        on_login.call((tok, user_val));
                    }
                }
                Err(err) => {
                    error_message.set(Some(err));
                }
            }

            loading.set(false);
        });
    };

    rsx! {
        style { "{LOGIN_PAGE_CSS}" }

        div { class: "login-page",
            div { class: "login-box",
                h2 { "Sign in" }
                p { class: "subtitle", "Sign in to your account to continue." }

                div { class: "login-form",
                    // Organization
                    div { class: "login-field",
                        label {
                            "Organization"
                            span { class: "required-mark", " *" }
                        }
                        input {
                            class: "text-input",
                            r#type: "text",
                            placeholder: "admin",
                            value: "{organization}",
                            oninput: move |evt| organization.set(evt.value()),
                        }
                    }

                    // Username
                    div { class: "login-field",
                        label {
                            "Username"
                            span { class: "required-mark", " *" }
                        }
                        input {
                            class: "text-input",
                            r#type: "text",
                            placeholder: "Enter your username",
                            value: "{username}",
                            oninput: move |evt| username.set(evt.value()),
                        }
                    }

                    // Password
                    div { class: "login-field",
                        label {
                            "Password"
                            span { class: "required-mark", " *" }
                        }
                        div { class: "password-wrapper",
                            input {
                                class: "text-input password-input",
                                r#type: if show_password() { "text" } else { "password" },
                                placeholder: "Enter your password",
                                value: "{password}",
                                oninput: move |evt| password.set(evt.value()),
                                onkeypress: move |evt: KeyboardEvent| {
                                    if evt.key() == Key::Enter {
                                        do_login(());
                                    }
                                },
                            }
                            button {
                                class: "password-toggle ghost-button",
                                r#type: "button",
                                onclick: move |_| show_password.set(!show_password()),
                                if show_password() { "Hide" } else { "Show" }
                            }
                        }
                    }

                    // Error display
                    if let Some(err) = error_message() {
                        div { class: "inline-message error", "{err}" }
                    }

                    // Actions
                    div { class: "login-actions",
                        button {
                            class: "primary-button",
                            disabled: loading() || username().is_empty() || password().is_empty(),
                            onclick: do_login,
                            if loading() { "Signing in..." } else { "Sign in" }
                        }
                        button {
                            class: "ghost-button",
                            r#type: "button",
                            onclick: move |_| on_navigate.call("forgot_password".to_string()),
                            "Forgot password?"
                        }
                    }
                }

                // Social / OAuth providers
                if !providers().is_empty() {
                    div { class: "social-divider", "Or sign in with" }
                    div { class: "social-grid",
                        {providers().iter().map(|p| {
                            let name = p.name.clone();
                            let display = p.display_name.clone().unwrap_or_else(|| p.name.clone());
                            let api_base_val = api_base();
                            let org = organization();
                            rsx! {
                                button {
                                    class: "social-button",
                                    key: "{name}",
                                    onclick: move |_| {
                                        let redirect_url = build_url(
                                            &api_base_val,
                                            &format!("/api/login/oauth/authorize/{org}/{name}"),
                                        );
                                        // Navigate to the OAuth provider authorization URL
                                        document::eval(&format!("window.location.assign('{}')", redirect_url.replace('\'', "\\'")));
                                    },
                                    "{display}"
                                }
                            }
                        })}
                    }
                }

                // Sign up link
                div { class: "login-links",
                    span { "Don't have an account?" }
                    button {
                        onclick: move |_| on_navigate.call("signup".to_string()),
                        "Sign up"
                    }
                }
            }
        }
    }
}
