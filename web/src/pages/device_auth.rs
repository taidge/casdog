use dioxus::prelude::*;
use serde_json::{Value, json};

use crate::api::{build_url, request_json};

const DEVICE_AUTH_CSS: &str = r#"
.device-auth-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
}

.device-auth-box {
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

.device-auth-box h2 {
  margin: 0 0 8px;
  font-size: 32px;
  font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
}

.device-auth-box .subtitle {
  margin: 0 0 24px;
  color: var(--text-soft);
  line-height: 1.5;
}

.device-code-input {
  display: grid;
  gap: 14px;
}

.device-code-field {
  display: grid;
  gap: 6px;
}

.device-code-field label {
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.04em;
}

.device-code-field input {
  text-align: center;
  font-size: 24px;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  font-family: "IBM Plex Mono", Consolas, monospace;
}

.device-status {
  margin: 20px 0;
  padding: 16px;
  border-radius: 16px;
  text-align: center;
  font-size: 15px;
  line-height: 1.5;
}

.device-status.pending {
  background: rgba(208, 111, 60, 0.1);
  color: var(--accent-strong);
}

.device-status.verified {
  background: rgba(35, 123, 86, 0.1);
  color: var(--success);
}

.device-status.approved {
  background: rgba(35, 123, 86, 0.15);
  color: var(--success);
}

.device-status.denied {
  background: rgba(166, 54, 54, 0.1);
  color: var(--danger);
}

.device-app-info {
  padding: 14px;
  border-radius: 14px;
  background: var(--surface-soft);
  margin-bottom: 16px;
}

.device-app-info h4 {
  margin: 0 0 4px;
  font-size: 15px;
}

.device-app-info p {
  margin: 0;
  font-size: 13px;
  color: var(--text-soft);
}

.device-actions {
  display: flex;
  gap: 12px;
  margin-top: 8px;
}

.device-actions button {
  flex: 1;
}
"#;

#[derive(Debug, Clone, PartialEq)]
enum DeviceStatus {
    Input,
    Verifying,
    Verified {
        device_code: String,
        app_name: String,
        scopes: Vec<String>,
    },
    Approved,
    Denied,
    Error(String),
}

/// Device authorization page: enter a user code, verify it, then approve or deny.
///
/// Props:
/// * `api_base` - Signal with the API base URL.
/// * `token` - The current user's auth token.
/// * `initial_code` - Pre-filled user code (e.g. from a URL parameter).
#[component]
pub fn DeviceAuthPage(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
    #[props(default)] initial_code: String,
) -> Element {
    let mut user_code = use_signal(|| initial_code.clone());
    let mut status = use_signal(|| DeviceStatus::Input);

    let do_verify = move |_| {
        let api_base_val = api_base();
        let token_val = token();
        let code = user_code();
        let mut status = status;

        if code.trim().is_empty() {
            status.set(DeviceStatus::Error("Please enter a user code.".to_string()));
            return;
        }

        status.set(DeviceStatus::Verifying);

        spawn(async move {
            let url = build_url(&api_base_val, "/api/login/oauth/device/verify");
            let payload = json!({ "user_code": code.trim().to_uppercase() });

            match request_json("POST", &url, token_val.as_deref(), Some(payload)).await {
                Ok(value) => {
                    let device_code = value
                        .get("device_code")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let app_name = value
                        .get("application")
                        .or_else(|| value.get("client_name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown application")
                        .to_string();

                    let scopes: Vec<String> = value
                        .get("scope")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .split_whitespace()
                        .map(String::from)
                        .filter(|s| !s.is_empty())
                        .collect();

                    if device_code.is_empty() {
                        status.set(DeviceStatus::Error(
                            value
                                .get("msg")
                                .and_then(|m| m.as_str())
                                .unwrap_or("Invalid or expired user code.")
                                .to_string(),
                        ));
                    } else {
                        status.set(DeviceStatus::Verified {
                            device_code,
                            app_name,
                            scopes,
                        });
                    }
                }
                Err(err) => {
                    status.set(DeviceStatus::Error(err));
                }
            }
        });
    };

    let do_decision = move |approve: bool| {
        let current_status = status();
        let device_code = match &current_status {
            DeviceStatus::Verified { device_code, .. } => device_code.clone(),
            _ => return,
        };

        let api_base_val = api_base();
        let token_val = token();
        let mut status = status;

        spawn(async move {
            let url = build_url(&api_base_val, "/api/login/oauth/device/authorize");
            let payload = json!({
                "device_code": device_code,
                "approved": approve,
            });

            match request_json("POST", &url, token_val.as_deref(), Some(payload)).await {
                Ok(_) => {
                    if approve {
                        status.set(DeviceStatus::Approved);
                    } else {
                        status.set(DeviceStatus::Denied);
                    }
                }
                Err(err) => {
                    status.set(DeviceStatus::Error(err));
                }
            }
        });
    };

    rsx! {
        style { "{DEVICE_AUTH_CSS}" }

        div { class: "device-auth-page",
            div { class: "device-auth-box",
                h2 { "Device authorization" }
                p { class: "subtitle",
                    "Enter the code shown on your device to authorize it."
                }

                match status() {
                    DeviceStatus::Input | DeviceStatus::Verifying => {
                        rsx! {
                            div { class: "device-code-input",
                                div { class: "device-code-field",
                                    label { "User code" }
                                    input {
                                        class: "text-input",
                                        r#type: "text",
                                        placeholder: "ABCD-1234",
                                        value: "{user_code}",
                                        disabled: matches!(status(), DeviceStatus::Verifying),
                                        oninput: move |evt| user_code.set(evt.value()),
                                        onkeypress: move |evt: KeyboardEvent| {
                                            if evt.key() == Key::Enter {
                                                do_verify(());
                                            }
                                        },
                                    }
                                }
                                button {
                                    class: "primary-button",
                                    disabled: matches!(status(), DeviceStatus::Verifying) || user_code().trim().is_empty(),
                                    onclick: do_verify,
                                    if matches!(status(), DeviceStatus::Verifying) { "Verifying..." } else { "Verify" }
                                }
                            }
                        }
                    }
                    DeviceStatus::Verified { ref app_name, ref scopes, .. } => {
                        let app = app_name.clone();
                        let sc = scopes.clone();
                        rsx! {
                            div { class: "device-status verified",
                                "Code verified. Approve or deny this device."
                            }

                            div { class: "device-app-info",
                                h4 { "{app}" }
                                if !sc.is_empty() {
                                    p { "Scopes: {sc.join(\", \")}" }
                                }
                            }

                            div { class: "device-actions",
                                button {
                                    class: "primary-button",
                                    onclick: move |_| do_decision(true),
                                    "Approve"
                                }
                                button {
                                    class: "danger-button",
                                    onclick: move |_| do_decision(false),
                                    "Deny"
                                }
                            }
                        }
                    }
                    DeviceStatus::Approved => {
                        rsx! {
                            div { class: "device-status approved",
                                "Device authorized successfully. You can close this page."
                            }
                            button {
                                class: "ghost-button",
                                onclick: move |_| {
                                    user_code.set(String::new());
                                    status.set(DeviceStatus::Input);
                                },
                                "Authorize another device"
                            }
                        }
                    }
                    DeviceStatus::Denied => {
                        rsx! {
                            div { class: "device-status denied",
                                "Authorization denied."
                            }
                            button {
                                class: "ghost-button",
                                onclick: move |_| {
                                    user_code.set(String::new());
                                    status.set(DeviceStatus::Input);
                                },
                                "Try again"
                            }
                        }
                    }
                    DeviceStatus::Error(ref msg) => {
                        let m = msg.clone();
                        rsx! {
                            div { class: "inline-message error", "{m}" }
                            button {
                                class: "ghost-button",
                                onclick: move |_| status.set(DeviceStatus::Input),
                                "Try again"
                            }
                        }
                    }
                }
            }
        }
    }
}
