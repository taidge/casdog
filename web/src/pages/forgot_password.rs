use dioxus::prelude::*;
use serde_json::{Value, json};

use crate::api::{build_url, request_json};

const FORGOT_PASSWORD_CSS: &str = r#"
.forgot-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
}

.forgot-box {
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

.forgot-box h2 {
  margin: 0 0 8px;
  font-size: 28px;
  font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
}

.forgot-box .subtitle {
  margin: 0 0 24px;
  color: var(--text-soft);
  line-height: 1.5;
}

.forgot-form {
  display: grid;
  gap: 16px;
}

.forgot-field {
  display: grid;
  gap: 6px;
}

.forgot-field label {
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.04em;
}

.forgot-field .required-mark {
  color: var(--danger);
}

.forgot-actions {
  display: flex;
  gap: 10px;
  margin-top: 8px;
}

.forgot-links {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: 20px;
  font-size: 14px;
  color: var(--text-soft);
}

.forgot-links button {
  background: none;
  border: none;
  color: var(--accent);
  cursor: pointer;
  font: inherit;
  font-weight: 600;
  padding: 0;
}

.forgot-links button:hover {
  text-decoration: underline;
}

.forgot-step-indicator {
  display: flex;
  gap: 8px;
  margin-bottom: 20px;
}

.forgot-step {
  flex: 1;
  height: 4px;
  border-radius: 2px;
  background: var(--line);
  transition: background 300ms ease;
}

.forgot-step.active {
  background: var(--accent);
}

.forgot-step.done {
  background: var(--success);
}
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ForgotStep {
    /// Step 1: Enter email address
    Email,
    /// Step 2: Enter verification code + new password
    Reset,
    /// Step 3: Success
    Done,
}

/// Password reset flow with three steps:
/// 1. Enter email to receive verification code
/// 2. Enter code + new password
/// 3. Success confirmation
///
/// Props:
/// * `api_base` - Signal with the API base URL.
/// * `on_navigate` - Called with a page name ("login") to navigate away.
/// * `default_organization` - Pre-filled organization.
#[component]
pub fn ForgotPasswordPage(
    api_base: Signal<String>,
    on_navigate: EventHandler<String>,
    #[props(default = "admin".to_string())] default_organization: String,
) -> Element {
    let mut step = use_signal(|| ForgotStep::Email);
    let mut organization = use_signal(|| default_organization.clone());
    let mut email = use_signal(String::new);
    let mut code = use_signal(String::new);
    let mut new_password = use_signal(String::new);
    let mut confirm_password = use_signal(String::new);
    let mut loading = use_signal(|| false);
    let mut error_message = use_signal(|| None::<String>);
    let mut info_message = use_signal(|| None::<String>);
    let mut show_password = use_signal(|| false);

    let passwords_match = new_password().is_empty() || new_password() == confirm_password();

    let step_index = match step() {
        ForgotStep::Email => 0,
        ForgotStep::Reset => 1,
        ForgotStep::Done => 2,
    };

    // Step 1: Send verification code
    let do_send_code = move |_| {
        let api_base_val = api_base();
        let org = organization();
        let em = email();

        if em.is_empty() {
            error_message.set(Some("Email address is required.".to_string()));
            return;
        }

        spawn(async move {
            loading.set(true);
            error_message.set(None);
            info_message.set(None);

            let payload = json!({
                "organization": org,
                "email": em,
                "type": "forget",
            });

            let url = build_url(&api_base_val, "/api/send-verification-code");
            match request_json("POST", &url, None, Some(payload)).await {
                Ok(value) => {
                    let status = value
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("ok");

                    if status == "error" {
                        let msg = value
                            .get("msg")
                            .and_then(|m| m.as_str())
                            .unwrap_or("Failed to send verification code.")
                            .to_string();
                        error_message.set(Some(msg));
                    } else {
                        info_message.set(Some("Verification code sent to your email.".to_string()));
                        step.set(ForgotStep::Reset);
                    }
                }
                Err(err) => {
                    error_message.set(Some(err));
                }
            }

            loading.set(false);
        });
    };

    // Step 2: Reset password with code
    let do_reset = move |_| {
        let api_base_val = api_base();
        let org = organization();
        let em = email();
        let c = code();
        let pw = new_password();
        let cpw = confirm_password();

        if pw != cpw {
            error_message.set(Some("Passwords do not match.".to_string()));
            return;
        }

        if c.is_empty() || pw.is_empty() {
            error_message.set(Some("Verification code and new password are required.".to_string()));
            return;
        }

        spawn(async move {
            loading.set(true);
            error_message.set(None);
            info_message.set(None);

            let payload = json!({
                "organization": org,
                "email": em,
                "code": c,
                "new_password": pw,
            });

            let url = build_url(&api_base_val, "/api/reset-password");
            match request_json("POST", &url, None, Some(payload)).await {
                Ok(value) => {
                    let status = value
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("ok");

                    if status == "error" {
                        let msg = value
                            .get("msg")
                            .and_then(|m| m.as_str())
                            .unwrap_or("Password reset failed.")
                            .to_string();
                        error_message.set(Some(msg));
                    } else {
                        step.set(ForgotStep::Done);
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
        style { "{FORGOT_PASSWORD_CSS}" }

        div { class: "forgot-page",
            div { class: "forgot-box",
                // Step indicator
                div { class: "forgot-step-indicator",
                    {(0..3).map(|i| {
                        let cls = if i < step_index {
                            "forgot-step done"
                        } else if i == step_index {
                            "forgot-step active"
                        } else {
                            "forgot-step"
                        };
                        rsx! {
                            div { class: "{cls}", key: "step-{i}" }
                        }
                    })}
                }

                match step() {
                    ForgotStep::Email => {
                        rsx! {
                            h2 { "Reset your password" }
                            p { class: "subtitle",
                                "Enter your email address to receive a verification code."
                            }

                            div { class: "forgot-form",
                                div { class: "forgot-field",
                                    label { "Organization" }
                                    input {
                                        class: "text-input",
                                        r#type: "text",
                                        placeholder: "admin",
                                        value: "{organization}",
                                        oninput: move |evt| organization.set(evt.value()),
                                    }
                                }

                                div { class: "forgot-field",
                                    label {
                                        "Email address"
                                        span { class: "required-mark", " *" }
                                    }
                                    input {
                                        class: "text-input",
                                        r#type: "email",
                                        placeholder: "you@example.com",
                                        value: "{email}",
                                        oninput: move |evt| email.set(evt.value()),
                                        onkeypress: move |evt: KeyboardEvent| {
                                            if evt.key() == Key::Enter {
                                                do_send_code(());
                                            }
                                        },
                                    }
                                }

                                if let Some(err) = error_message() {
                                    div { class: "inline-message error", "{err}" }
                                }

                                div { class: "forgot-actions",
                                    button {
                                        class: "primary-button",
                                        disabled: loading() || email().is_empty(),
                                        onclick: do_send_code,
                                        if loading() { "Sending..." } else { "Send code" }
                                    }
                                }
                            }
                        }
                    }
                    ForgotStep::Reset => {
                        rsx! {
                            h2 { "Enter verification code" }
                            p { class: "subtitle",
                                "Check your email for the verification code and set a new password."
                            }

                            if let Some(info) = info_message() {
                                div { class: "inline-message success", "{info}" }
                            }

                            div { class: "forgot-form",
                                div { class: "forgot-field",
                                    label {
                                        "Verification code"
                                        span { class: "required-mark", " *" }
                                    }
                                    input {
                                        class: "text-input",
                                        r#type: "text",
                                        placeholder: "Enter the code from your email",
                                        value: "{code}",
                                        oninput: move |evt| code.set(evt.value()),
                                    }
                                }

                                div { class: "forgot-field",
                                    label {
                                        "New password"
                                        span { class: "required-mark", " *" }
                                    }
                                    div { class: "password-wrapper",
                                        input {
                                            class: "text-input password-input",
                                            r#type: if show_password() { "text" } else { "password" },
                                            placeholder: "Choose a new password",
                                            value: "{new_password}",
                                            oninput: move |evt| new_password.set(evt.value()),
                                        }
                                        button {
                                            class: "password-toggle ghost-button",
                                            r#type: "button",
                                            onclick: move |_| show_password.set(!show_password()),
                                            if show_password() { "Hide" } else { "Show" }
                                        }
                                    }
                                }

                                div { class: "forgot-field",
                                    label {
                                        "Confirm new password"
                                        span { class: "required-mark", " *" }
                                    }
                                    input {
                                        class: "text-input",
                                        r#type: if show_password() { "text" } else { "password" },
                                        placeholder: "Confirm your new password",
                                        value: "{confirm_password}",
                                        oninput: move |evt| confirm_password.set(evt.value()),
                                    }
                                    if !passwords_match {
                                        div { class: "inline-message error", "Passwords do not match." }
                                    }
                                }

                                if let Some(err) = error_message() {
                                    div { class: "inline-message error", "{err}" }
                                }

                                div { class: "forgot-actions",
                                    button {
                                        class: "primary-button",
                                        disabled: loading() || code().is_empty() || new_password().is_empty() || !passwords_match,
                                        onclick: do_reset,
                                        if loading() { "Resetting..." } else { "Reset password" }
                                    }
                                    button {
                                        class: "ghost-button",
                                        onclick: move |_| {
                                            step.set(ForgotStep::Email);
                                            error_message.set(None);
                                        },
                                        "Back"
                                    }
                                }
                            }
                        }
                    }
                    ForgotStep::Done => {
                        rsx! {
                            h2 { "Password reset" }
                            p { class: "subtitle",
                                "Your password has been reset successfully. You can now sign in with your new password."
                            }

                            div { class: "forgot-actions",
                                button {
                                    class: "primary-button",
                                    onclick: move |_| on_navigate.call("login".to_string()),
                                    "Back to sign in"
                                }
                            }
                        }
                    }
                }

                // Back to login link (except on done step)
                if !matches!(step(), ForgotStep::Done) {
                    div { class: "forgot-links",
                        button {
                            onclick: move |_| on_navigate.call("login".to_string()),
                            "Back to sign in"
                        }
                    }
                }
            }
        }
    }
}
