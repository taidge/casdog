use dioxus::prelude::*;
use serde_json::{Value, json};

use crate::api::{build_url, request_json};

const SIGNUP_PAGE_CSS: &str = r#"
.signup-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
}

.signup-box {
  width: 100%;
  max-width: 480px;
  padding: 36px;
  border: 1px solid var(--line);
  border-radius: 28px;
  background: var(--surface);
  box-shadow: var(--shadow);
  backdrop-filter: blur(18px);
  animation: fade-up 320ms ease;
}

.signup-box h2 {
  margin: 0 0 8px;
  font-size: 32px;
  font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
}

.signup-box .subtitle {
  margin: 0 0 24px;
  color: var(--text-soft);
  line-height: 1.5;
}

.signup-form {
  display: grid;
  gap: 16px;
}

.signup-field {
  display: grid;
  gap: 6px;
}

.signup-field label {
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.04em;
}

.signup-field .required-mark {
  color: var(--danger);
}

.signup-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.signup-actions {
  margin-top: 8px;
}

.signup-links {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: 20px;
  font-size: 14px;
  color: var(--text-soft);
}

.signup-links button {
  background: none;
  border: none;
  color: var(--accent);
  cursor: pointer;
  font: inherit;
  font-weight: 600;
  padding: 0;
}

.signup-links button:hover {
  text-decoration: underline;
}
"#;

/// Registration page component.
///
/// Props:
/// * `api_base` - Signal with the API base URL.
/// * `on_signup` - Called with the server response Value after successful registration.
/// * `on_navigate` - Called with a page name ("login") when the "Sign in" link is clicked.
/// * `default_organization` - Pre-filled organization.
/// * `default_application` - Pre-filled application.
#[component]
pub fn SignupPage(
    api_base: Signal<String>,
    on_signup: EventHandler<Value>,
    on_navigate: EventHandler<String>,
    #[props(default = "admin".to_string())] default_organization: String,
    #[props(default)] default_application: String,
) -> Element {
    let mut organization = use_signal(|| default_organization.clone());
    let mut username = use_signal(String::new);
    let mut display_name = use_signal(String::new);
    let mut email = use_signal(String::new);
    let mut phone = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut confirm_password = use_signal(String::new);
    let mut application = use_signal(|| default_application.clone());
    let mut loading = use_signal(|| false);
    let mut error_message = use_signal(|| None::<String>);
    let mut show_password = use_signal(|| false);

    let passwords_match = password().is_empty() || password() == confirm_password();
    let can_submit = !username().is_empty()
        && !password().is_empty()
        && !confirm_password().is_empty()
        && passwords_match
        && !loading();

    let do_signup = move |_| {
        let api_base_val = api_base();
        let org = organization();
        let user = username();
        let disp = display_name();
        let em = email();
        let ph = phone();
        let pass = password();
        let conf = confirm_password();
        let app = application();
        let mut loading = loading;
        let mut error_message = error_message;

        if pass != conf {
            error_message.set(Some("Passwords do not match.".to_string()));
            return;
        }

        spawn(async move {
            loading.set(true);
            error_message.set(None);

            let mut payload = json!({
                "owner": org,
                "name": user,
                "password": pass,
            });

            let obj = payload.as_object_mut().unwrap();
            if !disp.is_empty() {
                obj.insert("display_name".into(), Value::String(disp));
            }
            if !em.is_empty() {
                obj.insert("email".into(), Value::String(em));
            }
            if !ph.is_empty() {
                obj.insert("phone".into(), Value::String(ph));
            }
            if !app.is_empty() {
                obj.insert("application".into(), Value::String(app));
            }

            let url = build_url(&api_base_val, "/api/signup");
            match request_json("POST", &url, None, Some(payload)).await {
                Ok(value) => {
                    // Check if server returned an error status in the response body
                    let status = value
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("ok");

                    if status == "error" {
                        let msg = value
                            .get("msg")
                            .and_then(|m| m.as_str())
                            .unwrap_or("Registration failed.")
                            .to_string();
                        error_message.set(Some(msg));
                    } else {
                        on_signup.call(value);
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
        style { "{SIGNUP_PAGE_CSS}" }

        div { class: "signup-page",
            div { class: "signup-box",
                h2 { "Create account" }
                p { class: "subtitle", "Register a new account to get started." }

                div { class: "signup-form",
                    // Organization
                    div { class: "signup-field",
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

                    // Username + Display Name row
                    div { class: "signup-row",
                        div { class: "signup-field",
                            label {
                                "Username"
                                span { class: "required-mark", " *" }
                            }
                            input {
                                class: "text-input",
                                r#type: "text",
                                placeholder: "Choose a username",
                                value: "{username}",
                                oninput: move |evt| username.set(evt.value()),
                            }
                        }
                        div { class: "signup-field",
                            label { "Display name" }
                            input {
                                class: "text-input",
                                r#type: "text",
                                placeholder: "Your display name",
                                value: "{display_name}",
                                oninput: move |evt| display_name.set(evt.value()),
                            }
                        }
                    }

                    // Email + Phone row
                    div { class: "signup-row",
                        div { class: "signup-field",
                            label { "Email" }
                            input {
                                class: "text-input",
                                r#type: "email",
                                placeholder: "you@example.com",
                                value: "{email}",
                                oninput: move |evt| email.set(evt.value()),
                            }
                        }
                        div { class: "signup-field",
                            label { "Phone" }
                            input {
                                class: "text-input",
                                r#type: "tel",
                                placeholder: "+1 555-0100",
                                value: "{phone}",
                                oninput: move |evt| phone.set(evt.value()),
                            }
                        }
                    }

                    // Password
                    div { class: "signup-field",
                        label {
                            "Password"
                            span { class: "required-mark", " *" }
                        }
                        div { class: "password-wrapper",
                            input {
                                class: "text-input password-input",
                                r#type: if show_password() { "text" } else { "password" },
                                placeholder: "Choose a password",
                                value: "{password}",
                                oninput: move |evt| password.set(evt.value()),
                            }
                            button {
                                class: "password-toggle ghost-button",
                                r#type: "button",
                                onclick: move |_| show_password.set(!show_password()),
                                if show_password() { "Hide" } else { "Show" }
                            }
                        }
                    }

                    // Confirm password
                    div { class: "signup-field",
                        label {
                            "Confirm password"
                            span { class: "required-mark", " *" }
                        }
                        input {
                            class: "text-input",
                            r#type: if show_password() { "text" } else { "password" },
                            placeholder: "Confirm your password",
                            value: "{confirm_password}",
                            oninput: move |evt| confirm_password.set(evt.value()),
                        }
                        if !passwords_match {
                            div { class: "inline-message error", "Passwords do not match." }
                        }
                    }

                    // Application
                    div { class: "signup-field",
                        label { "Application" }
                        input {
                            class: "text-input",
                            r#type: "text",
                            placeholder: "Application (optional)",
                            value: "{application}",
                            oninput: move |evt| application.set(evt.value()),
                        }
                    }

                    // Error display
                    if let Some(err) = error_message() {
                        div { class: "inline-message error", "{err}" }
                    }

                    // Submit
                    div { class: "signup-actions",
                        button {
                            class: "primary-button",
                            disabled: !can_submit,
                            onclick: do_signup,
                            if loading() { "Creating account..." } else { "Create account" }
                        }
                    }
                }

                // Sign in link
                div { class: "signup-links",
                    span { "Already have an account?" }
                    button {
                        onclick: move |_| on_navigate.call("login".to_string()),
                        "Sign in"
                    }
                }
            }
        }
    }
}
