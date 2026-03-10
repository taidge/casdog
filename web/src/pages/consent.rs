use dioxus::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{build_url, extract_collection, request_json};

const CONSENT_PAGE_CSS: &str = r#"
.consent-page {
  max-width: 720px;
  margin: 0 auto;
  padding: 30px;
  animation: fade-up 320ms ease;
}

.consent-page h2 {
  margin: 0 0 8px;
  font-size: 32px;
  font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
}

.consent-page .subtitle {
  margin: 0 0 28px;
  color: var(--text-soft);
  line-height: 1.5;
}

.consent-section {
  margin-bottom: 28px;
}

.consent-section h3 {
  margin: 0 0 14px;
  font-size: 18px;
}

.consent-list {
  display: grid;
  gap: 12px;
}

.consent-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 16px 20px;
  border: 1px solid var(--line);
  border-radius: 18px;
  background: var(--surface);
}

.consent-card-info {
  flex: 1;
  min-width: 0;
}

.consent-card-info h4 {
  margin: 0 0 4px;
  font-size: 16px;
}

.consent-card-info p {
  margin: 0;
  font-size: 13px;
  color: var(--text-soft);
}

.consent-card-scopes {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 8px;
}

.consent-scope-chip {
  padding: 3px 8px;
  border-radius: 8px;
  background: var(--surface-soft);
  font-size: 12px;
  color: var(--text);
}

.consent-grant-form {
  display: grid;
  gap: 14px;
  padding: 20px;
  border: 1px solid var(--line);
  border-radius: 18px;
  background: var(--surface);
}

.consent-grant-form .form-row {
  display: grid;
  gap: 6px;
}

.consent-grant-form label {
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.04em;
}

.consent-grant-actions {
  display: flex;
  gap: 10px;
}

.consent-empty {
  padding: 24px;
  text-align: center;
  color: var(--text-soft);
  border: 1px dashed var(--line);
  border-radius: 18px;
}
"#;

#[derive(Debug, Clone, Default, Deserialize)]
struct ConsentEntry {
    #[serde(default)]
    id: String,
    #[serde(default)]
    application: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    scopes: Option<String>,
    #[serde(default)]
    created_time: Option<String>,
    #[serde(default)]
    granted_at: Option<String>,
}

/// Consent management page: view granted consents, revoke, or grant new ones.
///
/// Props:
/// * `api_base` - Signal with the API base URL.
/// * `token` - The current user's auth token.
#[component]
pub fn ConsentPage(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
) -> Element {
    let mut consents = use_signal(Vec::<ConsentEntry>::new);
    let mut loading = use_signal(|| false);
    let mut error_message = use_signal(|| None::<String>);
    let mut success_message = use_signal(|| None::<String>);
    let mut refresh_nonce = use_signal(|| 0_u64);

    // Grant form state
    let mut grant_app = use_signal(String::new);
    let mut grant_scopes = use_signal(String::new);
    let mut granting = use_signal(|| false);

    // Fetch consents
    {
        let api_base_val = api_base();
        let token_val = token();
        let _nonce = refresh_nonce();
        let mut consents = consents;
        let mut loading = loading;
        let mut error_message = error_message;

        use_effect(move || {
            let api_base_val = api_base_val.clone();
            let token_val = token_val.clone();

            if token_val.is_none() {
                consents.set(Vec::new());
                error_message.set(Some("Sign in to manage consents.".to_string()));
                return;
            }

            loading.set(true);
            error_message.set(None);

            spawn(async move {
                let url = build_url(&api_base_val, "/api/consents");
                match request_json("GET", &url, token_val.as_deref(), None).await {
                    Ok(value) => {
                        let collection = extract_collection(value);
                        let entries: Vec<ConsentEntry> = collection
                            .into_iter()
                            .filter_map(|v| serde_json::from_value(v).ok())
                            .collect();
                        consents.set(entries);
                    }
                    Err(err) => {
                        error_message.set(Some(err));
                    }
                }
                loading.set(false);
            });
        });
    }

    let do_revoke = move |consent_id: String| {
        let api_base_val = api_base();
        let token_val = token();
        let mut error_message = error_message;
        let mut success_message = success_message;
        let mut refresh_nonce = refresh_nonce;

        spawn(async move {
            error_message.set(None);
            success_message.set(None);

            let url = build_url(&api_base_val, &format!("/api/consents/{consent_id}"));
            match request_json("DELETE", &url, token_val.as_deref(), None).await {
                Ok(_) => {
                    success_message.set(Some("Consent revoked successfully.".to_string()));
                    refresh_nonce.set(refresh_nonce() + 1);
                }
                Err(err) => {
                    error_message.set(Some(err));
                }
            }
        });
    };

    let do_grant = move |_| {
        let api_base_val = api_base();
        let token_val = token();
        let app = grant_app();
        let scopes = grant_scopes();
        let mut granting = granting;
        let mut error_message = error_message;
        let mut success_message = success_message;
        let mut refresh_nonce = refresh_nonce;
        let mut grant_app = grant_app;
        let mut grant_scopes = grant_scopes;

        if app.is_empty() {
            error_message.set(Some("Application is required.".to_string()));
            return;
        }

        spawn(async move {
            granting.set(true);
            error_message.set(None);
            success_message.set(None);

            let payload = json!({
                "application": app,
                "scopes": scopes,
            });

            let url = build_url(&api_base_val, "/api/consents");
            match request_json("POST", &url, token_val.as_deref(), Some(payload)).await {
                Ok(_) => {
                    success_message.set(Some("Consent granted successfully.".to_string()));
                    grant_app.set(String::new());
                    grant_scopes.set(String::new());
                    refresh_nonce.set(refresh_nonce() + 1);
                }
                Err(err) => {
                    error_message.set(Some(err));
                }
            }

            granting.set(false);
        });
    };

    rsx! {
        style { "{CONSENT_PAGE_CSS}" }

        div { class: "consent-page",
            h2 { "Consent management" }
            p { class: "subtitle", "Manage your application authorizations." }

            // Messages
            if let Some(msg) = success_message() {
                div { class: "inline-message success", "{msg}" }
            }
            if let Some(err) = error_message() {
                div { class: "inline-message error", "{err}" }
            }

            // Granted consents
            div { class: "consent-section",
                h3 { "Granted consents" }

                if loading() {
                    div { class: "inline-message neutral", "Loading consents..." }
                } else if consents().is_empty() {
                    div { class: "consent-empty", "No consents granted yet." }
                } else {
                    div { class: "consent-list",
                        {consents().iter().map(|consent| {
                            let id = consent.id.clone();
                            let app_name = consent.display_name.clone()
                                .filter(|s| !s.is_empty())
                                .unwrap_or_else(|| consent.application.clone());
                            let scope_list: Vec<String> = consent.scopes.clone()
                                .unwrap_or_default()
                                .split_whitespace()
                                .map(String::from)
                                .filter(|s| !s.is_empty())
                                .collect();
                            let granted = consent.granted_at.clone()
                                .or_else(|| consent.created_time.clone())
                                .unwrap_or_else(|| "Unknown".to_string());
                            let revoke_id = id.clone();

                            rsx! {
                                div { class: "consent-card", key: "{id}",
                                    div { class: "consent-card-info",
                                        h4 { "{app_name}" }
                                        p { "Granted: {granted}" }
                                        if !scope_list.is_empty() {
                                            div { class: "consent-card-scopes",
                                                {scope_list.iter().map(|s| {
                                                    rsx! {
                                                        span { class: "consent-scope-chip", key: "{s}", "{s}" }
                                                    }
                                                })}
                                            }
                                        }
                                    }
                                    button {
                                        class: "danger-button",
                                        onclick: move |_| do_revoke(revoke_id.clone()),
                                        "Revoke"
                                    }
                                }
                            }
                        })}
                    }
                }
            }

            // Grant new consent
            div { class: "consent-section",
                h3 { "Grant new consent" }
                div { class: "consent-grant-form",
                    div { class: "form-row",
                        label { "Application" }
                        input {
                            class: "text-input",
                            r#type: "text",
                            placeholder: "Application name or ID",
                            value: "{grant_app}",
                            oninput: move |evt| grant_app.set(evt.value()),
                        }
                    }
                    div { class: "form-row",
                        label { "Scopes" }
                        input {
                            class: "text-input",
                            r#type: "text",
                            placeholder: "openid profile email (space-separated)",
                            value: "{grant_scopes}",
                            oninput: move |evt| grant_scopes.set(evt.value()),
                        }
                    }
                    div { class: "consent-grant-actions",
                        button {
                            class: "primary-button",
                            disabled: granting() || grant_app().is_empty(),
                            onclick: do_grant,
                            if granting() { "Granting..." } else { "Grant" }
                        }
                    }
                }
            }
        }
    }
}
