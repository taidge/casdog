mod api;
mod resources;
mod style;

use dioxus::prelude::*;
use gloo_storage::{LocalStorage, Storage};
use resources::{GROUP_ORDER, RESOURCES, ResourceConfig, resource_config};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{
    build_url, extract_collection, filter_matches, item_id, item_subtitle, item_title, pretty_json,
    request_json,
};
use crate::style::APP_CSS;

const AUTH_TOKEN_KEY: &str = "casdog.auth.token";
const ACCOUNT_KEY: &str = "casdog.auth.account";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct AccountSummary {
    owner: String,
    name: String,
    display_name: Option<String>,
    is_admin: bool,
}

#[derive(Debug, Deserialize)]
struct LoginPayload {
    token: String,
    user: AccountSummary,
}

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    let mut api_base = use_signal(|| option_env!("CASDOG_API_BASE").unwrap_or("").to_string());
    let mut token = use_signal(|| LocalStorage::get::<String>(AUTH_TOKEN_KEY).ok());
    let mut account = use_signal(|| LocalStorage::get::<AccountSummary>(ACCOUNT_KEY).ok());
    let mut active_panel = use_signal(|| "dashboard".to_string());

    let is_authenticated = token().is_some();
    let account_name = account()
        .map(display_account_name)
        .unwrap_or_else(|| "Guest".to_string());

    rsx! {
        style { "{APP_CSS}" }
        div { class: "shell",
            aside { class: "sidebar",
                div { class: "brand",
                    p { class: "eyebrow", "Casdoor parity shell" }
                    h1 { "Casdog" }
                    p { "Dioxus frontend for the Salvo backend. The shell maps existing REST resources and exposes the new site and rule management domains." }
                }

                div { class: "field",
                    span { "API base" }
                    input {
                        class: "text-input",
                        placeholder: "same origin",
                        value: "{api_base}",
                        oninput: move |event| api_base.set(event.value()),
                    }
                }

                div { class: "field",
                    span { "Session" }
                    div { class: if is_authenticated { "status-chip success" } else { "status-chip warn" },
                        "{account_name}"
                    }
                }

                if is_authenticated {
                    button {
                        class: "ghost-button",
                        onclick: move |_| {
                            LocalStorage::delete(AUTH_TOKEN_KEY);
                            LocalStorage::delete(ACCOUNT_KEY);
                            token.set(None);
                            account.set(None);
                            active_panel.set("dashboard".to_string());
                        },
                        "Logout"
                    }
                }

                div { class: "nav-section",
                    p { class: "section-label", "Overview" }
                    div { class: "nav-grid",
                        button {
                            class: if active_panel() == "dashboard" { "nav-item active" } else { "nav-item" },
                            onclick: move |_| active_panel.set("dashboard".to_string()),
                            "Dashboard"
                        }
                    }
                }

                {
                    GROUP_ORDER.iter().map(|group| {
                        rsx! {
                            div { class: "nav-section", key: "{group}",
                                p { class: "section-label", "{group}" }
                                div { class: "nav-grid",
                                    {
                                        RESOURCES.iter().filter(|config| config.group == *group).map(|config| {
                                            let slug = config.slug.to_string();
                                            let is_active = active_panel() == slug;
                                            rsx! {
                                                button {
                                                    class: if is_active { "nav-item active" } else { "nav-item" },
                                                    onclick: move |_| active_panel.set(slug.clone()),
                                                    "{config.label}"
                                                }
                                            }
                                        })
                                    }
                                }
                            }
                        }
                    })
                }
            }

            main { class: "main",
                if active_panel() == "dashboard" {
                    DashboardPanel {
                        api_base,
                        token,
                        account,
                        active_panel,
                    }
                } else if let Some(config) = resource_config(&active_panel()) {
                    ResourcePanel {
                        key: "{config.slug}",
                        config,
                        api_base,
                        token,
                    }
                } else {
                    section { class: "hero panel",
                        h2 { "Unknown panel" }
                        p { "The selected navigation item is not registered in the frontend resource catalog." }
                    }
                }
            }
        }
    }
}

#[component]
fn DashboardPanel(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
    account: Signal<Option<AccountSummary>>,
    active_panel: Signal<String>,
) -> Element {
    let health_state = use_signal(|| "Checking /api/health".to_string());

    {
        let mut health_state = health_state;
        let api_base_value = api_base();
        use_effect(move || {
            let api_base_value = api_base_value.clone();
            spawn(async move {
                let url = build_url(&api_base_value, "/api/health");
                let message = match request_json("GET", &url, None, None).await {
                    Ok(value) => value
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("ok")
                        .to_string(),
                    Err(err) => err,
                };
                health_state.set(message);
            });
        });
    }

    let resource_count = RESOURCES.len();
    let session_text = if let Some(account) = account() {
        format!(
            "{} · owner: {} · admin: {}",
            display_account_name(account.clone()),
            account.owner,
            account.is_admin
        )
    } else {
        "Sign in with an API user to unlock CRUD operations.".to_string()
    };

    rsx! {
        section { class: "hero panel",
            p { class: "eyebrow", "Management shell" }
            h2 { "Casdoor features mapped to Dioxus" }
            p {
                "This frontend targets the current Salvo API surface. It exposes list and JSON-edit workflows for the core IAM resources and includes the newly added edge-management domains for sites and rules."
            }
            div { class: "badge-row",
                span { class: "status-chip success", "API health: {health_state}" }
                span { class: if token().is_some() { "status-chip success" } else { "status-chip warn" },
                    if token().is_some() { "Authenticated" } else { "Read-only until login" }
                }
                span { class: "status-chip", "{resource_count} mapped resources" }
            }
        }

        div { class: "dashboard-grid",
            article { class: "dashboard-card",
                h3 { "Session" }
                p { "{session_text}" }
            }
            article { class: "dashboard-card",
                h3 { "New parity slice" }
                p { "Rules and sites are now first-class backend resources, matching two major Casdoor domains that were still missing from the Rust port." }
            }
            article { class: "dashboard-card",
                h3 { "Quick jump" }
                div { class: "badge-row",
                    button {
                        class: "primary-button",
                        onclick: move |_| active_panel.set("rules".to_string()),
                        "Open rules"
                    }
                    button {
                        class: "ghost-button",
                        onclick: move |_| active_panel.set("sites".to_string()),
                        "Open sites"
                    }
                }
            }
        }

        if token().is_none() {
            LoginCard {
                api_base,
                token,
                account,
            }
        }
    }
}

#[component]
fn LoginCard(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
    account: Signal<Option<AccountSummary>>,
) -> Element {
    let mut owner = use_signal(|| "admin".to_string());
    let mut username = use_signal(|| "admin".to_string());
    let mut password = use_signal(String::new);
    let message = use_signal(|| None::<String>);
    let loading = use_signal(|| false);

    rsx! {
        section { class: "login-card",
            h3 { "Sign in" }
            p { "Use an existing Casdog account so the Dioxus shell can call the protected management APIs." }

            div { class: "field",
                span { "Organization" }
                input {
                    class: "text-input",
                    value: "{owner}",
                    oninput: move |event| owner.set(event.value()),
                }
            }

            div { class: "field",
                span { "Username" }
                input {
                    class: "text-input",
                    value: "{username}",
                    oninput: move |event| username.set(event.value()),
                }
            }

            div { class: "field",
                span { "Password" }
                input {
                    class: "text-input",
                    r#type: "password",
                    value: "{password}",
                    oninput: move |event| password.set(event.value()),
                }
            }

            div { class: "badge-row",
                button {
                    class: "primary-button",
                    disabled: loading(),
                    onclick: move |_| {
                        let api_base_value = api_base();
                        let owner_value = owner();
                        let username_value = username();
                        let password_value = password();
                        let mut token = token;
                        let mut account = account;
                        let mut message = message;
                        let mut loading = loading;

                        spawn(async move {
                            loading.set(true);
                            message.set(None);

                            let payload = json!({
                                "owner": owner_value,
                                "name": username_value,
                                "password": password_value,
                            });

                            let result = request_json(
                                "POST",
                                &build_url(&api_base_value, "/api/login"),
                                None,
                                Some(payload),
                            )
                            .await;

                            match result.and_then(|value| {
                                serde_json::from_value::<LoginPayload>(value)
                                    .map_err(|err| err.to_string())
                            }) {
                                Ok(login) => {
                                    let _ = LocalStorage::set(AUTH_TOKEN_KEY, login.token.clone());
                                    let _ = LocalStorage::set(ACCOUNT_KEY, login.user.clone());
                                    token.set(Some(login.token));
                                    account.set(Some(login.user));
                                }
                                Err(err) => {
                                    message.set(Some(err));
                                }
                            }

                            loading.set(false);
                        });
                    },
                    if loading() { "Signing in..." } else { "Sign in" }
                }
            }

            if let Some(message) = message() {
                div { class: "inline-message error", "{message}" }
            }
        }
    }
}

#[component]
fn ResourcePanel(
    config: ResourceConfig,
    api_base: Signal<String>,
    token: Signal<Option<String>>,
) -> Element {
    let items = use_signal(Vec::<Value>::new);
    let loading = use_signal(|| false);
    let error = use_signal(|| None::<String>);
    let mut filter = use_signal(String::new);
    let mut selected_id = use_signal(|| None::<String>);
    let mut editor_text = use_signal(|| config.template.to_string());
    let mut status_message = use_signal(|| None::<String>);
    let mut status_is_error = use_signal(|| false);
    let mut refresh_nonce = use_signal(|| 0_u64);

    {
        let endpoint = config.endpoint.to_string();
        let api_base_value = api_base();
        let token_value = token();
        let _refresh = refresh_nonce();
        let mut items = items;
        let mut loading = loading;
        let mut error = error;
        let mut status_message = status_message;
        use_effect(move || {
            if token_value.is_none() {
                items.set(Vec::new());
                error.set(Some("Sign in to load this resource.".to_string()));
                loading.set(false);
                return;
            }

            loading.set(true);
            error.set(None);
            status_message.set(None);

            let api_base_value = api_base_value.clone();
            let endpoint = endpoint.clone();
            let token_value = token_value.clone();
            spawn(async move {
                let url = build_url(&api_base_value, &endpoint);
                match request_json("GET", &url, token_value.as_deref(), None).await {
                    Ok(value) => {
                        items.set(extract_collection(value));
                        loading.set(false);
                    }
                    Err(err) => {
                        items.set(Vec::new());
                        error.set(Some(err));
                        loading.set(false);
                    }
                }
            });
        });
    }

    let filtered_items = {
        let needle = filter().to_lowercase();
        items()
            .into_iter()
            .filter(|value| filter_matches(value, &needle))
            .collect::<Vec<_>>()
    };

    let active_id = selected_id();

    rsx! {
        section { class: "hero panel",
            p { class: "eyebrow", "{config.group}" }
            h2 { "{config.label}" }
            p { "{config.description}" }
            div { class: "badge-row",
                span { class: "status-chip", "{filtered_items.len()} visible rows" }
                span { class: if token().is_some() { "status-chip success" } else { "status-chip warn" },
                    if token().is_some() { "API session ready" } else { "Sign in required" }
                }
            }
        }

        div { class: "resource-layout",
            section { class: "list-pane",
                div { class: "toolbar",
                    input {
                        class: "text-input",
                        placeholder: "Filter rows",
                        value: "{filter}",
                        oninput: move |event| filter.set(event.value()),
                    }
                    button {
                        class: "ghost-button",
                        onclick: move |_| refresh_nonce.set(refresh_nonce() + 1),
                        "Refresh"
                    }
                    button {
                        class: "primary-button",
                        onclick: move |_| {
                            selected_id.set(None);
                            editor_text.set(config.template.to_string());
                            status_is_error.set(false);
                            status_message.set(Some("Loaded resource template.".to_string()));
                        },
                        "New draft"
                    }
                }

                if loading() {
                    div { class: "inline-message neutral", "Loading {config.label.to_lowercase()}..." }
                } else if let Some(error) = error() {
                    div { class: "inline-message error", "{error}" }
                }

                div { class: "list-scroll",
                    if filtered_items.is_empty() {
                        div { class: "inline-message neutral", "No rows loaded yet." }
                    } else {
                        {
                            filtered_items.into_iter().map(|item| {
                                let id = item_id(&item);
                                let title = item_title(&item);
                                let subtitle = item_subtitle(&item);
                                let is_active = active_id.as_deref() == id.as_deref();
                                let fallback_item = item.clone();

                                rsx! {
                                    article {
                                        class: if is_active { "resource-card active" } else { "resource-card" },
                                        key: "{id.clone().unwrap_or_else(|| title.clone())}",
                                        onclick: move |_| {
                                            let mut selected_id = selected_id;
                                            let mut editor_text = editor_text;
                                            let mut status_message = status_message;
                                            let mut status_is_error = status_is_error;
                                            let api_base_value = api_base();
                                            let token_value = token();
                                            let endpoint = config.endpoint.to_string();
                                            let fallback_json = pretty_json(&fallback_item);

                                            if let Some(id) = id.clone() {
                                                spawn(async move {
                                                    let url = format!("{}/{}", build_url(&api_base_value, &endpoint), id);
                                                    match request_json("GET", &url, token_value.as_deref(), None).await {
                                                        Ok(value) => {
                                                            selected_id.set(item_id(&value));
                                                            editor_text.set(pretty_json(&value));
                                                            status_is_error.set(false);
                                                            status_message.set(None);
                                                        }
                                                        Err(err) => {
                                                            selected_id.set(None);
                                                            editor_text.set(fallback_json);
                                                            status_is_error.set(true);
                                                            status_message.set(Some(err));
                                                        }
                                                    }
                                                });
                                            } else {
                                                selected_id.set(None);
                                                editor_text.set(fallback_json);
                                                status_is_error.set(false);
                                                status_message.set(None);
                                            }
                                        },
                                        h4 { "{title}" }
                                        p { "{subtitle}" }
                                    }
                                }
                            })
                        }
                    }
                }
            }

            section { class: "editor-pane",
                div { class: "toolbar",
                    button {
                        class: "primary-button",
                        disabled: token().is_none(),
                        onclick: move |_| {
                            let token_value = token();
                            let api_base_value = api_base();
                            let endpoint = config.endpoint.to_string();
                            let selected = selected_id();
                            let current_text = editor_text();
                            let mut editor_text = editor_text;
                            let mut selected_id = selected_id;
                            let mut refresh_nonce = refresh_nonce;
                            let mut status_message = status_message;
                            let mut status_is_error = status_is_error;

                            spawn(async move {
                                let payload = match serde_json::from_str::<Value>(&current_text) {
                                    Ok(payload) => payload,
                                    Err(err) => {
                                        status_is_error.set(true);
                                        status_message.set(Some(format!("Invalid JSON: {err}")));
                                        return;
                                    }
                                };

                                let (method, url) = if let Some(id) = selected {
                                    (
                                        "PUT",
                                        format!("{}/{}", build_url(&api_base_value, &endpoint), id),
                                    )
                                } else {
                                    ("POST", build_url(&api_base_value, &endpoint))
                                };

                                match request_json(method, &url, token_value.as_deref(), Some(payload)).await {
                                    Ok(value) => {
                                        selected_id.set(item_id(&value));
                                        editor_text.set(pretty_json(&value));
                                        status_is_error.set(false);
                                        status_message.set(Some("Saved successfully.".to_string()));
                                        refresh_nonce.set(refresh_nonce() + 1);
                                    }
                                    Err(err) => {
                                        status_is_error.set(true);
                                        status_message.set(Some(err));
                                    }
                                }
                            });
                        },
                        "Save"
                    }
                    button {
                        class: "danger-button",
                        disabled: token().is_none() || selected_id().is_none(),
                        onclick: move |_| {
                            let token_value = token();
                            let api_base_value = api_base();
                            let endpoint = config.endpoint.to_string();
                            let selected = selected_id();
                            let mut selected_id = selected_id;
                            let mut editor_text = editor_text;
                            let mut refresh_nonce = refresh_nonce;
                            let mut status_message = status_message;
                            let mut status_is_error = status_is_error;

                            if let Some(id) = selected {
                                spawn(async move {
                                    let url = format!("{}/{}", build_url(&api_base_value, &endpoint), id);
                                    match request_json("DELETE", &url, token_value.as_deref(), None).await {
                                        Ok(_) => {
                                            selected_id.set(None);
                                            editor_text.set(config.template.to_string());
                                            status_is_error.set(false);
                                            status_message.set(Some("Deleted successfully.".to_string()));
                                            refresh_nonce.set(refresh_nonce() + 1);
                                        }
                                        Err(err) => {
                                            status_is_error.set(true);
                                            status_message.set(Some(err));
                                        }
                                    }
                                });
                            }
                        },
                        "Delete"
                    }
                }

                div { class: "editor",
                    p { class: "section-title", "JSON editor" }
                    p { "The editor sends raw JSON to the Salvo resource endpoint. Start from the built-in template or load an existing row from the left pane." }
                    textarea {
                        value: "{editor_text}",
                        oninput: move |event| editor_text.set(event.value()),
                    }
                }

                if let Some(message) = status_message() {
                    div {
                        class: if status_is_error() { "inline-message error" } else { "inline-message success" },
                        "{message}"
                    }
                }
            }
        }
    }
}

fn display_account_name(account: AccountSummary) -> String {
    account
        .display_name
        .filter(|value| !value.is_empty())
        .unwrap_or(account.name)
}
