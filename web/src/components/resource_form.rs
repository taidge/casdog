use dioxus::prelude::*;
use serde_json::{Value, json, Map};

use crate::components::form_fields::*;
use crate::resources::ResourceConfig;

pub const RESOURCE_FORM_CSS: &str = r#"
.resource-form-container {
  display: grid;
  gap: 8px;
}

.resource-form-tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}

.resource-form-tab {
  padding: 8px 14px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: transparent;
  color: var(--text-soft);
  cursor: pointer;
  font: inherit;
  font-size: 13px;
  transition: background 160ms ease, color 160ms ease;
}

.resource-form-tab:hover {
  background: var(--surface-soft);
}

.resource-form-tab.active {
  background: var(--surface-strong);
  color: #fff;
  border-color: var(--surface-strong);
}

.resource-form-section {
  margin-bottom: 8px;
}

.resource-form-section-title {
  font-size: 14px;
  font-weight: 600;
  margin: 16px 0 8px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--line);
  color: var(--text);
}
"#;

/// Field definition for the structured resource form.
#[derive(Clone)]
struct FieldDef {
    key: &'static str,
    label: &'static str,
    kind: FieldKind,
    required: bool,
}

#[derive(Clone)]
enum FieldKind {
    Text,
    TextArea,
    Password,
    Number,
    Toggle,
    Json,
    Select(Vec<SelectOption>),
    Tags,
}

/// ResourceForm replaces raw JSON editing with typed fields based on the resource type.
///
/// Props:
/// * `config` - The resource configuration (determines which fields to show).
/// * `value` - The current JSON string being edited.
/// * `onchange` - Called with the updated JSON string whenever a field changes.
#[component]
pub fn ResourceForm(
    config: ResourceConfig,
    value: String,
    onchange: EventHandler<String>,
) -> Element {
    let mut view_mode = use_signal(|| "structured".to_string());
    let mut json_text = use_signal(|| value.clone());

    // Parse the current value
    let parsed: Value = serde_json::from_str(&value).unwrap_or(Value::Object(Map::new()));

    let fields = fields_for_resource(config.slug);
    let has_structured = !fields.is_empty();

    // Sync json_text when value changes externally
    if json_text() != value {
        json_text.set(value.clone());
    }

    rsx! {
        style { "{RESOURCE_FORM_CSS}" }
        style { "{FORM_FIELDS_CSS}" }

        div { class: "resource-form-container",
            // View mode tabs
            if has_structured {
                div { class: "resource-form-tabs",
                    button {
                        class: if view_mode() == "structured" { "resource-form-tab active" } else { "resource-form-tab" },
                        onclick: move |_| {
                            // Sync from json_text to structured view
                            view_mode.set("structured".to_string());
                        },
                        "Structured"
                    }
                    button {
                        class: if view_mode() == "json" { "resource-form-tab active" } else { "resource-form-tab" },
                        onclick: move |_| {
                            view_mode.set("json".to_string());
                        },
                        "JSON"
                    }
                }
            }

            if !has_structured || view_mode() == "json" {
                // JSON editor mode
                div { class: "editor",
                    p { class: "section-title", "JSON editor" }
                    p { "Edit the raw JSON representation of this resource." }
                    textarea {
                        value: "{json_text}",
                        oninput: move |evt: Event<FormData>| {
                            let new_val = evt.value();
                            json_text.set(new_val.clone());
                            onchange.call(new_val);
                        },
                    }
                }
            } else {
                // Structured form mode
                {render_structured_fields(fields, &parsed, &onchange)}
            }
        }
    }
}

fn render_structured_fields(
    fields: Vec<FieldDef>,
    parsed: &Value,
    onchange: &EventHandler<String>,
) -> Element {
    let parsed_clone = parsed.clone();

    rsx! {
        div { class: "resource-form-section",
            {fields.into_iter().map(move |field| {
                let obj = parsed_clone.as_object();
                let current_value = obj
                    .and_then(|m| m.get(field.key))
                    .cloned()
                    .unwrap_or(Value::Null);

                render_single_field(field, current_value, &parsed_clone, onchange)
            })}
        }
    }
}

fn render_single_field(
    field: FieldDef,
    current: Value,
    full_obj: &Value,
    onchange: &EventHandler<String>,
) -> Element {
    let key = field.key;
    let label = field.label.to_string();
    let required = field.required;

    match field.kind {
        FieldKind::Text => {
            let str_val = current.as_str().unwrap_or("").to_string();
            let full = full_obj.clone();
            rsx! {
                TextField {
                    label,
                    value: str_val,
                    required,
                    oninput: move |new_val: String| {
                        let updated = set_field(&full, key, Value::String(new_val));
                        onchange.call(serde_json::to_string_pretty(&updated).unwrap_or_default());
                    },
                }
            }
        }
        FieldKind::TextArea => {
            let str_val = current.as_str().unwrap_or("").to_string();
            let full = full_obj.clone();
            rsx! {
                TextArea {
                    label,
                    value: str_val,
                    required,
                    rows: 4,
                    oninput: move |new_val: String| {
                        let updated = set_field(&full, key, Value::String(new_val));
                        onchange.call(serde_json::to_string_pretty(&updated).unwrap_or_default());
                    },
                }
            }
        }
        FieldKind::Password => {
            let str_val = current.as_str().unwrap_or("").to_string();
            let full = full_obj.clone();
            rsx! {
                PasswordField {
                    label,
                    value: str_val,
                    required,
                    oninput: move |new_val: String| {
                        let updated = set_field(&full, key, Value::String(new_val));
                        onchange.call(serde_json::to_string_pretty(&updated).unwrap_or_default());
                    },
                }
            }
        }
        FieldKind::Number => {
            let num_val = current.as_f64().unwrap_or(0.0);
            let full = full_obj.clone();
            rsx! {
                NumberField {
                    label,
                    value: num_val,
                    required,
                    oninput: move |new_val: f64| {
                        let json_num = if new_val == new_val.floor() {
                            json!(new_val as i64)
                        } else {
                            json!(new_val)
                        };
                        let updated = set_field(&full, key, json_num);
                        onchange.call(serde_json::to_string_pretty(&updated).unwrap_or_default());
                    },
                }
            }
        }
        FieldKind::Toggle => {
            let bool_val = current.as_bool().unwrap_or(false);
            let full = full_obj.clone();
            rsx! {
                ToggleField {
                    label,
                    checked: bool_val,
                    onchange: move |new_val: bool| {
                        let updated = set_field(&full, key, Value::Bool(new_val));
                        onchange.call(serde_json::to_string_pretty(&updated).unwrap_or_default());
                    },
                }
            }
        }
        FieldKind::Json => {
            let json_str = match &current {
                Value::Null => String::new(),
                Value::String(s) => s.clone(),
                other => serde_json::to_string_pretty(other).unwrap_or_default(),
            };
            let full = full_obj.clone();
            rsx! {
                JsonField {
                    label,
                    value: json_str,
                    required,
                    rows: 6,
                    oninput: move |new_val: String| {
                        let parsed_inner = serde_json::from_str::<Value>(&new_val)
                            .unwrap_or(Value::String(new_val));
                        let updated = set_field(&full, key, parsed_inner);
                        onchange.call(serde_json::to_string_pretty(&updated).unwrap_or_default());
                    },
                }
            }
        }
        FieldKind::Select(options) => {
            let str_val = current.as_str().unwrap_or("").to_string();
            let full = full_obj.clone();
            rsx! {
                SelectField {
                    label,
                    value: str_val,
                    options,
                    required,
                    onchange: move |new_val: String| {
                        let updated = set_field(&full, key, Value::String(new_val));
                        onchange.call(serde_json::to_string_pretty(&updated).unwrap_or_default());
                    },
                }
            }
        }
        FieldKind::Tags => {
            let tags: Vec<String> = match &current {
                Value::Array(arr) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
                Value::String(s) => s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect(),
                _ => Vec::new(),
            };
            let full = full_obj.clone();
            rsx! {
                TagsField {
                    label,
                    tags,
                    onchange: move |new_tags: Vec<String>| {
                        let arr = Value::Array(new_tags.into_iter().map(Value::String).collect());
                        let updated = set_field(&full, key, arr);
                        onchange.call(serde_json::to_string_pretty(&updated).unwrap_or_default());
                    },
                }
            }
        }
    }
}

fn set_field(obj: &Value, key: &str, value: Value) -> Value {
    let mut map = match obj {
        Value::Object(m) => m.clone(),
        _ => Map::new(),
    };
    map.insert(key.to_string(), value);
    Value::Object(map)
}

// ---------------------------------------------------------------------------
// Field definitions per resource type
// ---------------------------------------------------------------------------

fn fields_for_resource(slug: &str) -> Vec<FieldDef> {
    match slug {
        "organizations" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "website_url", label: "Website URL", kind: FieldKind::Text, required: false },
            FieldDef { key: "favicon", label: "Favicon URL", kind: FieldKind::Text, required: false },
            FieldDef { key: "password_type", label: "Password type", kind: FieldKind::Select(vec![
                SelectOption { value: "plain".into(), label: "Plain".into() },
                SelectOption { value: "salt".into(), label: "Salt".into() },
                SelectOption { value: "md5-salt".into(), label: "MD5-Salt".into() },
                SelectOption { value: "bcrypt".into(), label: "Bcrypt".into() },
                SelectOption { value: "argon2id".into(), label: "Argon2id".into() },
            ]), required: false },
            FieldDef { key: "languages", label: "Languages", kind: FieldKind::Tags, required: false },
            FieldDef { key: "tags", label: "Tags", kind: FieldKind::Tags, required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
        ],
        "applications" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "organization", label: "Organization", kind: FieldKind::Text, required: true },
            FieldDef { key: "logo", label: "Logo URL", kind: FieldKind::Text, required: false },
            FieldDef { key: "homepage_url", label: "Homepage URL", kind: FieldKind::Text, required: false },
            FieldDef { key: "description", label: "Description", kind: FieldKind::TextArea, required: false },
            FieldDef { key: "client_id", label: "Client ID", kind: FieldKind::Text, required: false },
            FieldDef { key: "client_secret", label: "Client secret", kind: FieldKind::Password, required: false },
            FieldDef { key: "redirect_uris", label: "Redirect URIs", kind: FieldKind::Tags, required: false },
            FieldDef { key: "grant_types", label: "Grant types", kind: FieldKind::Tags, required: false },
            FieldDef { key: "token_format", label: "Token format", kind: FieldKind::Select(vec![
                SelectOption { value: "JWT".into(), label: "JWT".into() },
                SelectOption { value: "JWT-Empty".into(), label: "JWT (empty)".into() },
            ]), required: false },
            FieldDef { key: "expire_in_hours", label: "Token expiry (hours)", kind: FieldKind::Number, required: false },
            FieldDef { key: "enable_password", label: "Enable password login", kind: FieldKind::Toggle, required: false },
            FieldDef { key: "enable_sign_up", label: "Enable sign-up", kind: FieldKind::Toggle, required: false },
            FieldDef { key: "enable_code_signin", label: "Enable code sign-in", kind: FieldKind::Toggle, required: false },
            FieldDef { key: "providers", label: "Providers (JSON)", kind: FieldKind::Json, required: false },
        ],
        "users" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Username", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "email", label: "Email", kind: FieldKind::Text, required: false },
            FieldDef { key: "phone", label: "Phone", kind: FieldKind::Text, required: false },
            FieldDef { key: "password", label: "Password", kind: FieldKind::Password, required: true },
            FieldDef { key: "avatar", label: "Avatar URL", kind: FieldKind::Text, required: false },
            FieldDef { key: "bio", label: "Bio", kind: FieldKind::TextArea, required: false },
            FieldDef { key: "type", label: "Type", kind: FieldKind::Select(vec![
                SelectOption { value: "normal-user".into(), label: "Normal user".into() },
                SelectOption { value: "admin".into(), label: "Admin".into() },
            ]), required: false },
            FieldDef { key: "is_admin", label: "Is admin", kind: FieldKind::Toggle, required: false },
            FieldDef { key: "is_forbidden", label: "Is forbidden", kind: FieldKind::Toggle, required: false },
            FieldDef { key: "is_deleted", label: "Is deleted", kind: FieldKind::Toggle, required: false },
            FieldDef { key: "signup_application", label: "Signup application", kind: FieldKind::Text, required: false },
            FieldDef { key: "tags", label: "Tags", kind: FieldKind::Tags, required: false },
            FieldDef { key: "properties", label: "Properties (JSON)", kind: FieldKind::Json, required: false },
        ],
        "groups" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "type", label: "Type", kind: FieldKind::Select(vec![
                SelectOption { value: "virtual".into(), label: "Virtual".into() },
                SelectOption { value: "physical".into(), label: "Physical".into() },
            ]), required: false },
            FieldDef { key: "parent_id", label: "Parent group ID", kind: FieldKind::Text, required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
            FieldDef { key: "users", label: "Users", kind: FieldKind::Tags, required: false },
        ],
        "invitations" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "code", label: "Invitation code", kind: FieldKind::Text, required: true },
            FieldDef { key: "application", label: "Application", kind: FieldKind::Text, required: false },
            FieldDef { key: "quota", label: "Quota", kind: FieldKind::Number, required: false },
            FieldDef { key: "used_count", label: "Used count", kind: FieldKind::Number, required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
        ],
        "roles" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "description", label: "Description", kind: FieldKind::TextArea, required: false },
            FieldDef { key: "users", label: "Users", kind: FieldKind::Tags, required: false },
            FieldDef { key: "roles", label: "Sub-roles", kind: FieldKind::Tags, required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
        ],
        "permissions" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "description", label: "Description", kind: FieldKind::TextArea, required: false },
            FieldDef { key: "resource_type", label: "Resource type", kind: FieldKind::Select(vec![
                SelectOption { value: "API".into(), label: "API".into() },
                SelectOption { value: "UI".into(), label: "UI".into() },
                SelectOption { value: "Menu".into(), label: "Menu".into() },
            ]), required: false },
            FieldDef { key: "resources", label: "Resources", kind: FieldKind::Tags, required: false },
            FieldDef { key: "actions", label: "Actions", kind: FieldKind::Tags, required: false },
            FieldDef { key: "users", label: "Users", kind: FieldKind::Tags, required: false },
            FieldDef { key: "roles", label: "Roles", kind: FieldKind::Tags, required: false },
            FieldDef { key: "effect", label: "Effect", kind: FieldKind::Select(vec![
                SelectOption { value: "Allow".into(), label: "Allow".into() },
                SelectOption { value: "Deny".into(), label: "Deny".into() },
            ]), required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
        ],
        "tokens" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "application", label: "Application", kind: FieldKind::Text, required: true },
            FieldDef { key: "organization", label: "Organization", kind: FieldKind::Text, required: true },
            FieldDef { key: "user", label: "User", kind: FieldKind::Text, required: true },
            FieldDef { key: "token_type", label: "Token type", kind: FieldKind::Select(vec![
                SelectOption { value: "access-token".into(), label: "Access token".into() },
                SelectOption { value: "refresh-token".into(), label: "Refresh token".into() },
                SelectOption { value: "authorization-code".into(), label: "Authorization code".into() },
            ]), required: false },
            FieldDef { key: "code", label: "Code", kind: FieldKind::Text, required: false },
            FieldDef { key: "access_token", label: "Access token", kind: FieldKind::TextArea, required: false },
            FieldDef { key: "refresh_token", label: "Refresh token", kind: FieldKind::Text, required: false },
            FieldDef { key: "scope", label: "Scope", kind: FieldKind::Text, required: false },
            FieldDef { key: "expires_in", label: "Expires in (seconds)", kind: FieldKind::Number, required: false },
        ],
        "sessions" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "application", label: "Application", kind: FieldKind::Text, required: false },
            FieldDef { key: "user_id", label: "User ID", kind: FieldKind::Text, required: true },
            FieldDef { key: "session_id", label: "Session ID", kind: FieldKind::Text, required: true },
        ],
        "models" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "model_text", label: "Model text (Casbin)", kind: FieldKind::TextArea, required: true },
            FieldDef { key: "description", label: "Description", kind: FieldKind::TextArea, required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
        ],
        "adapters" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "adapter_type", label: "Adapter type", kind: FieldKind::Select(vec![
                SelectOption { value: "Database".into(), label: "Database".into() },
                SelectOption { value: "File".into(), label: "File".into() },
                SelectOption { value: "HTTP".into(), label: "HTTP".into() },
            ]), required: true },
            FieldDef { key: "host", label: "Host", kind: FieldKind::Text, required: false },
            FieldDef { key: "port", label: "Port", kind: FieldKind::Number, required: false },
            FieldDef { key: "user", label: "User", kind: FieldKind::Text, required: false },
            FieldDef { key: "password", label: "Password", kind: FieldKind::Password, required: false },
            FieldDef { key: "database_type", label: "Database type", kind: FieldKind::Select(vec![
                SelectOption { value: "postgres".into(), label: "PostgreSQL".into() },
                SelectOption { value: "mysql".into(), label: "MySQL".into() },
                SelectOption { value: "sqlite".into(), label: "SQLite".into() },
            ]), required: false },
            FieldDef { key: "database", label: "Database name", kind: FieldKind::Text, required: false },
        ],
        "enforcers" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "model", label: "Model", kind: FieldKind::Text, required: true },
            FieldDef { key: "adapter", label: "Adapter", kind: FieldKind::Text, required: true },
            FieldDef { key: "description", label: "Description", kind: FieldKind::TextArea, required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
        ],
        "rules" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "rule_type", label: "Rule type", kind: FieldKind::Select(vec![
                SelectOption { value: "User-Agent".into(), label: "User-Agent".into() },
                SelectOption { value: "IP".into(), label: "IP".into() },
                SelectOption { value: "WAF".into(), label: "WAF".into() },
                SelectOption { value: "Compound".into(), label: "Compound".into() },
            ]), required: true },
            FieldDef { key: "expressions", label: "Expressions (JSON)", kind: FieldKind::Json, required: true },
            FieldDef { key: "action", label: "Action", kind: FieldKind::Select(vec![
                SelectOption { value: "Allow".into(), label: "Allow".into() },
                SelectOption { value: "Block".into(), label: "Block".into() },
                SelectOption { value: "Redirect".into(), label: "Redirect".into() },
                SelectOption { value: "Log".into(), label: "Log".into() },
            ]), required: true },
            FieldDef { key: "status_code", label: "Status code", kind: FieldKind::Number, required: false },
            FieldDef { key: "reason", label: "Reason", kind: FieldKind::Text, required: false },
            FieldDef { key: "is_verbose", label: "Verbose", kind: FieldKind::Toggle, required: false },
        ],
        "sites" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "domain", label: "Domain", kind: FieldKind::Text, required: true },
            FieldDef { key: "ssl_mode", label: "SSL mode", kind: FieldKind::Select(vec![
                SelectOption { value: "HTTPS Only".into(), label: "HTTPS Only".into() },
                SelectOption { value: "HTTP Only".into(), label: "HTTP Only".into() },
                SelectOption { value: "Both".into(), label: "Both".into() },
            ]), required: false },
            FieldDef { key: "port", label: "Port", kind: FieldKind::Number, required: false },
            FieldDef { key: "host", label: "Backend host", kind: FieldKind::Text, required: false },
            FieldDef { key: "description", label: "Description", kind: FieldKind::TextArea, required: false },
            FieldDef { key: "rules", label: "Rules (JSON)", kind: FieldKind::Json, required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
        ],
        "providers" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "category", label: "Category", kind: FieldKind::Select(vec![
                SelectOption { value: "OAuth".into(), label: "OAuth".into() },
                SelectOption { value: "Email".into(), label: "Email".into() },
                SelectOption { value: "SMS".into(), label: "SMS".into() },
                SelectOption { value: "Payment".into(), label: "Payment".into() },
                SelectOption { value: "Storage".into(), label: "Storage".into() },
                SelectOption { value: "Captcha".into(), label: "Captcha".into() },
                SelectOption { value: "Notification".into(), label: "Notification".into() },
            ]), required: true },
            FieldDef { key: "type", label: "Type", kind: FieldKind::Select(vec![
                SelectOption { value: "GitHub".into(), label: "GitHub".into() },
                SelectOption { value: "Google".into(), label: "Google".into() },
                SelectOption { value: "Facebook".into(), label: "Facebook".into() },
                SelectOption { value: "Twitter".into(), label: "Twitter".into() },
                SelectOption { value: "LinkedIn".into(), label: "LinkedIn".into() },
                SelectOption { value: "WeChat".into(), label: "WeChat".into() },
                SelectOption { value: "SMTP".into(), label: "SMTP".into() },
                SelectOption { value: "Twilio".into(), label: "Twilio".into() },
                SelectOption { value: "Stripe".into(), label: "Stripe".into() },
                SelectOption { value: "PayPal".into(), label: "PayPal".into() },
                SelectOption { value: "AWS S3".into(), label: "AWS S3".into() },
                SelectOption { value: "reCAPTCHA".into(), label: "reCAPTCHA".into() },
                SelectOption { value: "hCaptcha".into(), label: "hCaptcha".into() },
                SelectOption { value: "Custom".into(), label: "Custom".into() },
            ]), required: true },
            FieldDef { key: "client_id", label: "Client ID / API key", kind: FieldKind::Text, required: false },
            FieldDef { key: "client_secret", label: "Client secret", kind: FieldKind::Password, required: false },
            FieldDef { key: "host", label: "Host / Endpoint", kind: FieldKind::Text, required: false },
            FieldDef { key: "port", label: "Port", kind: FieldKind::Number, required: false },
            FieldDef { key: "domain", label: "Domain", kind: FieldKind::Text, required: false },
            FieldDef { key: "metadata", label: "Metadata (JSON)", kind: FieldKind::Json, required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
        ],
        "certs" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "scope", label: "Scope", kind: FieldKind::Select(vec![
                SelectOption { value: "JWT".into(), label: "JWT".into() },
                SelectOption { value: "SAML".into(), label: "SAML".into() },
            ]), required: true },
            FieldDef { key: "type", label: "Type", kind: FieldKind::Select(vec![
                SelectOption { value: "x509".into(), label: "X.509".into() },
            ]), required: false },
            FieldDef { key: "crypto_algorithm", label: "Algorithm", kind: FieldKind::Select(vec![
                SelectOption { value: "RS256".into(), label: "RS256".into() },
                SelectOption { value: "RS384".into(), label: "RS384".into() },
                SelectOption { value: "RS512".into(), label: "RS512".into() },
                SelectOption { value: "ES256".into(), label: "ES256".into() },
                SelectOption { value: "ES384".into(), label: "ES384".into() },
                SelectOption { value: "ES512".into(), label: "ES512".into() },
            ]), required: false },
            FieldDef { key: "bit_size", label: "Bit size", kind: FieldKind::Number, required: false },
            FieldDef { key: "expire_in_years", label: "Expiry (years)", kind: FieldKind::Number, required: false },
            FieldDef { key: "certificate", label: "Certificate (PEM)", kind: FieldKind::TextArea, required: false },
            FieldDef { key: "private_key", label: "Private key (PEM)", kind: FieldKind::TextArea, required: false },
        ],
        "resources" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "user_id", label: "User ID", kind: FieldKind::Text, required: false },
            FieldDef { key: "file_name", label: "File name", kind: FieldKind::Text, required: false },
            FieldDef { key: "file_type", label: "File type", kind: FieldKind::Text, required: false },
            FieldDef { key: "file_size", label: "File size (bytes)", kind: FieldKind::Number, required: false },
            FieldDef { key: "url", label: "URL", kind: FieldKind::Text, required: false },
            FieldDef { key: "description", label: "Description", kind: FieldKind::TextArea, required: false },
        ],
        "webhooks" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "organization", label: "Organization", kind: FieldKind::Text, required: true },
            FieldDef { key: "url", label: "URL", kind: FieldKind::Text, required: true },
            FieldDef { key: "content_type", label: "Content type", kind: FieldKind::Select(vec![
                SelectOption { value: "application/json".into(), label: "JSON".into() },
                SelectOption { value: "application/x-www-form-urlencoded".into(), label: "Form".into() },
            ]), required: false },
            FieldDef { key: "events", label: "Events", kind: FieldKind::Tags, required: false },
            FieldDef { key: "headers", label: "Headers (JSON)", kind: FieldKind::Json, required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
        ],
        "syncers" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "organization", label: "Organization", kind: FieldKind::Text, required: true },
            FieldDef { key: "type", label: "Type", kind: FieldKind::Select(vec![
                SelectOption { value: "Database".into(), label: "Database".into() },
                SelectOption { value: "LDAP".into(), label: "LDAP".into() },
                SelectOption { value: "Keycloak".into(), label: "Keycloak".into() },
            ]), required: true },
            FieldDef { key: "host", label: "Host", kind: FieldKind::Text, required: false },
            FieldDef { key: "port", label: "Port", kind: FieldKind::Number, required: false },
            FieldDef { key: "user_name", label: "Username", kind: FieldKind::Text, required: false },
            FieldDef { key: "password", label: "Password", kind: FieldKind::Password, required: false },
            FieldDef { key: "database", label: "Database", kind: FieldKind::Text, required: false },
            FieldDef { key: "table", label: "Table", kind: FieldKind::Text, required: false },
            FieldDef { key: "sync_interval", label: "Sync interval (minutes)", kind: FieldKind::Number, required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
        ],
        "records" => vec![
            // Records are mostly read-only audit entries
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: false },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: false },
            FieldDef { key: "organization", label: "Organization", kind: FieldKind::Text, required: false },
            FieldDef { key: "client_ip", label: "Client IP", kind: FieldKind::Text, required: false },
            FieldDef { key: "user", label: "User", kind: FieldKind::Text, required: false },
            FieldDef { key: "method", label: "Method", kind: FieldKind::Text, required: false },
            FieldDef { key: "request_uri", label: "Request URI", kind: FieldKind::Text, required: false },
            FieldDef { key: "action", label: "Action", kind: FieldKind::Text, required: false },
            FieldDef { key: "is_triggered", label: "Triggered", kind: FieldKind::Toggle, required: false },
        ],
        "forms" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "form_items", label: "Form items (JSON)", kind: FieldKind::Json, required: true },
        ],
        "tickets" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "subject", label: "Subject", kind: FieldKind::Text, required: true },
            FieldDef { key: "body", label: "Body", kind: FieldKind::TextArea, required: false },
            FieldDef { key: "status", label: "Status", kind: FieldKind::Select(vec![
                SelectOption { value: "Open".into(), label: "Open".into() },
                SelectOption { value: "In Progress".into(), label: "In Progress".into() },
                SelectOption { value: "Closed".into(), label: "Closed".into() },
            ]), required: false },
        ],
        "orders" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "product_name", label: "Product", kind: FieldKind::Text, required: true },
            FieldDef { key: "user", label: "User", kind: FieldKind::Text, required: true },
            FieldDef { key: "quantity", label: "Quantity", kind: FieldKind::Number, required: false },
            FieldDef { key: "price", label: "Price", kind: FieldKind::Number, required: false },
            FieldDef { key: "currency", label: "Currency", kind: FieldKind::Text, required: false },
            FieldDef { key: "status", label: "Status", kind: FieldKind::Select(vec![
                SelectOption { value: "Created".into(), label: "Created".into() },
                SelectOption { value: "Paid".into(), label: "Paid".into() },
                SelectOption { value: "Cancelled".into(), label: "Cancelled".into() },
            ]), required: false },
        ],
        "products" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "description", label: "Description", kind: FieldKind::TextArea, required: false },
            FieldDef { key: "image", label: "Image URL", kind: FieldKind::Text, required: false },
            FieldDef { key: "tag", label: "Tag", kind: FieldKind::Text, required: false },
            FieldDef { key: "quantity", label: "Quantity", kind: FieldKind::Number, required: false },
            FieldDef { key: "price", label: "Price", kind: FieldKind::Number, required: false },
            FieldDef { key: "currency", label: "Currency", kind: FieldKind::Text, required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
        ],
        "plans" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "product", label: "Product", kind: FieldKind::Text, required: true },
            FieldDef { key: "description", label: "Description", kind: FieldKind::TextArea, required: false },
            FieldDef { key: "period", label: "Period", kind: FieldKind::Select(vec![
                SelectOption { value: "Monthly".into(), label: "Monthly".into() },
                SelectOption { value: "Yearly".into(), label: "Yearly".into() },
                SelectOption { value: "Weekly".into(), label: "Weekly".into() },
            ]), required: false },
            FieldDef { key: "price", label: "Price", kind: FieldKind::Number, required: false },
            FieldDef { key: "currency", label: "Currency", kind: FieldKind::Text, required: false },
            FieldDef { key: "is_enabled", label: "Enabled", kind: FieldKind::Toggle, required: false },
        ],
        "pricings" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "plan", label: "Plan", kind: FieldKind::Text, required: true },
            FieldDef { key: "currency", label: "Currency", kind: FieldKind::Text, required: true },
            FieldDef { key: "price", label: "Price", kind: FieldKind::Number, required: true },
            FieldDef { key: "description", label: "Description", kind: FieldKind::TextArea, required: false },
        ],
        "subscriptions" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "plan", label: "Plan", kind: FieldKind::Text, required: true },
            FieldDef { key: "user", label: "User", kind: FieldKind::Text, required: true },
            FieldDef { key: "start_date", label: "Start date", kind: FieldKind::Text, required: false },
            FieldDef { key: "end_date", label: "End date", kind: FieldKind::Text, required: false },
            FieldDef { key: "status", label: "Status", kind: FieldKind::Select(vec![
                SelectOption { value: "Active".into(), label: "Active".into() },
                SelectOption { value: "Cancelled".into(), label: "Cancelled".into() },
                SelectOption { value: "Expired".into(), label: "Expired".into() },
                SelectOption { value: "Pending".into(), label: "Pending".into() },
            ]), required: false },
        ],
        "payments" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "organization", label: "Organization", kind: FieldKind::Text, required: true },
            FieldDef { key: "provider", label: "Provider", kind: FieldKind::Text, required: true },
            FieldDef { key: "type", label: "Type", kind: FieldKind::Select(vec![
                SelectOption { value: "PayPal".into(), label: "PayPal".into() },
                SelectOption { value: "Stripe".into(), label: "Stripe".into() },
                SelectOption { value: "Alipay".into(), label: "Alipay".into() },
                SelectOption { value: "WeChat Pay".into(), label: "WeChat Pay".into() },
            ]), required: false },
            FieldDef { key: "amount", label: "Amount", kind: FieldKind::Number, required: false },
            FieldDef { key: "currency", label: "Currency", kind: FieldKind::Text, required: false },
            FieldDef { key: "return_url", label: "Return URL", kind: FieldKind::Text, required: false },
            FieldDef { key: "status", label: "Status", kind: FieldKind::Select(vec![
                SelectOption { value: "Created".into(), label: "Created".into() },
                SelectOption { value: "Paid".into(), label: "Paid".into() },
                SelectOption { value: "Failed".into(), label: "Failed".into() },
            ]), required: false },
        ],
        "transactions" => vec![
            FieldDef { key: "owner", label: "Owner", kind: FieldKind::Text, required: true },
            FieldDef { key: "name", label: "Name", kind: FieldKind::Text, required: true },
            FieldDef { key: "display_name", label: "Display name", kind: FieldKind::Text, required: false },
            FieldDef { key: "provider", label: "Provider", kind: FieldKind::Text, required: false },
            FieldDef { key: "user", label: "User", kind: FieldKind::Text, required: false },
            FieldDef { key: "amount", label: "Amount", kind: FieldKind::Number, required: false },
            FieldDef { key: "currency", label: "Currency", kind: FieldKind::Text, required: false },
            FieldDef { key: "product_name", label: "Product", kind: FieldKind::Text, required: false },
            FieldDef { key: "detail", label: "Detail", kind: FieldKind::TextArea, required: false },
        ],
        _ => Vec::new(),
    }
}
