use crate::{resources::ResourceConfig, ui::*};
use glory::prelude::*;
use serde_json::{Value, json};
#[derive(Clone)]
struct SelectOption {
    value: String,
    label: String,
}
#[derive(Clone)]
pub struct FieldDef {
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

fn update(editor: Cage<String>, key: &str, value: Value, message: Cage<String>) {
    match serde_json::from_str::<Value>(&editor.get()) {
        Ok(Value::Object(mut data)) => {
            data.insert(key.to_string(), value);
            editor.set(crate::api::pretty_json(&Value::Object(data)));
            message.set(String::new());
        }
        _ => message.set("The resource must be a JSON object.".into()),
    }
}
fn read(editor: Cage<String>, key: &str) -> Value {
    serde_json::from_str::<Value>(&editor.get()).unwrap_or(Value::Null)[key].clone()
}
pub fn form(config: ResourceConfig, editor: Cage<String>, message: Cage<String>) -> Element {
    boxed(widget(move |scope| {
        let raw = scope.cage(false);
        let mut widgets: Vec<Element> = Vec::new();
        for field in fields_for_resource(config.slug) {
            let key = field.key;
            let name = field.label;
            let control: Element = match field.kind {
                FieldKind::Toggle => boxed(
                    sapid::checkbox()
                        .label(name)
                        .checked(scope.bond(move || read(editor, key).as_bool().unwrap_or(false)))
                        .on_checked_change(move |v| update(editor, key, json!(v), message)),
                ),
                FieldKind::Select(options) => {
                    // Semantic option keys are ASCII tokens. API values can
                    // contain spaces or other characters, so retain them separately.
                    let values: Vec<String> = options.iter().map(|option| option.value.clone()).collect();
                    let selected_values = values.clone();
                    boxed(
                        sapid::native_select(key)
                            .name(name)
                            .value(scope.bond(move || {
                                let current = read(editor, key);
                                selected_values
                                    .iter()
                                    .position(|value| current.as_str() == Some(value.as_str()))
                                    .map(|index| index.to_string())
                            }))
                            .options(
                                options
                                    .into_iter()
                                    .enumerate()
                                    .map(|(index, option)| sapid::select_option(index.to_string(), option.label)),
                            )
                            .on_value_change(move |selected| {
                                let value = selected
                                    .and_then(|key| key.parse::<usize>().ok())
                                    .and_then(|index| values.get(index))
                                    .cloned()
                                    .unwrap_or_default();
                                update(editor, key, json!(value), message);
                            }),
                    )
                }
                kind => {
                    let draft = scope.cage(String::new());
                    let is_json = matches!(kind, FieldKind::Json);
                    let is_number = matches!(kind, FieldKind::Number);
                    let is_tags = matches!(kind, FieldKind::Tags);
                    scope.effect(move || {
                        let value = read(editor, key);
                        draft.set(if is_json {
                            crate::api::pretty_json(&value)
                        } else if is_tags {
                            value
                                .as_array()
                                .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                                .unwrap_or_default()
                        } else {
                            value.as_str().map(str::to_string).unwrap_or_else(|| {
                                if value.is_null() {
                                    String::new()
                                } else {
                                    value.to_string()
                                }
                            })
                        });
                    });
                    let change = move |next: String| {
                        draft.set(next.clone());
                        let parsed = if is_json {
                            serde_json::from_str(&next).map_err(|e| e.to_string())
                        } else if is_number {
                            next.parse::<serde_json::Number>()
                                .map(Value::Number)
                                .map_err(|_| "Enter a finite number".to_string())
                        } else if is_tags {
                            Ok(json!(next.split(',').map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>()))
                        } else {
                            Ok(json!(next))
                        };
                        match parsed {
                            Ok(value) => update(editor, key, value, message),
                            Err(error) => message.set(format!("{name}: {error}")),
                        }
                    };
                    if matches!(kind, FieldKind::Json | FieldKind::TextArea) {
                        boxed(sapid::textarea().name(name).value(draft).on_value_change(change).rows(5))
                    } else if matches!(kind, FieldKind::Password) {
                        boxed(sapid::password_input().name(name).value(draft).on_value_change(change))
                    } else {
                        boxed(
                            sapid::text_field()
                                .name(name)
                                .value(draft)
                                .required(field.required)
                                .on_value_change(change),
                        )
                    }
                }
            };
            widgets.push(boxed(stack((label(name), control))));
        }
        let structured = stack(widgets);
        stack((
            sapid::button().label("Switch structured / JSON editor").on_press(move || raw.set(!raw.get())),
            // Both editors keep their identities, including selection and draft state.
            glory::ui::view()
                .class_fn(move || {
                    if raw.get() {
                        "hidden"
                    } else {
                        "structured-editor"
                    }
                    .into()
                })
                .fill(structured),
            glory::ui::view()
                .class_fn(move || {
                    if raw.get() {
                        "json-editor"
                    } else {
                        "hidden"
                    }
                    .into()
                })
                .fill(
                    sapid::textarea()
                        .name("Resource JSON")
                        .value(editor)
                        .on_value_change(move |value| editor.set(value))
                        .rows(18),
                ),
        ))
        .build(scope)
    }))
}
fn fields_for_resource(slug: &str) -> Vec<FieldDef> {
    match slug {
        "organizations" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "website_url",
                label: "Website URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "favicon",
                label: "Favicon URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "password_type",
                label: "Password type",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "plain".into(),
                        label: "Plain".into(),
                    },
                    SelectOption {
                        value: "salt".into(),
                        label: "Salt".into(),
                    },
                    SelectOption {
                        value: "md5-salt".into(),
                        label: "MD5-Salt".into(),
                    },
                    SelectOption {
                        value: "bcrypt".into(),
                        label: "Bcrypt".into(),
                    },
                    SelectOption {
                        value: "argon2id".into(),
                        label: "Argon2id".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "languages",
                label: "Languages",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "tags",
                label: "Tags",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "applications" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "organization",
                label: "Organization",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "logo",
                label: "Logo URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "homepage_url",
                label: "Homepage URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "description",
                label: "Description",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "client_id",
                label: "Client ID",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "client_secret",
                label: "Client secret",
                kind: FieldKind::Password,
                required: false,
            },
            FieldDef {
                key: "redirect_uris",
                label: "Redirect URIs",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "grant_types",
                label: "Grant types",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "token_format",
                label: "Token format",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "JWT".into(),
                        label: "JWT".into(),
                    },
                    SelectOption {
                        value: "JWT-Empty".into(),
                        label: "JWT (empty)".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "expire_in_hours",
                label: "Token expiry (hours)",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "enable_password",
                label: "Enable password login",
                kind: FieldKind::Toggle,
                required: false,
            },
            FieldDef {
                key: "enable_sign_up",
                label: "Enable sign-up",
                kind: FieldKind::Toggle,
                required: false,
            },
            FieldDef {
                key: "enable_code_signin",
                label: "Enable code sign-in",
                kind: FieldKind::Toggle,
                required: false,
            },
            FieldDef {
                key: "providers",
                label: "Providers (JSON)",
                kind: FieldKind::Json,
                required: false,
            },
        ],
        "users" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Username",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "email",
                label: "Email",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "phone",
                label: "Phone",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "password",
                label: "Password",
                kind: FieldKind::Password,
                required: true,
            },
            FieldDef {
                key: "avatar",
                label: "Avatar URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "bio",
                label: "Bio",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "type",
                label: "Type",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "normal-user".into(),
                        label: "Normal user".into(),
                    },
                    SelectOption {
                        value: "admin".into(),
                        label: "Admin".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "is_admin",
                label: "Is admin",
                kind: FieldKind::Toggle,
                required: false,
            },
            FieldDef {
                key: "is_forbidden",
                label: "Is forbidden",
                kind: FieldKind::Toggle,
                required: false,
            },
            FieldDef {
                key: "is_deleted",
                label: "Is deleted",
                kind: FieldKind::Toggle,
                required: false,
            },
            FieldDef {
                key: "signup_application",
                label: "Signup application",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "tags",
                label: "Tags",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "properties",
                label: "Properties (JSON)",
                kind: FieldKind::Json,
                required: false,
            },
        ],
        "groups" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "type",
                label: "Type",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "virtual".into(),
                        label: "Virtual".into(),
                    },
                    SelectOption {
                        value: "physical".into(),
                        label: "Physical".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "parent_id",
                label: "Parent group ID",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
            FieldDef {
                key: "users",
                label: "Users",
                kind: FieldKind::Tags,
                required: false,
            },
        ],
        "invitations" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "code",
                label: "Invitation code",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "application",
                label: "Application",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "quota",
                label: "Quota",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "used_count",
                label: "Used count",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "roles" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "description",
                label: "Description",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "users",
                label: "Users",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "roles",
                label: "Sub-roles",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "permissions" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "description",
                label: "Description",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "resource_type",
                label: "Resource type",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "API".into(),
                        label: "API".into(),
                    },
                    SelectOption {
                        value: "UI".into(),
                        label: "UI".into(),
                    },
                    SelectOption {
                        value: "Menu".into(),
                        label: "Menu".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "resources",
                label: "Resources",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "actions",
                label: "Actions",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "users",
                label: "Users",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "roles",
                label: "Roles",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "effect",
                label: "Effect",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "Allow".into(),
                        label: "Allow".into(),
                    },
                    SelectOption {
                        value: "Deny".into(),
                        label: "Deny".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "tokens" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "application",
                label: "Application",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "organization",
                label: "Organization",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "user",
                label: "User",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "token_type",
                label: "Token type",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "access-token".into(),
                        label: "Access token".into(),
                    },
                    SelectOption {
                        value: "refresh-token".into(),
                        label: "Refresh token".into(),
                    },
                    SelectOption {
                        value: "authorization-code".into(),
                        label: "Authorization code".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "code",
                label: "Code",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "access_token",
                label: "Access token",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "refresh_token",
                label: "Refresh token",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "scope",
                label: "Scope",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "expires_in",
                label: "Expires in (seconds)",
                kind: FieldKind::Number,
                required: false,
            },
        ],
        "sessions" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "application",
                label: "Application",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "user_id",
                label: "User ID",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "session_id",
                label: "Session ID",
                kind: FieldKind::Text,
                required: true,
            },
        ],
        "models" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "model_text",
                label: "Model text (Casbin)",
                kind: FieldKind::TextArea,
                required: true,
            },
            FieldDef {
                key: "description",
                label: "Description",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "adapters" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "adapter_type",
                label: "Adapter type",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "Database".into(),
                        label: "Database".into(),
                    },
                    SelectOption {
                        value: "File".into(),
                        label: "File".into(),
                    },
                    SelectOption {
                        value: "HTTP".into(),
                        label: "HTTP".into(),
                    },
                ]),
                required: true,
            },
            FieldDef {
                key: "host",
                label: "Host",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "port",
                label: "Port",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "user",
                label: "User",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "password",
                label: "Password",
                kind: FieldKind::Password,
                required: false,
            },
            FieldDef {
                key: "database_type",
                label: "Database type",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "postgres".into(),
                        label: "PostgreSQL".into(),
                    },
                    SelectOption {
                        value: "mysql".into(),
                        label: "MySQL".into(),
                    },
                    SelectOption {
                        value: "sqlite".into(),
                        label: "SQLite".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "database",
                label: "Database name",
                kind: FieldKind::Text,
                required: false,
            },
        ],
        "enforcers" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "model",
                label: "Model",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "adapter",
                label: "Adapter",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "description",
                label: "Description",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "rules" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "rule_type",
                label: "Rule type",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "User-Agent".into(),
                        label: "User-Agent".into(),
                    },
                    SelectOption {
                        value: "IP".into(),
                        label: "IP".into(),
                    },
                    SelectOption {
                        value: "WAF".into(),
                        label: "WAF".into(),
                    },
                    SelectOption {
                        value: "Compound".into(),
                        label: "Compound".into(),
                    },
                ]),
                required: true,
            },
            FieldDef {
                key: "expressions",
                label: "Expressions (JSON)",
                kind: FieldKind::Json,
                required: true,
            },
            FieldDef {
                key: "action",
                label: "Action",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "Allow".into(),
                        label: "Allow".into(),
                    },
                    SelectOption {
                        value: "Block".into(),
                        label: "Block".into(),
                    },
                    SelectOption {
                        value: "Redirect".into(),
                        label: "Redirect".into(),
                    },
                    SelectOption {
                        value: "Log".into(),
                        label: "Log".into(),
                    },
                ]),
                required: true,
            },
            FieldDef {
                key: "status_code",
                label: "Status code",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "reason",
                label: "Reason",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "is_verbose",
                label: "Verbose",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "sites" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "domain",
                label: "Domain",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "ssl_mode",
                label: "SSL mode",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "HTTPS Only".into(),
                        label: "HTTPS Only".into(),
                    },
                    SelectOption {
                        value: "HTTP Only".into(),
                        label: "HTTP Only".into(),
                    },
                    SelectOption {
                        value: "Both".into(),
                        label: "Both".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "port",
                label: "Port",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "host",
                label: "Backend host",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "description",
                label: "Description",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "rules",
                label: "Rules (JSON)",
                kind: FieldKind::Json,
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "providers" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "category",
                label: "Category",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "OAuth".into(),
                        label: "OAuth".into(),
                    },
                    SelectOption {
                        value: "Email".into(),
                        label: "Email".into(),
                    },
                    SelectOption {
                        value: "SMS".into(),
                        label: "SMS".into(),
                    },
                    SelectOption {
                        value: "Payment".into(),
                        label: "Payment".into(),
                    },
                    SelectOption {
                        value: "Storage".into(),
                        label: "Storage".into(),
                    },
                    SelectOption {
                        value: "Captcha".into(),
                        label: "Captcha".into(),
                    },
                    SelectOption {
                        value: "Notification".into(),
                        label: "Notification".into(),
                    },
                ]),
                required: true,
            },
            FieldDef {
                key: "type",
                label: "Type",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "GitHub".into(),
                        label: "GitHub".into(),
                    },
                    SelectOption {
                        value: "Google".into(),
                        label: "Google".into(),
                    },
                    SelectOption {
                        value: "Facebook".into(),
                        label: "Facebook".into(),
                    },
                    SelectOption {
                        value: "Twitter".into(),
                        label: "Twitter".into(),
                    },
                    SelectOption {
                        value: "LinkedIn".into(),
                        label: "LinkedIn".into(),
                    },
                    SelectOption {
                        value: "WeChat".into(),
                        label: "WeChat".into(),
                    },
                    SelectOption {
                        value: "SMTP".into(),
                        label: "SMTP".into(),
                    },
                    SelectOption {
                        value: "Twilio".into(),
                        label: "Twilio".into(),
                    },
                    SelectOption {
                        value: "Stripe".into(),
                        label: "Stripe".into(),
                    },
                    SelectOption {
                        value: "PayPal".into(),
                        label: "PayPal".into(),
                    },
                    SelectOption {
                        value: "AWS S3".into(),
                        label: "AWS S3".into(),
                    },
                    SelectOption {
                        value: "reCAPTCHA".into(),
                        label: "reCAPTCHA".into(),
                    },
                    SelectOption {
                        value: "hCaptcha".into(),
                        label: "hCaptcha".into(),
                    },
                    SelectOption {
                        value: "Custom".into(),
                        label: "Custom".into(),
                    },
                ]),
                required: true,
            },
            FieldDef {
                key: "client_id",
                label: "Client ID / API key",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "client_secret",
                label: "Client secret",
                kind: FieldKind::Password,
                required: false,
            },
            FieldDef {
                key: "host",
                label: "Host / Endpoint",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "port",
                label: "Port",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "domain",
                label: "Domain",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "metadata",
                label: "Metadata (JSON)",
                kind: FieldKind::Json,
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "certs" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "scope",
                label: "Scope",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "JWT".into(),
                        label: "JWT".into(),
                    },
                    SelectOption {
                        value: "SAML".into(),
                        label: "SAML".into(),
                    },
                ]),
                required: true,
            },
            FieldDef {
                key: "type",
                label: "Type",
                kind: FieldKind::Select(vec![SelectOption {
                    value: "x509".into(),
                    label: "X.509".into(),
                }]),
                required: false,
            },
            FieldDef {
                key: "crypto_algorithm",
                label: "Algorithm",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "RS256".into(),
                        label: "RS256".into(),
                    },
                    SelectOption {
                        value: "RS384".into(),
                        label: "RS384".into(),
                    },
                    SelectOption {
                        value: "RS512".into(),
                        label: "RS512".into(),
                    },
                    SelectOption {
                        value: "ES256".into(),
                        label: "ES256".into(),
                    },
                    SelectOption {
                        value: "ES384".into(),
                        label: "ES384".into(),
                    },
                    SelectOption {
                        value: "ES512".into(),
                        label: "ES512".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "bit_size",
                label: "Bit size",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "expire_in_years",
                label: "Expiry (years)",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "certificate",
                label: "Certificate (PEM)",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "private_key",
                label: "Private key (PEM)",
                kind: FieldKind::TextArea,
                required: false,
            },
        ],
        "resources" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "user_id",
                label: "User ID",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "file_name",
                label: "File name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "file_type",
                label: "File type",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "file_size",
                label: "File size (bytes)",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "url",
                label: "URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "description",
                label: "Description",
                kind: FieldKind::TextArea,
                required: false,
            },
        ],
        "webhooks" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "organization",
                label: "Organization",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "url",
                label: "URL",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "content_type",
                label: "Content type",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "application/json".into(),
                        label: "JSON".into(),
                    },
                    SelectOption {
                        value: "application/x-www-form-urlencoded".into(),
                        label: "Form".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "events",
                label: "Events",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "headers",
                label: "Headers (JSON)",
                kind: FieldKind::Json,
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "syncers" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "organization",
                label: "Organization",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "type",
                label: "Type",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "Database".into(),
                        label: "Database".into(),
                    },
                    SelectOption {
                        value: "LDAP".into(),
                        label: "LDAP".into(),
                    },
                    SelectOption {
                        value: "Keycloak".into(),
                        label: "Keycloak".into(),
                    },
                ]),
                required: true,
            },
            FieldDef {
                key: "host",
                label: "Host",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "port",
                label: "Port",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "user_name",
                label: "Username",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "password",
                label: "Password",
                kind: FieldKind::Password,
                required: false,
            },
            FieldDef {
                key: "database",
                label: "Database",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "table",
                label: "Table",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "sync_interval",
                label: "Sync interval (minutes)",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "records" => vec![
            // Records are mostly read-only audit entries
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "organization",
                label: "Organization",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "client_ip",
                label: "Client IP",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "user",
                label: "User",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "method",
                label: "Method",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "request_uri",
                label: "Request URI",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "action",
                label: "Action",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "is_triggered",
                label: "Triggered",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "forms" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "form_items",
                label: "Form items (JSON)",
                kind: FieldKind::Json,
                required: true,
            },
        ],
        "tickets" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "subject",
                label: "Subject",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "body",
                label: "Body",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "status",
                label: "Status",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "Open".into(),
                        label: "Open".into(),
                    },
                    SelectOption {
                        value: "In Progress".into(),
                        label: "In Progress".into(),
                    },
                    SelectOption {
                        value: "Closed".into(),
                        label: "Closed".into(),
                    },
                ]),
                required: false,
            },
        ],
        "orders" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "product_name",
                label: "Product",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "user",
                label: "User",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "quantity",
                label: "Quantity",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "price",
                label: "Price",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "currency",
                label: "Currency",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "status",
                label: "Status",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "Created".into(),
                        label: "Created".into(),
                    },
                    SelectOption {
                        value: "Paid".into(),
                        label: "Paid".into(),
                    },
                    SelectOption {
                        value: "Cancelled".into(),
                        label: "Cancelled".into(),
                    },
                ]),
                required: false,
            },
        ],
        "products" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "description",
                label: "Description",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "image",
                label: "Image URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "tag",
                label: "Tag",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "quantity",
                label: "Quantity",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "price",
                label: "Price",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "currency",
                label: "Currency",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "plans" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "product",
                label: "Product",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "description",
                label: "Description",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "period",
                label: "Period",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "Monthly".into(),
                        label: "Monthly".into(),
                    },
                    SelectOption {
                        value: "Yearly".into(),
                        label: "Yearly".into(),
                    },
                    SelectOption {
                        value: "Weekly".into(),
                        label: "Weekly".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "price",
                label: "Price",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "currency",
                label: "Currency",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "is_enabled",
                label: "Enabled",
                kind: FieldKind::Toggle,
                required: false,
            },
        ],
        "pricings" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "plan",
                label: "Plan",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "currency",
                label: "Currency",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "price",
                label: "Price",
                kind: FieldKind::Number,
                required: true,
            },
            FieldDef {
                key: "description",
                label: "Description",
                kind: FieldKind::TextArea,
                required: false,
            },
        ],
        "subscriptions" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "plan",
                label: "Plan",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "user",
                label: "User",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "start_date",
                label: "Start date",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "end_date",
                label: "End date",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "status",
                label: "Status",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "Active".into(),
                        label: "Active".into(),
                    },
                    SelectOption {
                        value: "Cancelled".into(),
                        label: "Cancelled".into(),
                    },
                    SelectOption {
                        value: "Expired".into(),
                        label: "Expired".into(),
                    },
                    SelectOption {
                        value: "Pending".into(),
                        label: "Pending".into(),
                    },
                ]),
                required: false,
            },
        ],
        "payments" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "organization",
                label: "Organization",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "provider",
                label: "Provider",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "type",
                label: "Type",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "PayPal".into(),
                        label: "PayPal".into(),
                    },
                    SelectOption {
                        value: "Stripe".into(),
                        label: "Stripe".into(),
                    },
                    SelectOption {
                        value: "Alipay".into(),
                        label: "Alipay".into(),
                    },
                    SelectOption {
                        value: "WeChat Pay".into(),
                        label: "WeChat Pay".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "amount",
                label: "Amount",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "currency",
                label: "Currency",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "return_url",
                label: "Return URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "status",
                label: "Status",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "Created".into(),
                        label: "Created".into(),
                    },
                    SelectOption {
                        value: "Paid".into(),
                        label: "Paid".into(),
                    },
                    SelectOption {
                        value: "Failed".into(),
                        label: "Failed".into(),
                    },
                ]),
                required: false,
            },
        ],
        "transactions" => vec![
            FieldDef {
                key: "owner",
                label: "Owner",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "name",
                label: "Name",
                kind: FieldKind::Text,
                required: true,
            },
            FieldDef {
                key: "display_name",
                label: "Display name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "provider",
                label: "Provider",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "user",
                label: "User",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "amount",
                label: "Amount",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "currency",
                label: "Currency",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "product_name",
                label: "Product",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "detail",
                label: "Detail",
                kind: FieldKind::TextArea,
                required: false,
            },
        ],
        _ => Vec::new(),
    }
}
