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
    SecondaryCredential,
    ProviderContent,
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
fn cloud_directory(editor: Cage<String>) -> bool {
    matches!(
        read(editor, "type").as_str(),
        Some("Azure AD" | "Google Workspace")
    )
}
fn cloud_label(editor: Cage<String>, key: &str) -> Option<&'static str> {
    match (read(editor, "type").as_str(), key) {
        (Some("Azure AD"), "host") => Some("Azure tenant ID / domain"),
        (Some("Azure AD"), "user") => Some("Azure client ID"),
        (Some("Azure AD"), "password") => Some("Azure client secret"),
        (Some("Google Workspace"), "host") => Some("Delegated administrator email"),
        (Some("Google Workspace"), "user") => Some("Service account email"),
        (Some("Google Workspace"), "password") => Some("Service account JSON"),
        (Some("Azure AD" | "Google Workspace"), "database") => {
            Some("Cloud transport options (JSON)")
        }
        _ => None,
    }
}
fn custom_delivery(editor: Cage<String>) -> bool {
    let kind = read(editor, "type")
        .as_str()
        .unwrap_or("")
        .to_ascii_lowercase()
        .replace([' ', '-', '_'], "");
    matches!(
        read(editor, "category").as_str(),
        Some("Email" | "Notification")
    ) && kind.starts_with("customhttp")
        || read(editor, "category") == "SMS"
            && matches!(
                kind.as_str(),
                "http" | "customhttp" | "customhttpsms" | "generic"
            )
}
pub fn supports_network_approval(value: &Value) -> bool {
    let kind = value["type"]
        .as_str()
        .unwrap_or("")
        .to_ascii_lowercase()
        .replace([' ', '-', '_'], "");
    match value["category"].as_str() {
        Some("OAuth") => matches!(kind.as_str(), "custom" | "oidc" | "okta" | "genericoauth"),
        Some("Email" | "Notification") => kind.starts_with("customhttp"),
        Some("SMS") => {
            kind != "twilio"
                && ["endpoint", "provider_url"]
                    .iter()
                    .any(|key| value[*key].as_str().is_some_and(|v| !v.is_empty()))
        }
        _ => false,
    }
}
fn provider_field_visible(editor: Cage<String>, key: &str) -> bool {
    let category = read(editor, "category");
    let category = category.as_str().unwrap_or("");
    match key {
        "custom_auth_url" | "custom_token_url" | "custom_user_info_url" | "custom_logo" => {
            category == "OAuth"
        }
        "user_mapping" => {
            category == "OAuth" || custom_delivery(editor) && matches!(category, "Email" | "SMS")
        }
        "method" => matches!(category, "OAuth" | "SAML") || custom_delivery(editor),
        "issuer_url" => {
            matches!(category, "OAuth" | "SAML")
                || custom_delivery(editor) && matches!(category, "Email" | "SMS")
        }
        "client_id2" => matches!(category, "Email" | "OAuth" | "Payment" | "Notification"),
        "client_secret2" => matches!(category, "Email" | "OAuth" | "Payment" | "Notification"),
        "host" | "port" => matches!(category, "Email" | "LDAP"),
        "disable_ssl" => {
            category == "LDAP"
                || category == "Email"
                    && read(editor, "ssl_mode")
                        .as_str()
                        .is_none_or(|v| v.is_empty())
        }
        "ssl_mode" => {
            category == "Email" && matches!(read(editor, "type").as_str(), Some("SMTP" | "SUBMAIL"))
        }
        "receiver" => matches!(category, "Email" | "SMS" | "Notification"),
        "title" => matches!(category, "Email" | "SMS" | "Notification"),
        "app_id" | "sign_name" | "template_code" => category == "SMS",
        "region_id" => matches!(category, "Storage" | "SMS"),
        "domain" => {
            category == "Storage"
                || (category == "OAuth"
                    && matches!(read(editor, "type").as_str(), Some("Okta" | "OIDC")))
        }
        "bucket" | "path_prefix" => category == "Storage",
        "cert" => category == "SAML",
        "http_headers" => matches!(category, "OAuth" | "Notification" | "Email" | "SMS"),
        _ => true,
    }
}
pub fn form(config: ResourceConfig, editor: Cage<String>, message: Cage<String>) -> Element {
    boxed(widget(move |scope| {
        let raw = scope.cage(false);
        let mut widgets: Vec<Element> = Vec::new();
        for field in fields_for_resource(config.slug) {
            let key = field.key;
            let name = field.label;
            let accessible = scope.bond(move || {
                if config.slug == "syncers" && cloud_directory(editor) {
                    cloud_label(editor, key).unwrap_or(name).to_string()
                } else if config.slug == "syncers"
                    && matches!(
                        read(editor, "type").as_str(),
                        Some("LDAP" | "Active Directory")
                    )
                {
                    match key {
                        "database" => "Base DN",
                        "table" => "LDAP search filter",
                        "user" => "Bind DN",
                        "password" => "Bind password",
                        _ => name,
                    }
                    .to_string()
                } else if config.slug == "providers" {
                    match (key, read(editor, "category").as_str()) {
                        ("disable_ssl", Some("Email")) => "Allow plaintext SMTP".into(),
                        ("client_id2", Some("Email")) => "From address".into(),
                        ("client_secret2", Some("Email")) => "From name".into(),
                        ("region_id", Some("SMS")) => "SMS region".into(),
                        ("method", Some("Email" | "SMS" | "Notification")) => {
                            "HTTP request method".into()
                        }
                        ("user_mapping", Some("Email" | "SMS")) => {
                            "HTTP body mapping (JSON)".into()
                        }
                        ("issuer_url", Some("Email" | "SMS")) => "HTTP content type".into(),
                        ("title", Some("Notification")) if custom_delivery(editor) => {
                            "Notification parameter name".into()
                        }
                        ("domain", Some("OAuth")) if read(editor, "type") == "OIDC" => {
                            "OIDC issuer base".into()
                        }
                        ("domain", Some("OAuth")) if read(editor, "type") == "Okta" => {
                            "Okta issuer base".into()
                        }
                        ("content", Some("OAuth")) if read(editor, "type") == "WeChat" => {
                            "WeChat private key / content".into()
                        }
                        _ => name.to_string(),
                    }
                } else {
                    name.to_string()
                }
            });
            let control: Element = match field.kind {
                FieldKind::Toggle => boxed(
                    sapid::checkbox()
                        .label(accessible)
                        .checked(scope.bond(move || read(editor, key).as_bool().unwrap_or(false)))
                        .on_checked_change(move |v| update(editor, key, json!(v), message)),
                ),
                FieldKind::Select(options) => {
                    // Semantic option keys are ASCII tokens. API values can
                    // contain spaces or other characters, so retain them separately.
                    let values: Vec<String> =
                        options.iter().map(|option| option.value.clone()).collect();
                    let selected_values = values.clone();
                    boxed(
                        sapid::native_select(key)
                            .name(accessible)
                            .value(scope.bond(move || {
                                let current = read(editor, key);
                                selected_values
                                    .iter()
                                    .position(|value| current.as_str() == Some(value.as_str()))
                                    .map(|index| index.to_string())
                            }))
                            .options(options.into_iter().enumerate().map(|(index, option)| {
                                sapid::select_option(index.to_string(), option.label)
                            }))
                            .on_value_change(move |selected| {
                                let value = selected
                                    .and_then(|key| key.parse::<usize>().ok())
                                    .and_then(|index| values.get(index))
                                    .cloned()
                                    .unwrap_or_default();
                                if config.slug == "syncers"
                                    && key == "type"
                                    && matches!(value.as_str(), "Azure AD" | "Google Workspace")
                                    && read(editor, "type") != value
                                {
                                    if let Ok(Value::Object(mut data)) =
                                        serde_json::from_str::<Value>(&editor.get())
                                    {
                                        data.insert("type".into(), json!(value));
                                        data.insert("is_read_only".into(), json!(true));
                                        data.insert("table_columns".into(), json!([]));
                                        for key in [
                                            "database_type",
                                            "ssl_mode",
                                            "table",
                                            "affiliation_table",
                                        ] {
                                            data.insert(key.into(), Value::Null);
                                        }
                                        for key in ["host", "user", "password", "database"] {
                                            data.insert(key.into(), json!(""));
                                        }
                                        data.insert("port".into(), json!(443));
                                        editor.set(crate::api::pretty_json(&Value::Object(data)));
                                        message.set(String::new());
                                        return;
                                    }
                                }
                                if config.slug == "syncers"
                                    && key == "type"
                                    && value == "SCIM"
                                    && read(editor, "type") != "SCIM"
                                {
                                    if let Ok(Value::Object(mut data)) =
                                        serde_json::from_str::<Value>(&editor.get())
                                    {
                                        data.insert("type".into(), json!("SCIM"));
                                        data.insert("is_read_only".into(), json!(true));
                                        data.insert("table_columns".into(), json!([]));
                                        for field in [
                                            "database_type",
                                            "ssl_mode",
                                            "database",
                                            "table",
                                            "affiliation_table",
                                        ] {
                                            data.insert(field.into(), Value::Null);
                                        }
                                        for field in ["host", "user", "password"] {
                                            data.insert(field.into(), json!(""));
                                        }
                                        editor.set(crate::api::pretty_json(&Value::Object(data)));
                                        message.set(String::new());
                                        return;
                                    }
                                }
                                if config.slug == "syncers"
                                    && key == "type"
                                    && matches!(value.as_str(), "LDAP" | "Active Directory")
                                    && read(editor, "type").as_str() != Some(value.as_str())
                                {
                                    if let Ok(Value::Object(mut data)) =
                                        serde_json::from_str::<Value>(&editor.get())
                                    {
                                        data.insert("type".into(), json!(value));
                                        data.insert("is_read_only".into(), json!(true));
                                        data.insert("table_columns".into(), json!([]));
                                        data.insert("database_type".into(), Value::Null);
                                        data.insert("affiliation_table".into(), Value::Null);
                                        data.insert("database".into(), json!(""));
                                        data.insert("table".into(), json!(""));
                                        data.insert("port".into(), json!(389));
                                        data.insert("ssl_mode".into(), json!("disable"));
                                        editor.set(crate::api::pretty_json(&Value::Object(data)));
                                        message.set(String::new());
                                        return;
                                    }
                                }
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
                            if config.slug == "providers"
                                && matches!(key, "metadata" | "user_mapping" | "http_headers")
                            {
                                value.as_str().map(str::to_owned).unwrap_or_else(|| {
                                    if value.is_null() {
                                        "{}".into()
                                    } else {
                                        crate::api::pretty_json(&value)
                                    }
                                })
                            } else {
                                crate::api::pretty_json(&value)
                            }
                        } else if is_tags {
                            value
                                .as_array()
                                .map(|a| {
                                    a.iter()
                                        .filter_map(Value::as_str)
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                })
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
                            serde_json::from_str::<Value>(&next)
                                .map(|v| {
                                    if config.slug == "providers" && key == "metadata" {
                                        json!(v.to_string())
                                    } else {
                                        v
                                    }
                                })
                                .map_err(|e| e.to_string())
                        } else if is_number {
                            next.parse::<serde_json::Number>()
                                .map(Value::Number)
                                .map_err(|_| "Enter a finite number".to_string())
                        } else if is_tags {
                            Ok(json!(
                                next.split(',')
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty())
                                    .collect::<Vec<_>>()
                            ))
                        } else {
                            Ok(json!(next))
                        };
                        match parsed {
                            Ok(value) => update(editor, key, value, message),
                            Err(error) => message.set(format!("{name}: {error}")),
                        }
                    };
                    if matches!(kind, FieldKind::ProviderContent) {
                        boxed(stack((
                            when(
                                scope.bond(move || read(editor, "type") == "WeChat"),
                                move || {
                                    widget(move |scope| {
                                        sapid::password_input()
                                            .name("WeChat private key / content")
                                            .value(draft)
                                            .on_value_change(change)
                                            .build(scope)
                                    })
                                },
                            ),
                            when(
                                scope.bond(move || read(editor, "type") != "WeChat"),
                                move || {
                                    widget(move |scope| {
                                        sapid::textarea()
                                            .name("Content / discovery ports")
                                            .value(draft)
                                            .on_value_change(change)
                                            .rows(5)
                                            .build(scope)
                                    })
                                },
                            ),
                        )))
                    } else if matches!(kind, FieldKind::Json | FieldKind::TextArea) {
                        boxed(
                            sapid::textarea()
                                .name(accessible)
                                .value(draft)
                                .on_value_change(change)
                                .rows(5),
                        )
                    } else if matches!(kind, FieldKind::SecondaryCredential) {
                        boxed(stack((
                            when(
                                scope.bond(move || read(editor, "category") == "Email"),
                                move || {
                                    widget(move |scope| {
                                        sapid::text_field()
                                            .name("From name")
                                            .value(draft)
                                            .on_value_change(change)
                                            .build(scope)
                                    })
                                },
                            ),
                            when(
                                scope.bond(move || read(editor, "category") != "Email"),
                                move || {
                                    widget(move |scope| {
                                        sapid::password_input()
                                            .name("Secondary client secret")
                                            .value(draft)
                                            .on_value_change(change)
                                            .build(scope)
                                    })
                                },
                            ),
                        )))
                    } else if matches!(kind, FieldKind::Password) {
                        boxed(
                            sapid::password_input()
                                .name(accessible)
                                .value(draft)
                                .on_value_change(change),
                        )
                    } else {
                        boxed(
                            sapid::text_field()
                                .name(accessible)
                                .value(draft)
                                .required(field.required)
                                .on_value_change(change),
                        )
                    }
                }
            };
            let title = scope.bond(move || {
                if config.slug == "syncers" && cloud_directory(editor) {
                    cloud_label(editor, key).unwrap_or(name)
                } else if config.slug == "syncers"
                    && matches!(
                        read(editor, "type").as_str(),
                        Some("LDAP" | "Active Directory")
                    )
                {
                    match key {
                        "database" => "Base DN",
                        "table" => "LDAP search filter (blank uses directory default)",
                        "user" => "Bind DN",
                        "password" => "Bind password",
                        _ => name,
                    }
                } else if config.slug == "providers" {
                    match (key, read(editor, "category").as_str()) {
                        ("disable_ssl", Some("Email")) => "Allow plaintext SMTP",
                        ("client_id2", Some("Email")) => "From address",
                        ("client_secret2", Some("Email")) => "From name",
                        ("region_id", Some("SMS")) => "SMS region",
                        ("method", Some("Email" | "SMS" | "Notification")) => "HTTP request method",
                        ("user_mapping", Some("Email" | "SMS")) => "HTTP body mapping (JSON)",
                        ("issuer_url", Some("Email" | "SMS")) => "HTTP content type",
                        ("title", Some("Notification")) if custom_delivery(editor) => {
                            "Notification parameter name"
                        }
                        ("domain", Some("OAuth")) if read(editor, "type") == "OIDC" => {
                            "OIDC issuer base"
                        }
                        ("domain", Some("OAuth")) if read(editor, "type") == "Okta" => {
                            "Okta issuer base"
                        }
                        _ => name,
                    }
                } else {
                    name
                }
            });
            widgets.push(boxed(
                stack((text().content_fn(move || title.get().to_string()), control)).class_fn(
                    move || {
                        let directory = matches!(
                            read(editor, "type").as_str(),
                            Some("LDAP" | "Active Directory")
                        );
                        let hidden = (config.slug == "providers"
                            && !provider_field_visible(editor, key))
                            || config.slug == "syncers"
                                && ((read(editor, "type") == "SCIM"
                                    && [
                                        "database_type",
                                        "ssl_mode",
                                        "port",
                                        "database",
                                        "table",
                                        "affiliation_table",
                                    ]
                                    .contains(&key))
                                    || (cloud_directory(editor)
                                        && [
                                            "database_type",
                                            "ssl_mode",
                                            "port",
                                            "table",
                                            "affiliation_table",
                                        ]
                                        .contains(&key))
                                    || (directory
                                        && ["database_type", "affiliation_table", "ssl_mode"]
                                            .contains(&key)));
                        if hidden {
                            "stack hidden".into()
                        } else {
                            "stack".into()
                        }
                    },
                ),
            ));
        }
        let structured = stack(widgets);
        stack((
            stack((
            stack((
            when(scope.bond(move || config.slug=="syncers" && read(editor,"type")=="SCIM"), || label("SCIM reads users from Host/Users. Enter an HTTPS base URL, or local HTTP for testing. Leave Username blank and put a Bearer token in Password; enter both for Basic authentication. Empty mappings use standard SCIM fields. Only read-only synchronization is supported.")),
            when(scope.bond(move || config.slug=="syncers" && read(editor,"type")=="Azure AD"),||label("Azure AD uses your tenant ID or domain, application client ID and client secret to read Microsoft Graph. Grant the application directory read permissions. Synchronization is read-only and preserves local passwords, MFA and account links. Empty mappings use the standard directory fields. Cloud transport options may override token_endpoint and api_base; internal endpoints require global administrator review and approval.")),
            when(scope.bond(move || config.slug=="syncers" && read(editor,"type")=="Google Workspace"),||label("Google Workspace requires a service account JSON key with domain-wide delegation and a delegated administrator email. Service account email may be empty or must match client_email in the key. Users, groups and memberships are fully read before local changes apply. Managed groups preserve manual memberships; remote administrators do not become local administrators. Cloud transport options may set api_base and customer. Internal endpoints, including a private token_uri in the key, require separate global approval.")),
            when(scope.bond(move || config.slug=="syncers" && matches!(read(editor,"type").as_str(),Some("LDAP"|"Active Directory"))),||label("Directory synchronization is read-only. Host accepts ldap:// or ldaps://; use Base DN and an optional LDAP filter, not SQL database/table names. Empty mappings use directory defaults. Active Directory tracks objectGUID across DN/OU/name changes and reads the account-disabled bit. Use starttls with ldap:// or ldaps:// for encrypted connections.")),
            )),
            when(scope.bond(move || config.slug=="providers" && read(editor,"category")=="Storage"),||label("Storage: Bucket is the container/bucket; Region is used by S3/MinIO. Domain takes precedence over Endpoint as the public/CDN base for Azure Blob and Google Cloud Storage. For Azure Blob and Google Cloud Storage, Domain's path and Path prefix become part of the stored object key. MinIO/S3 Endpoint is the storage API origin. Without a public base, resource access uses a fresh signed URL or authenticated download. Azure Client ID is the account name and Client secret is its base64 account key. Google Cloud Storage Client secret is the full service_account JSON, including private_key and token_uri; keep it out of Content. Metadata may contain the advanced storageApiEndpoint API-origin override; this is separate from the public/CDN base.")),
            when(scope.bond(move || config.slug=="providers" && read(editor,"category")=="OAuth"),||label("Custom OAuth uses the authorization, token and user info URLs. Scopes are sent during sign-in and account linking. User mapping maps id, username, displayName, email, emailVerified, phone, phoneVerified or avatarUrl to dot-separated response paths, for example {\"id\":\"data.employeeId\",\"displayName\":\"data.name\"}. Changing identity configuration requires starting a new sign-in.")),
            when(scope.bond(move || config.slug=="providers" && read(editor,"category")=="OAuth" && read(editor,"type")=="Okta"),||label("Okta issuer base is the complete authorization-server URL, including any path such as https://example.okta.com/oauth2/default. The provider appends /v1/authorize, /v1/token and /v1/userinfo. Issuer URL is a fallback when the issuer base is empty.")),
            when(scope.bond(move || config.slug=="providers" && read(editor,"category")=="OAuth" && read(editor,"type")=="WeChat"),||label("WeChat website login uses Client ID and Client secret. In the WeChat browser, Secondary client ID and Secondary client secret are the official-account credentials. Configure both before mobile sign-in. The selected account remains bound to that login attempt across callback and MFA. A changed credential requires starting sign-in again; accounts are never linked by display name or email.")),
            when(scope.bond(move || config.slug=="providers" && read(editor,"category")=="Email"),||label("From address uses the secondary client ID; From name uses the secondary client secret field as a public display name. SMTP Host and Port select the mail server. Legacy secure defaults use implicit TLS on port 465 and require STARTTLS elsewhere; the legacy plaintext toggle permits a relay without STARTTLS. Explicit Enable requires implicit TLS on any port. Auto chooses implicit TLS on 465 and optional STARTTLS elsewhere; Disable uses optional STARTTLS on all ports. Auto and Disable allow plaintext when the relay has no STARTTLS. TLS certificate verification remains enabled.")),
            when(scope.bond(move || config.slug=="providers" && custom_delivery(editor)),||label("Custom HTTP: leave Method empty to retain the existing JSON protocol. An explicit method enables the Casdoor protocol. Email supports GET/POST/PUT/DELETE; HTTP content type is application/json or application/x-www-form-urlencoded (default). Body mapping renames request fields. Notification supports GET/POST and uses Notification parameter name for the content field, plus recipient. HTTP headers are sent to the configured endpoint and remain masked. Internal endpoints require separate global administrator approval; configuration changes require approval again.")),
            when(scope.bond(move || config.slug=="providers" && read(editor,"category")=="OAuth" && read(editor,"type")=="OIDC"),||label("OIDC issuer base takes precedence over Issuer URL. The server discovers authorization, token and user info endpoints from the issuer metadata; explicit URLs override discovered endpoints. The discovered issuer must match. Providers publishing JWKS can return a signed ID token without UserInfo; signatures, audience and a login-bound nonce are verified. When UserInfo is also returned, its subject must match. Authentication method accepts client_secret_basic, client_secret_post or none; leave it empty to use discovery. An unverified token is never accepted as identity.")),
            when(scope.bond(move || config.slug=="providers" && read(editor,"category")=="SMS"),||label("Twilio uses the client ID as account SID and client secret as auth token. Sender uses application ID, then signature, then default receiver. HTTP SMS uses Endpoint and the client secret API key.")),
            when(scope.bond(move || config.slug=="providers"),||label("Saved secrets are masked. Leave a secret blank to retain it; enter a new value to rotate it. Use the explicit clear controls to remove saved credentials. Metadata shows only safe or masked configuration; JSON objects merge by key and {} retains existing keys. Webhook URLs are masked; *** preserves the saved URL. Enter a replacement explicitly to change it. Do not place credentials in public text fields.")),
            when(scope.bond(move || config.slug=="organizations"),||label("Kerberos uses your browser's integrated authentication. Configure the realm, KDC host and HTTP service plus a base64 MIT keytab. The masked *** value preserves the saved keytab. Clear all four fields together to disable it.")),
            )),
            when(scope.bond(move || config.slug=="syncers" && matches!(read(editor,"type").as_str(),Some("LDAP"|"Active Directory"))),move ||widget(move |scope| {
                sapid::checkbox().label("Use StartTLS with ldap://").checked(scope.bond(move ||read(editor,"ssl_mode")=="starttls")).on_checked_change(move |checked|update(editor,"ssl_mode",json!(if checked{"starttls"}else{"disable"}),message)).build(scope)
            })),
            sapid::button()
                .label("Switch structured / JSON editor")
                .on_press(move || raw.set(!raw.get())),
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
                .class_fn(move || if raw.get() { "json-editor" } else { "hidden" }.into())
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
                key: "record_retention_days",
                label: "Audit retention days (0 inherits site policy)",
                kind: FieldKind::Number,
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
            FieldDef {
                key: "kerberos_realm",
                label: "Kerberos realm",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "kerberos_kdc_host",
                label: "Kerberos KDC host",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "kerberos_service_name",
                label: "Kerberos HTTP service",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "kerberos_keytab",
                label: "Kerberos keytab (base64)",
                kind: FieldKind::Password,
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
                        value: "SAML".into(),
                        label: "SAML".into(),
                    },
                    SelectOption {
                        value: "LDAP".into(),
                        label: "LDAP".into(),
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
                    SelectOption {
                        value: "Scan".into(),
                        label: "Scan".into(),
                    },
                    SelectOption {
                        value: "Log".into(),
                        label: "Log".into(),
                    },
                    SelectOption {
                        value: "ID Verification".into(),
                        label: "ID Verification".into(),
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
                        value: "Okta".into(),
                        label: "Okta".into(),
                    },
                    SelectOption {
                        value: "OIDC".into(),
                        label: "OIDC".into(),
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
                        value: "Azure Blob".into(),
                        label: "Azure Blob".into(),
                    },
                    SelectOption {
                        value: "Google Cloud Storage".into(),
                        label: "Google Cloud Storage".into(),
                    },
                    SelectOption {
                        value: "MinIO".into(),
                        label: "MinIO".into(),
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
                    SelectOption {
                        value: "Local".into(),
                        label: "Local".into(),
                    },
                    SelectOption {
                        value: "Local File System".into(),
                        label: "Local File System".into(),
                    },
                    SelectOption {
                        value: "Security Scan".into(),
                        label: "Security Scan".into(),
                    },
                    SelectOption {
                        value: "MCP Scan".into(),
                        label: "MCP Scan".into(),
                    },
                    SelectOption {
                        value: "OpenClaw".into(),
                        label: "OpenClaw".into(),
                    },
                    SelectOption {
                        value: "HTTP".into(),
                        label: "HTTP".into(),
                    },
                    SelectOption {
                        value: "Generic".into(),
                        label: "Generic".into(),
                    },
                    SelectOption {
                        value: "Custom HTTP".into(),
                        label: "Custom HTTP".into(),
                    },
                ]),
                required: true,
            },
            FieldDef {
                key: "sub_type",
                label: "Subtype",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "endpoint",
                label: "Endpoint URL / paths",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "scopes",
                label: "Scopes / discovery targets",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "content",
                label: "Content / discovery ports",
                kind: FieldKind::ProviderContent,
                required: false,
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
                key: "client_id2",
                label: "Secondary client ID",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "client_secret2",
                label: "Secondary client secret",
                kind: FieldKind::SecondaryCredential,
                required: false,
            },
            FieldDef {
                key: "custom_auth_url",
                label: "OAuth authorization URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "custom_token_url",
                label: "OAuth token URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "custom_user_info_url",
                label: "OAuth user info URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "custom_logo",
                label: "Custom logo URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "user_mapping",
                label: "OAuth user mapping (JSON)",
                kind: FieldKind::Json,
                required: false,
            },
            FieldDef {
                key: "method",
                label: "Authentication method",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "issuer_url",
                label: "Issuer URL",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "receiver",
                label: "Default receiver",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "title",
                label: "Message title",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "disable_ssl",
                label: "Disable implicit TLS",
                kind: FieldKind::Toggle,
                required: false,
            },
            FieldDef {
                key: "ssl_mode",
                label: "SMTP SSL mode",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "".into(),
                        label: "Legacy secure defaults".into(),
                    },
                    SelectOption {
                        value: "Auto".into(),
                        label: "Auto (465 implicit, otherwise optional STARTTLS)".into(),
                    },
                    SelectOption {
                        value: "Enable".into(),
                        label: "Enable (require implicit TLS on this port)".into(),
                    },
                    SelectOption {
                        value: "Disable".into(),
                        label: "Disable implicit TLS (optional STARTTLS)".into(),
                    },
                ]),
                required: false,
            },
            FieldDef {
                key: "app_id",
                label: "SMS sender / application ID",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "sign_name",
                label: "SMS signature / From number",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "template_code",
                label: "SMS template code",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "http_headers",
                label: "HTTP headers (JSON)",
                kind: FieldKind::Json,
                required: false,
            },
            FieldDef {
                key: "cert",
                label: "Identity provider certificate",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "provider_url",
                label: "Provider URL",
                kind: FieldKind::Text,
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
                key: "bucket",
                label: "Bucket / container",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "region_id",
                label: "Storage region",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "path_prefix",
                label: "Storage path prefix",
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
                        value: "Active Directory".into(),
                        label: "Active Directory".into(),
                    },
                    SelectOption {
                        value: "LDAP".into(),
                        label: "LDAP".into(),
                    },
                    SelectOption {
                        value: "Keycloak".into(),
                        label: "Keycloak".into(),
                    },
                    SelectOption {
                        value: "SCIM".into(),
                        label: "SCIM".into(),
                    },
                    SelectOption {
                        value: "Azure AD".into(),
                        label: "Azure AD".into(),
                    },
                    SelectOption {
                        value: "Google Workspace".into(),
                        label: "Google Workspace".into(),
                    },
                ]),
                required: true,
            },
            FieldDef {
                key: "database_type",
                label: "Database type",
                kind: FieldKind::Select(vec![SelectOption {
                    value: "postgres".into(),
                    label: "PostgreSQL".into(),
                }]),
                required: false,
            },
            FieldDef {
                key: "ssl_mode",
                label: "SSL mode",
                kind: FieldKind::Select(vec![
                    SelectOption {
                        value: "starttls".into(),
                        label: "StartTLS (LDAP)".into(),
                    },
                    SelectOption {
                        value: "disable".into(),
                        label: "Disable".into(),
                    },
                    SelectOption {
                        value: "require".into(),
                        label: "Require".into(),
                    },
                    SelectOption {
                        value: "verify-full".into(),
                        label: "Verify full".into(),
                    },
                ]),
                required: false,
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
                key: "table_columns",
                label: "Field mappings (JSON array)",
                kind: FieldKind::Json,
                required: false,
            },
            FieldDef {
                key: "is_read_only",
                label: "Read external source only",
                kind: FieldKind::Toggle,
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
                required: true,
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
                key: "detail",
                label: "Product detail",
                kind: FieldKind::TextArea,
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
                label: "Quantity (-1 for unlimited)",
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
                key: "state",
                label: "State",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "is_recharge",
                label: "Recharge product",
                kind: FieldKind::Toggle,
                required: false,
            },
            FieldDef {
                key: "recharge_options",
                label: "Recharge amounts (JSON array)",
                kind: FieldKind::Json,
                required: false,
            },
            FieldDef {
                key: "disable_custom_recharge",
                label: "Only preset recharge amounts",
                kind: FieldKind::Toggle,
                required: false,
            },
            FieldDef {
                key: "plan_id",
                label: "Bound plan ID or owner/name",
                kind: FieldKind::Text,
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
                required: true,
            },
            FieldDef {
                key: "description",
                label: "Description",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "price_per_month",
                label: "Monthly price",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "price_per_year",
                label: "Yearly price",
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
                key: "role",
                label: "Granted role ID or owner/name",
                kind: FieldKind::Text,
                required: false,
            },
            FieldDef {
                key: "options",
                label: "Plan options",
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
                required: true,
            },
            FieldDef {
                key: "description",
                label: "Description",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "plans",
                label: "Plan references (JSON array)",
                kind: FieldKind::TextArea,
                required: false,
            },
            FieldDef {
                key: "is_invite_only",
                label: "Invite-only pricing",
                kind: FieldKind::Toggle,
                required: false,
            },
            FieldDef {
                key: "users",
                label: "Invited usernames (empty allows the whole tenant)",
                kind: FieldKind::Tags,
                required: false,
            },
            FieldDef {
                key: "trial_duration",
                label: "Trial duration (days)",
                kind: FieldKind::Number,
                required: false,
            },
            FieldDef {
                key: "application",
                label: "Application",
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
