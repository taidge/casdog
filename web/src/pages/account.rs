use dioxus::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{build_url, extract_collection, request_json};
use crate::components::qr_code::QrCode;

const ACCOUNT_PAGE_CSS: &str = r#"
.account-page {
  max-width: 760px;
  margin: 0 auto;
  padding: 30px;
  animation: fade-up 320ms ease;
}

.account-page h2 {
  margin: 0 0 8px;
  font-size: 32px;
  font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
}

.account-page > .subtitle {
  margin: 0 0 28px;
  color: var(--text-soft);
  line-height: 1.5;
}

.account-tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.account-tab {
  padding: 10px 16px;
  border: 1px solid var(--line);
  border-radius: 14px;
  background: transparent;
  color: var(--text-soft);
  cursor: pointer;
  font: inherit;
  font-size: 14px;
  transition: background 160ms ease, color 160ms ease;
}

.account-tab:hover {
  background: var(--surface-soft);
}

.account-tab.active {
  background: var(--surface-strong);
  color: #fff;
  border-color: var(--surface-strong);
}

.account-section {
  padding: 24px;
  border: 1px solid var(--line);
  border-radius: 22px;
  background: var(--surface);
  box-shadow: var(--shadow);
  backdrop-filter: blur(18px);
  margin-bottom: 20px;
}

.account-section h3 {
  margin: 0 0 16px;
  font-size: 20px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--line);
}

.account-form {
  display: grid;
  gap: 16px;
}

.account-field {
  display: grid;
  gap: 6px;
}

.account-field label {
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.04em;
}

.account-field-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.account-actions {
  display: flex;
  gap: 10px;
  margin-top: 8px;
}

.mfa-setup {
  display: grid;
  gap: 16px;
  margin-top: 12px;
}

.mfa-status {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  border-radius: 14px;
  font-size: 14px;
}

.mfa-enabled {
  background: rgba(35, 123, 86, 0.1);
  color: var(--success);
}

.mfa-disabled {
  background: rgba(208, 111, 60, 0.1);
  color: var(--accent-strong);
}

.recovery-codes {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 6px;
  margin: 12px 0;
}

.recovery-code {
  padding: 8px 12px;
  border-radius: 10px;
  background: var(--surface-soft);
  font-family: "IBM Plex Mono", Consolas, monospace;
  font-size: 14px;
  text-align: center;
}

.webauthn-list {
  display: grid;
  gap: 10px;
  margin-top: 12px;
}

.webauthn-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border: 1px solid var(--line);
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.7);
}

.webauthn-item-info {
  flex: 1;
}

.webauthn-item-info h4 {
  margin: 0;
  font-size: 15px;
}

.webauthn-item-info p {
  margin: 4px 0 0;
  font-size: 12px;
  color: var(--text-soft);
}

.session-list {
  display: grid;
  gap: 10px;
  margin-top: 12px;
}

.session-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 16px;
  border: 1px solid var(--line);
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.7);
}

.session-item.current {
  border-color: rgba(35, 123, 86, 0.3);
  background: rgba(35, 123, 86, 0.04);
}

.session-item-info {
  flex: 1;
  min-width: 0;
}

.session-item-info h4 {
  margin: 0;
  font-size: 14px;
}

.session-item-info p {
  margin: 2px 0 0;
  font-size: 12px;
  color: var(--text-soft);
}

.session-tag {
  padding: 4px 8px;
  border-radius: 8px;
  background: rgba(35, 123, 86, 0.12);
  color: var(--success);
  font-size: 11px;
  font-weight: 600;
  white-space: nowrap;
}
"#;

#[derive(Debug, Clone, Default, Deserialize)]
struct UserProfile {
    #[serde(default)]
    owner: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    avatar: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default)]
    bio: Option<String>,
    #[serde(default)]
    is_mfa_enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct WebAuthnCredential {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    created_time: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct SessionInfo {
    #[serde(default)]
    id: String,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    application: Option<String>,
    #[serde(default)]
    created_time: Option<String>,
    #[serde(default)]
    is_current: Option<bool>,
}

/// Account settings page with sections: Profile, Security (password + MFA + WebAuthn), Sessions.
///
/// Props:
/// * `api_base` - Signal with the API base URL.
/// * `token` - The current user's auth token.
/// * `user_owner` - The user's owner/organization (for API paths).
/// * `user_name` - The user's username (for API paths).
#[component]
pub fn AccountPage(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
    #[props(default = "admin".to_string())] user_owner: String,
    #[props(default)] user_name: String,
) -> Element {
    let mut active_tab = use_signal(|| "profile".to_string());

    rsx! {
        style { "{ACCOUNT_PAGE_CSS}" }

        div { class: "account-page",
            h2 { "Account settings" }
            p { class: "subtitle", "Manage your profile, security, and sessions." }

            div { class: "account-tabs",
                {["profile", "security", "mfa", "webauthn", "sessions"].iter().map(|tab| {
                    let is_active = active_tab() == *tab;
                    let label = match *tab {
                        "profile" => "Profile",
                        "security" => "Security",
                        "mfa" => "MFA",
                        "webauthn" => "WebAuthn",
                        "sessions" => "Sessions",
                        _ => tab,
                    };
                    rsx! {
                        button {
                            class: if is_active { "account-tab active" } else { "account-tab" },
                            key: "{tab}",
                            onclick: move |_| active_tab.set(tab.to_string()),
                            "{label}"
                        }
                    }
                })}
            }

            match active_tab().as_str() {
                "profile" => rsx! {
                    ProfileSection {
                        api_base,
                        token,
                        user_owner: user_owner.clone(),
                        user_name: user_name.clone(),
                    }
                },
                "security" => rsx! {
                    SecuritySection {
                        api_base,
                        token,
                        user_owner: user_owner.clone(),
                        user_name: user_name.clone(),
                    }
                },
                "mfa" => rsx! {
                    MfaSection {
                        api_base,
                        token,
                        user_owner: user_owner.clone(),
                        user_name: user_name.clone(),
                    }
                },
                "webauthn" => rsx! {
                    WebAuthnSection {
                        api_base,
                        token,
                        user_owner: user_owner.clone(),
                        user_name: user_name.clone(),
                    }
                },
                "sessions" => rsx! {
                    SessionsSection {
                        api_base,
                        token,
                        user_owner: user_owner.clone(),
                        user_name: user_name.clone(),
                    }
                },
                _ => rsx! { div { "Unknown tab" } },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Profile Section
// ---------------------------------------------------------------------------

#[component]
fn ProfileSection(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
    user_owner: String,
    user_name: String,
) -> Element {
    let mut profile = use_signal(UserProfile::default);
    let mut display_name = use_signal(String::new);
    let mut avatar = use_signal(String::new);
    let mut email = use_signal(String::new);
    let mut phone = use_signal(String::new);
    let mut bio = use_signal(String::new);
    let mut loading = use_signal(|| false);
    let mut saving = use_signal(|| false);
    let mut message = use_signal(|| None::<(bool, String)>);

    // Fetch profile
    {
        let api_base_val = api_base();
        let token_val = token();
        let owner = user_owner.clone();
        let name = user_name.clone();
        use_effect(move || {
            let api_base_val = api_base_val.clone();
            let token_val = token_val.clone();
            let owner = owner.clone();
            let name = name.clone();
            loading.set(true);
            spawn(async move {
                let url = if name.is_empty() {
                    build_url(&api_base_val, "/api/userinfo")
                } else {
                    build_url(&api_base_val, &format!("/api/users/{owner}/{name}"))
                };
                match request_json("GET", &url, token_val.as_deref(), None).await {
                    Ok(value) => {
                        if let Ok(p) = serde_json::from_value::<UserProfile>(value) {
                            display_name.set(p.display_name.clone().unwrap_or_default());
                            avatar.set(p.avatar.clone().unwrap_or_default());
                            email.set(p.email.clone().unwrap_or_default());
                            phone.set(p.phone.clone().unwrap_or_default());
                            bio.set(p.bio.clone().unwrap_or_default());
                            profile.set(p);
                        }
                    }
                    Err(err) => {
                        message.set(Some((false, err)));
                    }
                }
                loading.set(false);
            });
        });
    }

    let do_save = move |_| {
        let api_base_val = api_base();
        let token_val = token();
        let p = profile();
        let dn = display_name();
        let av = avatar();
        let em = email();
        let ph = phone();
        let bi = bio();

        spawn(async move {
            saving.set(true);
            message.set(None);

            let payload = json!({
                "owner": p.owner,
                "name": p.name,
                "display_name": dn,
                "avatar": av,
                "email": em,
                "phone": ph,
                "bio": bi,
            });

            let url = build_url(
                &api_base_val,
                &format!("/api/users/{}/{}", p.owner, p.name),
            );
            match request_json("PUT", &url, token_val.as_deref(), Some(payload)).await {
                Ok(_) => {
                    message.set(Some((true, "Profile saved successfully.".to_string())));
                }
                Err(err) => {
                    message.set(Some((false, err)));
                }
            }
            saving.set(false);
        });
    };

    rsx! {
        div { class: "account-section",
            h3 { "Profile" }

            if loading() {
                div { class: "inline-message neutral", "Loading profile..." }
            } else {
                div { class: "account-form",
                    div { class: "account-field",
                        label { "Display name" }
                        input {
                            class: "text-input",
                            value: "{display_name}",
                            oninput: move |evt| display_name.set(evt.value()),
                        }
                    }
                    div { class: "account-field",
                        label { "Avatar URL" }
                        input {
                            class: "text-input",
                            placeholder: "https://example.com/avatar.png",
                            value: "{avatar}",
                            oninput: move |evt| avatar.set(evt.value()),
                        }
                    }
                    div { class: "account-field-row",
                        div { class: "account-field",
                            label { "Email" }
                            input {
                                class: "text-input",
                                r#type: "email",
                                value: "{email}",
                                oninput: move |evt| email.set(evt.value()),
                            }
                        }
                        div { class: "account-field",
                            label { "Phone" }
                            input {
                                class: "text-input",
                                r#type: "tel",
                                value: "{phone}",
                                oninput: move |evt| phone.set(evt.value()),
                            }
                        }
                    }
                    div { class: "account-field",
                        label { "Bio" }
                        textarea {
                            class: "text-input",
                            rows: "3",
                            value: "{bio}",
                            oninput: move |evt| bio.set(evt.value()),
                        }
                    }

                    if let Some((ok, msg)) = message() {
                        div {
                            class: if ok { "inline-message success" } else { "inline-message error" },
                            "{msg}"
                        }
                    }

                    div { class: "account-actions",
                        button {
                            class: "primary-button",
                            disabled: saving(),
                            onclick: do_save,
                            if saving() { "Saving..." } else { "Save profile" }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Security Section (change password)
// ---------------------------------------------------------------------------

#[component]
fn SecuritySection(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
    user_owner: String,
    user_name: String,
) -> Element {
    let mut current_password = use_signal(String::new);
    let mut new_password = use_signal(String::new);
    let mut confirm_password = use_signal(String::new);
    let mut changing = use_signal(|| false);
    let mut message = use_signal(|| None::<(bool, String)>);
    let mut show_passwords = use_signal(|| false);

    let passwords_match = new_password().is_empty() || new_password() == confirm_password();

    let do_change = move |_| {
        let api_base_val = api_base();
        let token_val = token();
        let owner = user_owner.clone();
        let name = user_name.clone();
        let old_pw = current_password();
        let new_pw = new_password();
        let conf = confirm_password();

        if new_pw != conf {
            message.set(Some((false, "Passwords do not match.".to_string())));
            return;
        }

        if new_pw.is_empty() {
            message.set(Some((false, "New password is required.".to_string())));
            return;
        }

        spawn(async move {
            changing.set(true);
            message.set(None);

            let payload = json!({
                "owner": owner,
                "name": name,
                "old_password": old_pw,
                "new_password": new_pw,
            });

            let url = build_url(&api_base_val, "/api/set-password");
            match request_json("POST", &url, token_val.as_deref(), Some(payload)).await {
                Ok(value) => {
                    let status = value
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("ok");
                    if status == "error" {
                        let msg = value
                            .get("msg")
                            .and_then(|m| m.as_str())
                            .unwrap_or("Failed to change password.")
                            .to_string();
                        message.set(Some((false, msg)));
                    } else {
                        message.set(Some((true, "Password changed successfully.".to_string())));
                        current_password.set(String::new());
                        new_password.set(String::new());
                        confirm_password.set(String::new());
                    }
                }
                Err(err) => {
                    message.set(Some((false, err)));
                }
            }
            changing.set(false);
        });
    };

    rsx! {
        div { class: "account-section",
            h3 { "Change password" }
            div { class: "account-form",
                div { class: "account-field",
                    label { "Current password" }
                    input {
                        class: "text-input",
                        r#type: if show_passwords() { "text" } else { "password" },
                        value: "{current_password}",
                        oninput: move |evt| current_password.set(evt.value()),
                    }
                }
                div { class: "account-field",
                    label { "New password" }
                    input {
                        class: "text-input",
                        r#type: if show_passwords() { "text" } else { "password" },
                        value: "{new_password}",
                        oninput: move |evt| new_password.set(evt.value()),
                    }
                }
                div { class: "account-field",
                    label { "Confirm new password" }
                    input {
                        class: "text-input",
                        r#type: if show_passwords() { "text" } else { "password" },
                        value: "{confirm_password}",
                        oninput: move |evt| confirm_password.set(evt.value()),
                    }
                    if !passwords_match {
                        div { class: "inline-message error", "Passwords do not match." }
                    }
                }

                div { class: "account-actions",
                    button {
                        class: "ghost-button",
                        onclick: move |_| show_passwords.set(!show_passwords()),
                        if show_passwords() { "Hide passwords" } else { "Show passwords" }
                    }
                }

                if let Some((ok, msg)) = message() {
                    div {
                        class: if ok { "inline-message success" } else { "inline-message error" },
                        "{msg}"
                    }
                }

                div { class: "account-actions",
                    button {
                        class: "primary-button",
                        disabled: changing() || new_password().is_empty() || !passwords_match,
                        onclick: do_change,
                        if changing() { "Changing..." } else { "Change password" }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MFA Section
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum MfaState {
    Loading,
    Disabled,
    SetupQr {
        secret: String,
        qr_data_url: String,
    },
    VerifyCode {
        secret: String,
    },
    Enabled,
    ShowRecoveryCodes {
        codes: Vec<String>,
    },
}

#[component]
fn MfaSection(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
    user_owner: String,
    user_name: String,
) -> Element {
    let mut mfa_state = use_signal(|| MfaState::Loading);
    let mut totp_code = use_signal(String::new);
    let mut message = use_signal(|| None::<(bool, String)>);
    let mut processing = use_signal(|| false);

    // Check MFA status
    {
        let api_base_val = api_base();
        let token_val = token();
        let name = user_name.clone();
        let owner = user_owner.clone();

        use_effect(move || {
            let api_base_val = api_base_val.clone();
            let token_val = token_val.clone();
            let name = name.clone();
            let owner = owner.clone();
            spawn(async move {
                let url = if name.is_empty() {
                    build_url(&api_base_val, "/api/userinfo")
                } else {
                    build_url(&api_base_val, &format!("/api/users/{owner}/{name}"))
                };
                match request_json("GET", &url, token_val.as_deref(), None).await {
                    Ok(value) => {
                        let enabled = value
                            .get("is_mfa_enabled")
                            .or_else(|| value.get("totp_secret").map(|s| {
                                // If there's a secret, MFA is likely enabled
                                if s.as_str().is_some_and(|v| !v.is_empty()) {
                                    &Value::Bool(true)
                                } else {
                                    &Value::Bool(false)
                                }
                            }))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                        if enabled {
                            mfa_state.set(MfaState::Enabled);
                        } else {
                            mfa_state.set(MfaState::Disabled);
                        }
                    }
                    Err(_) => {
                        mfa_state.set(MfaState::Disabled);
                    }
                }
            });
        });
    }

    let do_enable_mfa = move |_| {
        let api_base_val = api_base();
        let token_val = token();
        let owner = user_owner.clone();
        let name = user_name.clone();

        spawn(async move {
            processing.set(true);
            message.set(None);

            let url = build_url(&api_base_val, "/api/mfa/setup");
            let payload = json!({
                "owner": owner,
                "name": name,
                "type": "totp",
            });

            match request_json("POST", &url, token_val.as_deref(), Some(payload)).await {
                Ok(value) => {
                    let secret = value
                        .get("secret")
                        .or_else(|| value.get("totp_secret"))
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();

                    let qr = value
                        .get("qr_code")
                        .or_else(|| value.get("qr"))
                        .or_else(|| value.get("data_url"))
                        .and_then(|q| q.as_str())
                        .unwrap_or("")
                        .to_string();

                    if !secret.is_empty() {
                        mfa_state.set(MfaState::SetupQr {
                            secret: secret.clone(),
                            qr_data_url: qr,
                        });
                    } else {
                        message.set(Some((false, "Failed to initialize MFA setup.".to_string())));
                    }
                }
                Err(err) => {
                    message.set(Some((false, err)));
                }
            }
            processing.set(false);
        });
    };

    let do_verify_totp = move |_| {
        let api_base_val = api_base();
        let token_val = token();
        let owner = user_owner.clone();
        let name = user_name.clone();
        let code = totp_code();

        let secret = match mfa_state() {
            MfaState::SetupQr { ref secret, .. } | MfaState::VerifyCode { ref secret } => secret.clone(),
            _ => String::new(),
        };

        if code.trim().is_empty() {
            message.set(Some((false, "Please enter the verification code.".to_string())));
            return;
        }

        spawn(async move {
            processing.set(true);
            message.set(None);

            let url = build_url(&api_base_val, "/api/mfa/enable");
            let payload = json!({
                "owner": owner,
                "name": name,
                "type": "totp",
                "secret": secret,
                "passcode": code.trim(),
            });

            match request_json("POST", &url, token_val.as_deref(), Some(payload)).await {
                Ok(value) => {
                    // Check for recovery codes in the response
                    let codes: Vec<String> = value
                        .get("recovery_codes")
                        .and_then(|c| c.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    if codes.is_empty() {
                        mfa_state.set(MfaState::Enabled);
                        message.set(Some((true, "MFA enabled successfully.".to_string())));
                    } else {
                        mfa_state.set(MfaState::ShowRecoveryCodes { codes });
                    }
                    totp_code.set(String::new());
                }
                Err(err) => {
                    message.set(Some((false, err)));
                }
            }
            processing.set(false);
        });
    };

    let do_disable_mfa = move |_| {
        let api_base_val = api_base();
        let token_val = token();
        let owner = user_owner.clone();
        let name = user_name.clone();

        spawn(async move {
            processing.set(true);
            message.set(None);

            let url = build_url(&api_base_val, "/api/mfa/disable");
            let payload = json!({
                "owner": owner,
                "name": name,
                "type": "totp",
            });

            match request_json("POST", &url, token_val.as_deref(), Some(payload)).await {
                Ok(_) => {
                    mfa_state.set(MfaState::Disabled);
                    message.set(Some((true, "MFA disabled.".to_string())));
                }
                Err(err) => {
                    message.set(Some((false, err)));
                }
            }
            processing.set(false);
        });
    };

    rsx! {
        div { class: "account-section",
            h3 { "Multi-factor authentication" }

            match mfa_state() {
                MfaState::Loading => {
                    rsx! { div { class: "inline-message neutral", "Checking MFA status..." } }
                }
                MfaState::Disabled => {
                    rsx! {
                        div { class: "mfa-status mfa-disabled", "MFA is not enabled." }
                        div { class: "account-actions",
                            button {
                                class: "primary-button",
                                disabled: processing(),
                                onclick: do_enable_mfa,
                                if processing() { "Setting up..." } else { "Enable MFA" }
                            }
                        }
                    }
                }
                MfaState::SetupQr { ref secret, ref qr_data_url } => {
                    let sec = secret.clone();
                    let qr = qr_data_url.clone();
                    rsx! {
                        div { class: "mfa-setup",
                            p { "Scan this QR code with your authenticator app:" }

                            QrCode {
                                data_url: qr,
                                label: sec.clone(),
                                size: 200,
                            }

                            div { class: "account-field",
                                label { "Verification code" }
                                input {
                                    class: "text-input",
                                    r#type: "text",
                                    placeholder: "Enter 6-digit code",
                                    value: "{totp_code}",
                                    oninput: move |evt| totp_code.set(evt.value()),
                                    onkeypress: move |evt: KeyboardEvent| {
                                        if evt.key() == Key::Enter {
                                            do_verify_totp(());
                                        }
                                    },
                                }
                            }

                            div { class: "account-actions",
                                button {
                                    class: "primary-button",
                                    disabled: processing() || totp_code().trim().is_empty(),
                                    onclick: do_verify_totp,
                                    if processing() { "Verifying..." } else { "Verify and enable" }
                                }
                                button {
                                    class: "ghost-button",
                                    onclick: move |_| mfa_state.set(MfaState::Disabled),
                                    "Cancel"
                                }
                            }
                        }
                    }
                }
                MfaState::VerifyCode { .. } => {
                    rsx! {
                        div { class: "mfa-setup",
                            div { class: "account-field",
                                label { "Verification code" }
                                input {
                                    class: "text-input",
                                    r#type: "text",
                                    placeholder: "Enter 6-digit code",
                                    value: "{totp_code}",
                                    oninput: move |evt| totp_code.set(evt.value()),
                                }
                            }
                            div { class: "account-actions",
                                button {
                                    class: "primary-button",
                                    disabled: processing(),
                                    onclick: do_verify_totp,
                                    "Verify and enable"
                                }
                            }
                        }
                    }
                }
                MfaState::Enabled => {
                    rsx! {
                        div { class: "mfa-status mfa-enabled", "MFA is enabled." }
                        div { class: "account-actions",
                            button {
                                class: "danger-button",
                                disabled: processing(),
                                onclick: do_disable_mfa,
                                if processing() { "Disabling..." } else { "Disable MFA" }
                            }
                        }
                    }
                }
                MfaState::ShowRecoveryCodes { ref codes } => {
                    let c = codes.clone();
                    rsx! {
                        div { class: "mfa-status mfa-enabled", "MFA enabled successfully!" }
                        p { "Save these recovery codes in a secure place. Each code can only be used once." }
                        div { class: "recovery-codes",
                            {c.iter().map(|code| {
                                rsx! {
                                    div { class: "recovery-code", key: "{code}", "{code}" }
                                }
                            })}
                        }
                        div { class: "account-actions",
                            button {
                                class: "primary-button",
                                onclick: move |_| mfa_state.set(MfaState::Enabled),
                                "I have saved my recovery codes"
                            }
                        }
                    }
                }
            }

            if let Some((ok, msg)) = message() {
                div {
                    class: if ok { "inline-message success" } else { "inline-message error" },
                    "{msg}"
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// WebAuthn Section
// ---------------------------------------------------------------------------

#[component]
fn WebAuthnSection(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
    user_owner: String,
    user_name: String,
) -> Element {
    let mut credentials = use_signal(Vec::<WebAuthnCredential>::new);
    let mut loading = use_signal(|| false);
    let mut cred_name = use_signal(String::new);
    let mut registering = use_signal(|| false);
    let mut message = use_signal(|| None::<(bool, String)>);
    let mut refresh_nonce = use_signal(|| 0_u64);

    // Fetch credentials
    {
        let api_base_val = api_base();
        let token_val = token();
        let owner = user_owner.clone();
        let name = user_name.clone();
        let _nonce = refresh_nonce();

        use_effect(move || {
            let api_base_val = api_base_val.clone();
            let token_val = token_val.clone();
            let owner = owner.clone();
            let name = name.clone();
            loading.set(true);
            spawn(async move {
                let url = build_url(
                    &api_base_val,
                    &format!("/api/webauthn/credentials/{owner}/{name}"),
                );
                match request_json("GET", &url, token_val.as_deref(), None).await {
                    Ok(value) => {
                        let list = extract_collection(value);
                        let creds: Vec<WebAuthnCredential> = list
                            .into_iter()
                            .filter_map(|v| serde_json::from_value(v).ok())
                            .collect();
                        credentials.set(creds);
                    }
                    Err(_) => {
                        credentials.set(Vec::new());
                    }
                }
                loading.set(false);
            });
        });
    }

    let do_register = move |_| {
        let api_base_val = api_base();
        let token_val = token();
        let owner = user_owner.clone();
        let name = user_name.clone();
        let cn = cred_name();

        spawn(async move {
            registering.set(true);
            message.set(None);

            // Step 1: Get registration options from server
            let url = build_url(
                &api_base_val,
                &format!("/api/webauthn/register/begin/{owner}/{name}"),
            );
            let payload = if cn.is_empty() {
                json!({})
            } else {
                json!({ "name": cn })
            };

            match request_json("POST", &url, token_val.as_deref(), Some(payload)).await {
                Ok(value) => {
                    // In a full implementation, we would call the WebAuthn browser API here.
                    // navigator.credentials.create(value) and then POST the result.
                    // For now, display an informative message.
                    message.set(Some((true,
                        "WebAuthn registration initiated. Browser credential API integration is required for the final step.".to_string()
                    )));
                    let _ = value; // Options returned by server
                }
                Err(err) => {
                    message.set(Some((false, err)));
                }
            }

            registering.set(false);
        });
    };

    let do_remove = move |cred_id: String| {
        let api_base_val = api_base();
        let token_val = token();
        let owner = user_owner.clone();
        let name = user_name.clone();

        spawn(async move {
            message.set(None);
            let url = build_url(
                &api_base_val,
                &format!("/api/webauthn/credentials/{owner}/{name}/{cred_id}"),
            );
            match request_json("DELETE", &url, token_val.as_deref(), None).await {
                Ok(_) => {
                    message.set(Some((true, "Credential removed.".to_string())));
                    refresh_nonce.set(refresh_nonce() + 1);
                }
                Err(err) => {
                    message.set(Some((false, err)));
                }
            }
        });
    };

    rsx! {
        div { class: "account-section",
            h3 { "WebAuthn / Passkeys" }

            // Register new credential
            div { class: "account-form",
                div { class: "account-field",
                    label { "Credential name" }
                    input {
                        class: "text-input",
                        placeholder: "e.g. MacBook Touch ID",
                        value: "{cred_name}",
                        oninput: move |evt| cred_name.set(evt.value()),
                    }
                }
                div { class: "account-actions",
                    button {
                        class: "primary-button",
                        disabled: registering(),
                        onclick: do_register,
                        if registering() { "Registering..." } else { "Register new credential" }
                    }
                }
            }

            if let Some((ok, msg)) = message() {
                div {
                    class: if ok { "inline-message success" } else { "inline-message error" },
                    "{msg}"
                }
            }

            // Existing credentials
            if loading() {
                div { class: "inline-message neutral", "Loading credentials..." }
            } else if credentials().is_empty() {
                div { class: "inline-message neutral", "No credentials registered." }
            } else {
                div { class: "webauthn-list",
                    {credentials().iter().map(|cred| {
                        let id = cred.id.clone();
                        let name = cred.name.clone().unwrap_or_else(|| "Unnamed credential".to_string());
                        let created = cred.created_time.clone().unwrap_or_else(|| "Unknown".to_string());
                        let remove_id = id.clone();

                        rsx! {
                            div { class: "webauthn-item", key: "{id}",
                                div { class: "webauthn-item-info",
                                    h4 { "{name}" }
                                    p { "Registered: {created}" }
                                }
                                button {
                                    class: "danger-button",
                                    onclick: move |_| do_remove(remove_id.clone()),
                                    "Remove"
                                }
                            }
                        }
                    })}
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sessions Section
// ---------------------------------------------------------------------------

#[component]
fn SessionsSection(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
    user_owner: String,
    user_name: String,
) -> Element {
    let mut sessions = use_signal(Vec::<SessionInfo>::new);
    let mut loading = use_signal(|| false);
    let mut message = use_signal(|| None::<(bool, String)>);
    let mut refresh_nonce = use_signal(|| 0_u64);

    // Fetch sessions
    {
        let api_base_val = api_base();
        let token_val = token();
        let _nonce = refresh_nonce();
        use_effect(move || {
            let api_base_val = api_base_val.clone();
            let token_val = token_val.clone();
            loading.set(true);
            spawn(async move {
                let url = build_url(&api_base_val, "/api/sessions");
                match request_json("GET", &url, token_val.as_deref(), None).await {
                    Ok(value) => {
                        let list = extract_collection(value);
                        let sess: Vec<SessionInfo> = list
                            .into_iter()
                            .filter_map(|v| serde_json::from_value(v).ok())
                            .collect();
                        sessions.set(sess);
                    }
                    Err(err) => {
                        message.set(Some((false, err)));
                    }
                }
                loading.set(false);
            });
        });
    }

    let do_revoke = move |session_id: String| {
        let api_base_val = api_base();
        let token_val = token();

        spawn(async move {
            message.set(None);
            let url = build_url(&api_base_val, &format!("/api/sessions/{session_id}"));
            match request_json("DELETE", &url, token_val.as_deref(), None).await {
                Ok(_) => {
                    message.set(Some((true, "Session revoked.".to_string())));
                    refresh_nonce.set(refresh_nonce() + 1);
                }
                Err(err) => {
                    message.set(Some((false, err)));
                }
            }
        });
    };

    let do_revoke_all = move |_| {
        let api_base_val = api_base();
        let token_val = token();

        spawn(async move {
            message.set(None);
            let url = build_url(&api_base_val, "/api/sessions/revoke-all");
            match request_json("POST", &url, token_val.as_deref(), None).await {
                Ok(_) => {
                    message.set(Some((true, "All other sessions revoked.".to_string())));
                    refresh_nonce.set(refresh_nonce() + 1);
                }
                Err(err) => {
                    message.set(Some((false, err)));
                }
            }
        });
    };

    rsx! {
        div { class: "account-section",
            h3 { "Active sessions" }

            if let Some((ok, msg)) = message() {
                div {
                    class: if ok { "inline-message success" } else { "inline-message error" },
                    "{msg}"
                }
            }

            if loading() {
                div { class: "inline-message neutral", "Loading sessions..." }
            } else if sessions().is_empty() {
                div { class: "inline-message neutral", "No active sessions found." }
            } else {
                div { class: "session-list",
                    {sessions().iter().map(|sess| {
                        let id = sess.id.clone();
                        let sid = sess.session_id.clone();
                        let app = sess.application.clone().unwrap_or_else(|| "Unknown".to_string());
                        let created = sess.created_time.clone().unwrap_or_else(|| "Unknown".to_string());
                        let is_current = sess.is_current.unwrap_or(false);
                        let revoke_id = id.clone();

                        rsx! {
                            div {
                                class: if is_current { "session-item current" } else { "session-item" },
                                key: "{id}",
                                div { class: "session-item-info",
                                    h4 { "{app}" }
                                    p { "Session: {sid}" }
                                    p { "Started: {created}" }
                                }
                                if is_current {
                                    span { class: "session-tag", "Current" }
                                } else {
                                    button {
                                        class: "danger-button",
                                        onclick: move |_| do_revoke(revoke_id.clone()),
                                        "Revoke"
                                    }
                                }
                            }
                        }
                    })}
                }

                if sessions().len() > 1 {
                    div { class: "account-actions",
                        button {
                            class: "danger-button",
                            onclick: do_revoke_all,
                            "Revoke all other sessions"
                        }
                    }
                }
            }
        }
    }
}
