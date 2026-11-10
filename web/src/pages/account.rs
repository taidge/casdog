use crate::{AppState, api, ui::*};
use gloo_storage::{SessionStorage, Storage};
use glory::prelude::*;
use serde_json::{Value, json};

pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let linked = query("social") == "linked";
        if linked {
            clear_social_marker();
        }
        let tab = scope.cage(
            if app.panel.get() == "password-change-page" {
                "security"
            } else if linked {
                "social"
            } else {
                "profile"
            }
            .to_string(),
        );
        let tabs: Vec<Element> = [
            ("profile", "Profile"),
            ("contacts", "Email and phone"),
            ("security", "Security"),
            ("mfa", "MFA"),
            ("webauthn", "WebAuthn"),
            ("social", "Linked accounts"),
            ("sessions", "Sessions"),
        ]
        .into_iter()
        .map(|(key, title)| boxed(sapid::button().label(title).on_press(move || tab.set(key.into()))))
        .collect();
        stack((
            heading("Account settings"),
            glory::ui::row().class("account-tabs").fill(tabs),
            when(scope.bond(move || app.token.get().is_some()), move || boxed(content_placeholder(app, tab)))
                .otherwise(move || {
                    boxed(
                        sapid::button()
                            .label("Sign in to manage your account")
                            .on_press(move || app.navigate("login-page")),
                    )
                }),
        ))
        .build(scope)
    }))
}
// A keyed page owns its form state and outstanding requests until the tab changes.
fn content_placeholder(app: AppState, tab: Cage<String>) -> impl Widget {
    widget(move |scope| {
        each(scope.bond(move || vec![tab.get()]))
            .key(|tab| tab.clone())
            .seed(move |tab| match tab.as_str() {
                "security" => security(app),
                "contacts" => contacts(app),
                "mfa" => mfa(app),
                "social" => social(app),
                "sessions" => sessions(app),
                "webauthn" => webauthn(app),
                _ => profile(app),
            })
            .build(scope)
    })
}
fn identity(app: AppState) -> (String, String) {
    app.account.get().map(|a| (a.owner, a.name)).unwrap_or_default()
}
fn contacts(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let kind = scope.cage("email".to_string());
        let destination = scope.cage(String::new());
        let application = scope.cage("admin/app-built-in".to_string());
        let code = scope.cage(String::new());
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        stack((
            heading("Update email or phone"),
            select(
                scope,
                "Contact type",
                kind,
                vec![("email".into(), "Email".into()), ("phone".into(), "Phone".into())],
            ),
            field(scope, "New contact", destination),
            field(scope, "Application", application),
            action(scope, "Send contact code", busy, message, move || async move {
                app.request(
                    "POST",
                    "/api/send-verification-code",
                    Some(json!({
                        "type": kind.get(),
                        "dest": destination.get(),
                        "application": application.get(),
                        "method": "contact",
                    })),
                )
                .await?;
                Ok("Verification code sent to your new contact.".into())
            }),
            field(scope, "Contact verification code", code),
            action(scope, "Verify and update contact", busy, message, move || async move {
                app.request(
                    "POST",
                    "/api/reset-email-or-phone",
                    Some(json!({
                        "type": kind.get(),
                        "dest": destination.get(),
                        "code": code.get().trim(),
                    })),
                )
                .await?;
                code.set(String::new());
                Ok("Contact updated.".into())
            }),
            notice(message),
        ))
        .build(scope)
    }))
}
fn profile(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let data = scope.cage(json!({}));
        let display = scope.cage(String::new());
        let avatar = scope.cage(String::new());
        let bio = scope.cage(String::new());
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let _ = scope.spawn(async move {
            match app.request("GET", "/api/get-account", None).await {
                Ok(value) => {
                    display.set(value["display_name"].as_str().unwrap_or_default().into());
                    avatar.set(value["avatar"].as_str().unwrap_or_default().into());
                    bio.set(value["bio"].as_str().unwrap_or_default().into());
                    data.set(value);
                }
                Err(error) => message.set(error),
            }
        });
        stack((
            heading("Profile"),
            text().content_fn(move || {
                format!(
                    "{} / {}",
                    data.get()["owner"].as_str().unwrap_or_default(),
                    data.get()["name"].as_str().unwrap_or_default()
                )
            }),
            field(scope, "Display name", display),
            field(scope, "Avatar URL", avatar),
            field(scope, "Bio", bio),
            text().content_fn(move || {
                format!(
                    "Email: {} · Phone: {}",
                    data.get()["email"].as_str().unwrap_or_default(),
                    data.get()["phone"].as_str().unwrap_or_default()
                )
            }),
            action(scope, "Save profile", busy, message, move || async move {
                let id = data.get()["id"].as_str().ok_or("Account ID unavailable")?.to_string();
                app.request(
                    "PUT",
                    &format!("/api/users/{}", query_component(&id)),
                    Some(json!({
                        "display_name": display.get(),
                        "avatar": avatar.get(),
                        "bio": bio.get(),
                    })),
                )
                .await?;
                if let Some(mut account) = app.account.get() {
                    account.display_name = Some(display.get());
                    app.account.set(Some(account.clone()));
                    let _ = gloo_storage::LocalStorage::set(crate::ACCOUNT_KEY, account);
                }
                Ok("Profile saved.".into())
            }),
            notice(message),
        ))
        .build(scope)
    }))
}
fn security(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let old = scope.cage(String::new());
        let new = scope.cage(String::new());
        let confirm = scope.cage(String::new());
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        stack((
            heading("Change password"),
            password("Current password", old),
            password("New password", new),
            password("Confirm new password", confirm),
            action(scope, "Change password", busy, message, move || async move {
                if new.get() != confirm.get() {
                    return Err("Passwords do not match.".into());
                }
                let (owner, name) = identity(app);
                app.request(
                    "POST",
                    "/api/set-password",
                    Some(json!({
                        "owner": owner,
                        "name": name,
                        "old_password": old.get(),
                        "new_password": new.get(),
                    })),
                )
                .await?;

                old.set(String::new());
                new.set(String::new());
                confirm.set(String::new());
                app.clear_session();
                Ok("Password changed. Sign in again.".into())
            }),
            notice(message),
        ))
        .build(scope)
    }))
}
fn mfa(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let status = scope.cage("Loading MFA status".to_string());
        let uri = scope.cage(String::new());
        let secret = scope.cage(String::new());
        let code = scope.cage(String::new());
        let recovery = scope.cage(Vec::<String>::new());
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let _ = scope.spawn(async move {
            match app.request("GET", "/api/get-account", None).await {
                Ok(v) => status.set(
                    if v["mfa_enabled"] == true {
                        "MFA enabled"
                    } else {
                        "MFA disabled"
                    }
                    .into(),
                ),
                Err(e) => message.set(e),
            }
        });
        stack((
            heading("Multi-factor authentication"),
            notice(status),
            action(scope, "Set up authenticator", busy, message, move || async move {
                let (owner, name) = identity(app);
                let v = app
                    .request(
                        "POST",
                        "/api/mfa/setup",
                        Some(json!({
                            "owner": owner,
                            "name": name,
                            "mfa_type": "totp",
                        })),
                    )
                    .await?;

                secret.set(
                    v.get("secret")
                        .or_else(|| v.get("totp_secret"))
                        .and_then(Value::as_str)
                        .ok_or("MFA setup secret missing")?
                        .to_string(),
                );

                uri.set(
                    ["qr_url", "qr_code", "qr", "data_url"]
                        .iter()
                        .find_map(|k| v[*k].as_str())
                        .unwrap_or_default()
                        .into(),
                );
                Ok("Scan the QR code, then verify a code before enabling MFA.".into())
            }),
            when(scope.bond(move || !secret.get().is_empty()), move || {
                widget(move |scope| {
                    stack((
                        crate::components::qr_code::code(scope, uri),
                        text().content_fn(move || format!("Setup key: {}", secret.get())),
                        field(scope, "Authenticator code", code),
                        action(scope, "Verify and enable MFA", busy, message, move || async move {
                            let (owner, name) = identity(app);
                            let codes = api::parse_mfa_verification(
                                app.request(
                                    "POST",
                                    "/api/mfa/verify",
                                    Some(json!({
                                        "owner": owner,
                                        "name": name,
                                        "mfa_type": "totp",
                                        "code": code.get().trim(),
                                    })),
                                )
                                .await?,
                            )?;

                            recovery.set(codes);
                            status.set("MFA enabled".into());
                            secret.set(String::new());
                            uri.set(String::new());
                            code.set(String::new());
                            Ok("MFA enabled. Save your one-use recovery codes.".into())
                        }),
                    ))
                    .build(scope)
                })
            }),
            text().class("recovery-codes").content_fn(move || recovery.get().join("\n")),
            action(scope, "Disable authenticator", busy, message, move || async move {
                let (owner, name) = identity(app);
                app.request(
                    "POST",
                    "/api/mfa/delete",
                    Some(json!({
                        "owner": owner,
                        "name": name,
                        "mfa_type": "totp",
                    })),
                )
                .await?;
                status.set("MFA disabled".into());
                secret.set(String::new());
                uri.set(String::new());
                recovery.set(Vec::new());
                Ok("MFA disabled.".into())
            }),
            notice(message),
        ))
        .build(scope)
    }))
}
fn social(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let application =
            scope.cage(SessionStorage::get::<String>("casdog.social.link.application").unwrap_or_default());
        let pass = scope.cage(String::new());
        let links = scope.cage(Vec::<Value>::new());
        let providers = scope.cage(Vec::<Value>::new());
        let refresh = scope.cage(0_u64);
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let owner = scope.clone();
        scope.effect(move || {
            let _ = refresh.get();
            let reference = application.get();
            let path = format!("/api/auth/links?application={}", query_component(&reference));
            let _ = owner.spawn(async move {
                match app.request("GET", &path, None).await {
                    Ok(v) => links.set(api::extract_collection(v)),
                    Err(e) => message.set(e),
                }
            });
        });
        let linked =
            each(links).key(|v| v["provider_id"].as_str().unwrap_or_default().to_string()).seed(move |value| {
                widget(move |scope| {
                    let name = value["provider"].as_str().unwrap_or_default().to_string();
                    let title = format!("Unlink {}", value["display_name"].as_str().unwrap_or(&name));
                    action(scope, &title, busy, message, move || {
                        let path = format!("/api/auth/{}/unlink", query_component(&name));
                        async move {
                            app.request(
                                "POST",
                                &path,
                                Some(json!({
                                    "application": application.get(),
                                    "password": pass.get(),
                                })),
                            )
                            .await?;
                            pass.set(String::new());
                            refresh.set(refresh.get() + 1);
                            Ok("Account unlinked.".into())
                        }
                    })
                    .build(scope)
                })
            });
        let available =
            each(providers).key(|v| v["name"].as_str().unwrap_or_default().to_string()).seed(move |value| {
                widget(move |scope| {
                    let name = value["name"].as_str().unwrap_or_default().to_string();
                    let title = format!("Link {}", value["display_name"].as_str().unwrap_or(&name));
                    action(scope, &title, busy, message, move || {
                        let path = format!("/api/auth/{}/link", query_component(&name));
                        async move {
                            let value = app
                                .request(
                                    "POST",
                                    &path,
                                    Some(json!({
                                        "application": application.get(),
                                    })),
                                )
                                .await?;
                            SessionStorage::set("casdog.social.link.application", application.get())
                                .map_err(|e| e.to_string())?;
                            redirect(value["url"].as_str().ok_or("Provider URL missing")?)?;
                            Ok(String::new())
                        }
                    })
                    .build(scope)
                })
            });
        stack((
            heading("Linked accounts"),
            label("Sign in again before changing links if your session is more than five minutes old."),
            field(scope, "Application", application),
            password("Current password", pass),
            action(scope, "Load sign-in providers", busy, message, move || async move {
                let path = format!("/api/auth/providers?application={}", query_component(&application.get()));
                providers.set(api::extract_collection(app.request("GET", &path, None).await?));
                refresh.set(refresh.get() + 1);
                Ok(String::new())
            }),
            linked,
            available,
            notice(message),
        ))
        .build(scope)
    }))
}
fn sessions(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let rows = scope.cage(Vec::<Value>::new());
        let refresh = scope.cage(0_u64);
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let owner = scope.clone();
        scope.effect(move || {
            let _ = refresh.get();
            let _ = owner.spawn(async move {
                match app.request("GET", "/api/sessions", None).await {
                    Ok(v) => rows.set(api::extract_collection(v)),
                    Err(e) => message.set(e),
                }
            });
        });
        let list = each(rows).key(|v| v["id"].as_str().unwrap_or_default().to_string()).seed(move |value| {
            widget(move |scope| {
                let id = value["id"].as_str().unwrap_or_default().to_string();
                let title = format!("Revoke {}", api::item_title(&value));
                action(scope, &title, busy, message, move || {
                    let path = format!("/api/sessions/{}", query_component(&id));
                    async move {
                        app.request("DELETE", &path, None).await?;
                        refresh.set(refresh.get() + 1);
                        Ok("Session revoked.".into())
                    }
                })
                .build(scope)
            })
        });
        stack((
            heading("Sessions"),
            list,
            action(scope, "Revoke all sessions", busy, message, move || async move {
                app.request("POST", "/api/sessions/revoke-all", Some(json!({}))).await?;
                refresh.set(refresh.get() + 1);
                Ok("Sessions revoked.".into())
            }),
            notice(message),
        ))
        .build(scope)
    }))
}
fn webauthn(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let rows = scope.cage(Vec::<Value>::new());
        let refresh = scope.cage(0_u64);
        let name = scope.cage(String::new());
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let owner = scope.clone();
        scope.effect(move || {
            let _ = refresh.get();
            let (tenant, user) = identity(app);
            let path = format!("/api/webauthn/credentials/{}/{}", query_component(&tenant), query_component(&user));
            let _ = owner.spawn(async move {
                match app.request("GET", &path, None).await {
                    Ok(v) => rows.set(api::extract_collection(v)),
                    Err(e) => message.set(e),
                }
            });
        });
        let list = each(rows).key(|v| v["id"].as_str().unwrap_or_default().to_string()).seed(move |value| {
            widget(move |scope| {
                let id = value["id"].as_str().unwrap_or_default().to_string();
                let title = format!("Remove {}", api::item_title(&value));
                action(scope, &title, busy, message, move || {
                    let (tenant, user) = identity(app);
                    let path = format!(
                        "/api/webauthn/credentials/{}/{}/{}",
                        query_component(&tenant),
                        query_component(&user),
                        query_component(&id)
                    );
                    async move {
                        app.request("DELETE", &path, None).await?;
                        refresh.set(refresh.get() + 1);
                        Ok("Credential removed.".into())
                    }
                })
                .build(scope)
            })
        });
        stack((
            heading("WebAuthn credentials"),
            field(scope, "Credential name", name),
            action(scope, "Begin credential registration", busy, message, move || async move {
                let (tenant, user) = identity(app);
                let path =
                    format!("/api/webauthn/register/begin/{}/{}", query_component(&tenant), query_component(&user));
                app.request(
                    "POST",
                    &path,
                    Some(json!({
                        "name": name.get(),
                    })),
                )
                .await?;
                Ok("Registration initialized. Browser credential creation is required to finish enrollment.".into())
            }),
            list,
            notice(message),
        ))
        .build(scope)
    }))
}
