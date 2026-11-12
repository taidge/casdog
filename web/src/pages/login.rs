use crate::{
    AppState,
    api::{self, LoginOutcome},
    ui::*,
};
use glory::prelude::*;
use serde_json::{Value, json};

fn accept(
    app: AppState,
    value: Value,
    mode: Cage<String>,
    methods: Cage<Vec<String>>,
    method: Cage<String>,
    password_value: Cage<String>,
) -> std::result::Result<String, String> {
    match api::parse_login_response(value.clone())? {
        LoginOutcome::Challenge(choices) => {
            password_value.set(String::new());
            method.set(choices.first().cloned().unwrap_or_default());
            methods.set(choices.clone());
            if mode.get().is_empty() {
                mode.set("password".into());
            }
            if choices.is_empty() {
                Err(
                    "No supported verification method is enrolled. Contact your administrator."
                        .into(),
                )
            } else {
                Ok("Enter your second-factor code.".into())
            }
        }
        LoginOutcome::Authenticated { .. } => {
            password_value.set(String::new());
            app.signed_in(value)?;
            Ok(String::new())
        }
    }
}
fn session_path(mode: &str) -> &'static str {
    if mode == "social" {
        "/api/auth/session"
    } else {
        "/api/auth/password/session"
    }
}

fn login_context(owner: String, name: String, application: String) -> Value {
    let mut body = json!({"owner":owner,"name":name,"application":if application.is_empty() { None } else { Some(application) }});
    for (key, alias) in [
        ("clientId", "client_id"),
        ("responseType", "response_type"),
        ("redirectUri", "redirect_uri"),
        ("scope", "scope"),
        ("state", "state"),
        ("nonce", "nonce"),
        ("codeChallenge", "code_challenge"),
        ("codeChallengeMethod", "code_challenge_method"),
    ] {
        let value = query(key);
        let value = if value.is_empty() {
            query(alias)
        } else {
            value
        };
        if !value.is_empty() {
            body[key] = json!(value);
        }
    }
    body
}

pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let _ = scope.retain(crate::webauthn::CancelOnDrop);
        let organization = scope.cage("built-in".to_string());
        let username = scope.cage(String::new());
        let password_value = scope.cage(String::new());
        let primary_method = scope.cage("password".to_string());
        let primary_code = scope.cage(String::new());
        let application = scope.cage(query("application"));
        let mode = scope.cage(String::new());
        let methods = scope.cage(Vec::<String>::new());
        let method = scope.cage("app".to_string());
        let passcode = scope.cage(String::new());
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let providers = scope.cage(Vec::<Value>::new());
        let refresh = scope.clone();
        scope.effect(move || {
            let reference = application.get();
            let reference = if reference.is_empty() {
                "admin/app-built-in".into()
            } else {
                reference
            };
            let path = format!(
                "/api/auth/providers?application={}",
                query_component(&reference)
            );
            let _ = refresh.spawn(async move {
                if let Ok(value) = app.request("GET", &path, None).await {
                    providers.set(api::extract_collection(value));
                }
            });
        });
        let social = query("social") == "complete";
        let _ = scope.spawn(async move {
            let route = if social {
                "/api/auth/session"
            } else {
                "/api/auth/password/session"
            };
            match app.request("POST", route, Some(json!({}))).await {
                Ok(value) if value.get("pending").and_then(Value::as_bool) != Some(false) => {
                    if social {
                        mode.set("social".into());
                    }
                    message.set(
                        accept(app, value, mode, methods, method, password_value)
                            .unwrap_or_else(|e| e),
                    );
                }
                Err(error) if social => {
                    mode.set(String::new());
                    message.set(error);
                }
                _ => {}
            }
        });
        if social {
            clear_social_marker();
        }
        let credentials = when(scope.bond(move || mode.get().is_empty()), move || {
            widget(move |scope| {
                stack((
                    field(scope, "Organization", organization),
                    field(scope, "Username", username),
                    sapid::native_select("sign-in-method")
                        .name("Sign-in method")
                        .value(scope.bond(move || Some(primary_method.get())))
                        .options(
                            [
                                ("password", "Password"),
                                ("ldap", "LDAP"),
                                ("email", "Email code"),
                                ("sms", "SMS code"),
                            ]
                            .into_iter()
                            .map(|(value, label)| sapid::select_option(value, label)),
                        )
                        .on_value_change(move |value| {
                            primary_method.set(value.unwrap_or_else(|| "password".into()));
                            password_value.set(String::new());
                            primary_code.set(String::new());
                        }),
                    when(
                        scope.bond(move || {
                            matches!(primary_method.get().as_str(), "password" | "ldap")
                        }),
                        move || password("Password", password_value),
                    ),
                    when(
                        scope
                            .bond(move || matches!(primary_method.get().as_str(), "email" | "sms")),
                        move || {
                            widget(move |scope| {
                                stack((
                                    field(scope, "Sign-in code", primary_code),
                                    action(
                                        scope,
                                        "Send sign-in code",
                                        busy,
                                        message,
                                        move || async move {
                                            if username.get().trim().is_empty() {
                                                return Err(
                                                    "Enter your username or enrolled contact."
                                                        .into(),
                                                );
                                            }
                                            let reference = application.get();
                                            let reference = if reference.is_empty() {
                                                "admin/app-built-in".into()
                                            } else {
                                                reference
                                            };
                                            let mut body = login_context(
                                                organization.get(),
                                                username.get(),
                                                reference,
                                            );
                                            body["method"] = json!(primary_method.get());
                                            app.request("POST", "/api/auth/code/start", Some(body))
                                                .await?;
                                            primary_code.set(String::new());
                                            Ok("Sign-in code sent to your enrolled contact.".into())
                                        },
                                    ),
                                ))
                                .build(scope)
                            })
                        },
                    ),
                    field(scope, "Application", application),
                ))
                .build(scope)
            })
        });
        let challenge = when(scope.bond(move || !mode.get().is_empty()), move || {
            widget(move |scope| {
                let choices = methods.get().into_iter().map(|s| (s.clone(), s)).collect();
                stack((
                    select(scope, "Verification method", method, choices),
                    field(scope, "Verification code", passcode),
                    action(
                        scope,
                        "Send verification code",
                        busy,
                        message,
                        move || async move {
                            if !matches!(method.get().as_str(), "email" | "sms") {
                                return Err("Select email or sms to send a code.".into());
                            }
                            app.request(
                                "POST",
                                &format!("{}/send-code", session_path(&mode.get())),
                                Some(json!({
                                    "mfaType": method.get(),
                                })),
                            )
                            .await?;
                            Ok("Verification code sent to your enrolled contact.".into())
                        },
                    ),
                    action(
                        scope,
                        "Cancel verification",
                        busy,
                        message,
                        move || async move {
                            app.request(
                                "POST",
                                &format!("{}/cancel", session_path(&mode.get())),
                                Some(json!({})),
                            )
                            .await?;
                            mode.set(String::new());
                            methods.set(Vec::new());
                            passcode.set(String::new());
                            Ok("Verification canceled.".into())
                        },
                    ),
                ))
                .build(scope)
            })
        });
        let social_buttons = each(providers)
            .key(|v| v["name"].as_str().unwrap_or_default().to_string())
            .seed(move |provider| {
                widget(move |scope| {
                    let name = provider["name"].as_str().unwrap_or_default().to_string();
                    let title = format!(
                        "Sign in with {}",
                        provider["display_name"].as_str().unwrap_or(&name)
                    );
                    action(scope, &title, busy, message, move || {
                        let path = format!(
                            "/api/auth/{}?application={}",
                            query_component(&name),
                            query_component(&{
                                let v = application.get();
                                if v.is_empty() {
                                    "admin/app-built-in".into()
                                } else {
                                    v
                                }
                            })
                        );
                        async move {
                            let value = app.request("GET", &path, None).await?;
                            redirect(value["url"].as_str().ok_or("Provider URL missing")?)?;
                            Ok(String::new())
                        }
                    })
                    .build(scope)
                })
            });
        stack((
            heading("Sign in"),
            credentials,
            challenge,
            notice(message),
            action(scope, "Sign in", busy, message, move || async move {
                let current = mode.get();
                let (route, payload) = if current.is_empty() {
                    let chosen = primary_method.get();
                    let code_login = matches!(chosen.as_str(), "email" | "sms");
                    if username.get().trim().is_empty()
                        || (if code_login {
                            primary_code.get().is_empty()
                        } else {
                            password_value.get().is_empty()
                        })
                    {
                        return Err(if code_login {
                            "Enter your username and sign-in code."
                        } else {
                            "Enter your username and password."
                        }
                        .into());
                    }
                    let reference = application.get();
                    let reference = if chosen != "password" && reference.is_empty() {
                        "admin/app-built-in".into()
                    } else {
                        reference
                    };
                    let mut body = login_context(organization.get(), username.get(), reference);
                    body["type"] = json!(if code_login { "code" } else { chosen.as_str() });
                    if code_login {
                        body["code"] = json!(primary_code.get());
                        body["codeMethod"] = json!(primary_method.get());
                    } else {
                        body["password"] = json!(password_value.get());
                    }
                    ("/api/login", body)
                } else {
                    (
                        session_path(&current),
                        json!({
                            "mfaType": method.get(),
                            "passcode": passcode.get(),
                        }),
                    )
                };
                let value = app.request("POST", route, Some(payload)).await?;
                primary_code.set(String::new());
                passcode.set(String::new());
                accept(app, value, mode, methods, method, password_value)
            }),
            when(scope.bond(move || mode.get().is_empty()), move || {
                widget(move |scope| {
                    action(
                        scope,
                        "Sign in with passkey",
                        busy,
                        message,
                        move || async move {
                            if username.get().trim().is_empty() {
                                return Err("Enter your username before using a passkey.".into());
                            }
                            let mut path = format!(
                                "/api/webauthn/signin/begin?owner={}&name={}",
                                query_component(&organization.get()),
                                query_component(username.get().trim())
                            );
                            if !application.get().trim().is_empty() {
                                path.push_str(&format!(
                                    "&application={}",
                                    query_component(application.get().trim())
                                ));
                            }
                            let begin = app.request("GET", &path, None).await?;
                            let request_id = begin["requestId"]
                                .as_str()
                                .ok_or("Sign-in request ID missing")?;
                            let options = begin
                                .get("options")
                                .cloned()
                                .ok_or("Sign-in options missing")?;
                            let credential = crate::webauthn::authenticate(options).await?;
                            let value = app
                                .request(
                                    "POST",
                                    &format!(
                                        "/api/webauthn/signin/finish?requestId={}",
                                        query_component(request_id)
                                    ),
                                    Some(credential),
                                )
                                .await?;
                            accept(app, value, mode, methods, method, password_value)
                        },
                    )
                    .build(scope)
                })
            }),
            sapid::button()
                .label("Cancel passkey request")
                .enabled(busy)
                .on_press(crate::webauthn::cancel),
            social_buttons,
            sapid::button()
                .label("Create account")
                .on_press(move || app.navigate("signup-page")),
            sapid::button()
                .label("Forgot password")
                .on_press(move || app.navigate("forgot-password-page")),
        ))
        .class("login-box")
        .build(scope)
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oauth_query_values_cannot_escape_their_parameter() {
        assert_eq!(query_component("a&b=c #"), "a%26b%3Dc%20%23");
    }
}
