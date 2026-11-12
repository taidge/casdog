mod api;
mod branding;
mod components;
mod i18n;
mod pages;
mod resources;
mod style;
mod ui;
mod webauthn;

use gloo_storage::{LocalStorage, Storage};
use glory::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::result::Result;
use ui::*;

const AUTH_TOKEN_KEY: &str = "casdog.auth.token";
const ACCOUNT_KEY: &str = "casdog.auth.account";
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountSummary {
    pub owner: String,
    pub name: String,
    pub display_name: Option<String>,
    pub is_admin: bool,
}
#[derive(Clone, Copy)]
pub struct AppState {
    pub api_base: Cage<String>,
    pub token: Cage<Option<String>>,
    pub account: Cage<Option<AccountSummary>>,
    pub panel: Cage<String>,
    pub locale: Cage<i18n::Locale>,
}
impl AppState {
    pub async fn request(self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        api::request_json(method, &api::build_url(&self.api_base.get(), path), self.token.get().as_deref(), body).await
    }
    pub fn navigate(self, page: &str) {
        self.panel.set(page.to_string());
    }
    pub fn signed_in(self, value: Value) -> Result<(), String> {
        match api::parse_login_response(value)? {
            api::LoginOutcome::Authenticated {
                token,
                user,
                password_expired,
            } => {
                let account: AccountSummary = serde_json::from_value(user).map_err(|e| e.to_string())?;
                LocalStorage::set(AUTH_TOKEN_KEY, &token).map_err(|e| e.to_string())?;
                LocalStorage::set(ACCOUNT_KEY, &account).map_err(|e| e.to_string())?;
                self.token.set(Some(token));
                self.account.set(Some(account));
                self.navigate(if password_expired {
                    "password-change-page"
                } else {
                    "dashboard"
                });
                Ok(())
            }
            api::LoginOutcome::Challenge(_) => Err("Complete the second factor first".into()),
        }
    }
    pub fn clear_session(self) {
        LocalStorage::delete(AUTH_TOKEN_KEY);
        LocalStorage::delete(ACCOUNT_KEY);
        self.token.set(None);
        self.account.set(None);
        self.navigate("login-page");
    }
}
fn application() -> impl Widget {
    widget(|scope| {
        let social = query("social");
        let app = AppState {
            api_base: scope.cage(option_env!("CASDOG_API_BASE").unwrap_or("").to_string()),
            token: scope.cage(LocalStorage::get(AUTH_TOKEN_KEY).ok()),
            account: scope.cage(LocalStorage::get(ACCOUNT_KEY).ok()),
            panel: scope.cage(
                match social.as_str() {
                    "complete" => "login-page",
                    "linked" => "account-page",
                    _ if !query("user_code").is_empty() => "device-auth-page",
                    _ => "dashboard",
                }
                .to_string(),
            ),
            locale: scope.cage(
                LocalStorage::get::<String>("casdog.locale")
                    .ok()
                    .and_then(|s| i18n::Locale::from_code(&s))
                    .unwrap_or(i18n::Locale::En),
            ),
        };
        let pages =
            each(scope.bond(move || vec![app.panel.get()])).key(|page| page.clone()).seed(move |page| {
                match page.as_str() {
                    "login-page" => pages::login::page(app),
                    "signup-page" => pages::signup::page(app),
                    "forgot-password-page" => pages::forgot_password::page(app),
                    "account-page" | "password-change-page" => pages::account::page(app),
                    "authorize-page" => pages::authorize::page(app),
                    "consent-page" => pages::consent::page(app),
                    "device-auth-page" => pages::device_auth::page(app),
                    "result-page" => pages::result::page(app),
                    "marketplace-page" => pages::marketplace::page(app),
                    "keys-page" => pages::keys::page(app),
                    "store-page" => pages::store::page(app),
                    "settings-page" => pages::settings::page(app),
                    "telemetry-page" => pages::telemetry::page(app),
                    "user-import-page" => pages::user_import::page(app),
                    "dashboard" => dashboard(app),
                    slug => match resources::resource_config(slug) {
                        Some(config) => pages::resource::page(app, config),
                        None => boxed(label("Unknown page")),
                    },
                }
            });
        glory::ui::view().class("shell").fill((sidebar(app), glory::ui::view().class("main").fill(pages))).build(scope)
    })
}
fn sidebar(app: AppState) -> impl Widget {
    widget(move |scope| {
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let mut navigation: Vec<Element> = vec![
            boxed(text().kind(TextKind::Heading(1)).content("Casdog")),
            boxed(field(scope, "API base", app.api_base)),
        ];
        navigation.push(boxed(text().content_fn(move || {
            app.account.get().map(|a| format!("{}/{}", a.owner, a.name)).unwrap_or("Guest".into())
        })));
        navigation.push(boxed(
            sapid::native_select("language")
                .name("Language")
                .value(scope.bond(move || Some(app.locale.get().code().to_string())))
                .options(i18n::Locale::all().iter().map(|l| sapid::select_option(l.code(), l.label())))
                .on_value_change(move |value| {
                    if let Some(locale) = value.and_then(|v| i18n::Locale::from_code(&v)) {
                        app.locale.set(locale);
                        let _ = LocalStorage::set("casdog.locale", locale.code());
                    }
                }),
        ));
        for (slug, _name) in [
            ("dashboard", "Dashboard"),
            ("login-page", "Sign in"),
            ("signup-page", "Sign up"),
            ("account-page", "Account"),
            ("forgot-password-page", "Recover password"),
            ("authorize-page", "Authorize"),
            ("consent-page", "Consents"),
            ("device-auth-page", "Device authorization"),
            ("result-page", "Result"),
            ("marketplace-page", "Marketplace"),
            ("keys-page", "API keys"),
            ("store-page", "Store"),
            ("settings-page", "Site settings"),
            ("telemetry-page", "Telemetry"),
            ("user-import-page", "Restore users and MFA"),
        ] {
            navigation.push(boxed(
                sapid::button()
                    .label(scope.bond(move || {
                        i18n::t(
                            match slug {
                                "dashboard" => "nav.dashboard",
                                "login-page" => "page.login",
                                "signup-page" => "page.signup",
                                "account-page" => "page.account",
                                "forgot-password-page" => "page.forgot_password",
                                "authorize-page" => "page.authorize",
                                "consent-page" => "page.consent",
                                "device-auth-page" => "page.device_auth",
                                "marketplace-page" => "page.marketplace",
                                "keys-page" => "page.keys",
                                "store-page" => "page.store",
                                "settings-page" => "page.settings",
                                "telemetry-page" => "page.telemetry",
                                "user-import-page" => "page.user_import",
                                _ => "page.result",
                            },
                            app.locale.get(),
                        )
                        .to_string()
                    }))
                    .variant(sapid::ButtonVariant::Subtle)
                    .on_press(move || app.navigate(slug)),
            ));
        }
        for group in resources::GROUP_ORDER {
            navigation.push(boxed(label(group)));
            for config in resources::RESOURCES.iter().filter(|c| c.group == *group) {
                navigation.push(boxed(
                    sapid::button()
                        .label(config.label)
                        .variant(sapid::ButtonVariant::Subtle)
                        .on_press(move || app.navigate(config.slug)),
                ));
            }
        }
        navigation.push(boxed(when(scope.bond(move || app.token.get().is_some()), move || {
            widget(move |scope| {
                action(scope, "Sign out", busy, message, move || async move {
                    app.request("POST", "/api/logout", Some(serde_json::json!({}))).await?;
                    app.clear_session();
                    Ok(String::new())
                })
                .build(scope)
            })
        })));
        navigation.push(boxed(notice(message)));
        glory::ui::col().class("sidebar").fill(navigation).build(scope)
    })
}
fn dashboard(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let health = scope.cage("Checking /api/health".to_string());
        let _ = scope.spawn(async move {
            health.set(match app.request("GET", "/api/health", None).await {
                Ok(v) => api::pretty_json(&v),
                Err(e) => e,
            });
        });
        stack((
            heading("Identity and access management"),
            label("Manage organizations, applications, users, access policies and authentication."),
            notice(health),
        ))
        .build(scope)
    }))
}
#[cfg(target_arch = "wasm32")]
fn main() {
    let document = web_sys::window().unwrap().document().unwrap();
    let theme = sapid::Theme::from_default(&sapid::BLUE).expect("Sapid theme");
    let styles = document.create_element("style").unwrap();
    styles.set_text_content(Some(&format!(
        "{}\n{}\n{}",
        theme.stylesheet().unwrap(),
        style::APP_CSS,
        include_str!("../assets/app.css")
    )));
    document.head().unwrap().append_child(&styles).unwrap();
    let root = document.get_element_by_id("app").expect("#app root");
    let app = glory::web::launch(root, application()).expect("Mount Glory application");
    APP.with(|current| *current.borrow_mut() = Some(app));
}
#[cfg(target_arch = "wasm32")]
thread_local! { static APP: std::cell::RefCell<Option<glory::web::WebApp>> = const {std::cell::RefCell::new(None)}; }
#[cfg(not(target_arch = "wasm32"))]
fn main() {
    println!("Build this frontend with trunk serve or trunk build.");
}
