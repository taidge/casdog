use glory::prelude::*;
use glory::ui::IntoChildren;
use std::future::Future;
use std::result::Result;

pub type Element = Box<dyn Widget>;

pub trait StateExt<T> {
    fn set(self, value: T);
}
impl<T: 'static> StateExt<T> for Cage<T> {
    fn set(self, value: T) {
        // A request can finish after navigation has disposed its page.
        let _ = self.try_revise(|current| *current = value);
    }
}

pub fn boxed(widget: impl Widget) -> Element {
    Box::new(widget)
}
pub fn stack(children: impl IntoChildren) -> glory::ui::View {
    glory::ui::col().class("stack").fill(children)
}
pub fn heading(value: &str) -> glory::ui::Text {
    text().kind(TextKind::Heading(2)).content(value.to_string())
}
pub fn label(value: &str) -> glory::ui::Text {
    text().content(value.to_string())
}
pub fn notice(value: Cage<String>) -> glory::ui::Text {
    text().class("notice").content_fn(move || value.get())
}
pub fn field(_scope: &Scope, name: &str, value: Cage<String>) -> glory::ui::View {
    let control = sapid::text_field()
        .name(name.to_string())
        .placeholder(name.to_string())
        .value(value)
        .on_value_change(move |next| value.set(next))
        .class("text-input");
    stack((label(name), control))
}
pub fn password(name: &str, value: Cage<String>) -> glory::ui::View {
    let control = sapid::password_input()
        .name(name.to_string())
        .placeholder(name.to_string())
        .value(value)
        .on_value_change(move |next| value.set(next));
    stack((label(name), control))
}
pub fn select(scope: &Scope, name: &str, value: Cage<String>, options: Vec<(String, String)>) -> sapid::NativeSelect {
    sapid::native_select(name.to_ascii_lowercase().replace(' ', "-"))
        .name(name.to_string())
        .value(scope.bond(move || Some(value.get())))
        .options(options.into_iter().map(|(key, label)| sapid::select_option(key, label)))
        .on_value_change(move |next| value.set(next.unwrap_or_default()))
}
pub fn action<F, Fut>(
    scope: &Scope,
    title: &str,
    busy: Cage<bool>,
    message: Cage<String>,
    mut operation: F,
) -> sapid::Button
where
    F: FnMut() -> Fut + 'static,
    Fut: Future<Output = Result<String, String>> + 'static,
{
    let owner = scope.downgrade();
    sapid::button().label(title.to_string()).enabled(scope.bond(move || !busy.get())).on_press(move || {
        if busy.get() {
            return;
        }
        let Some(owner) = owner.upgrade() else {
            return;
        };
        busy.set(true);
        message.set(String::new());
        let future = operation();
        let _ = owner.spawn(async move {
            message.set(match future.await {
                Ok(message) => message,
                Err(error) => error,
            });
            busy.set(false);
        });
    })
}
pub fn query_component(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (byte as char).to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}
#[cfg(target_arch = "wasm32")]
pub fn query(name: &str) -> String {
    web_sys::window()
        .and_then(|w| w.location().search().ok())
        .and_then(|search| web_sys::UrlSearchParams::new_with_str(&search).ok())
        .and_then(|params| params.get(name))
        .unwrap_or_default()
}
#[cfg(not(target_arch = "wasm32"))]
pub fn query(_: &str) -> String {
    String::new()
}
#[cfg(target_arch = "wasm32")]
pub fn redirect(target: &str) -> Result<(), String> {
    web_sys::window().ok_or("Window unavailable")?.location().assign(target).map_err(|_| "Navigation failed".into())
}
#[cfg(not(target_arch = "wasm32"))]
pub fn redirect(_: &str) -> Result<(), String> {
    Err("Navigation requires a browser".into())
}

pub fn clear_social_marker() {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        if let Ok(params) = web_sys::UrlSearchParams::new_with_str(&window.location().search().unwrap_or_default()) {
            params.delete("social");
            let search = params.to_string().as_string().unwrap_or_default();
            let suffix = if search.is_empty() {
                String::new()
            } else {
                format!("?{search}")
            };
            let path = format!(
                "{}{}{}",
                window.location().pathname().unwrap_or_default(),
                suffix,
                window.location().hash().unwrap_or_default()
            );
            if let Ok(history) = window.history() {
                let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&path));
            }
        }
    }
}
