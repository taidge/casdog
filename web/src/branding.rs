use crate::{AppState, ui::*};
use glory::prelude::*;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(module = "/src/branding.js")]
unsafe extern "C" {
    #[wasm_bindgen(js_name = beginBranding)]
    fn begin_branding() -> u32;
    #[wasm_bindgen(js_name = applyBranding)]
    fn apply_branding(token: u32, json: &str);
    #[wasm_bindgen(js_name = endBranding)]
    fn end_branding(token: u32);
}

#[cfg(target_arch = "wasm32")]
struct BrandingScope(u32);
#[cfg(target_arch = "wasm32")]
impl Drop for BrandingScope {
    fn drop(&mut self) {
        end_branding(self.0);
    }
}

/// Application fields are intentionally shared with the authentication form.
/// Scope disposal and request generations prevent a slow previous lookup from
/// applying another application's branding after navigation or an input edit.
pub fn bind(scope: &Scope, app: AppState, application: Cage<String>) {
    #[cfg(target_arch = "wasm32")]
    {
        use std::{cell::Cell, rc::Rc};
        let token = begin_branding();
        let _ = scope.retain(BrandingScope(token));
        let generation = Rc::new(Cell::new(0u64));
        let tasks = scope.clone();
        scope.effect(move || {
            let reference = application.get();
            let _ = app.api_base.get();
            let reference = if reference.trim().is_empty() {
                let client = query("client_id");
                let client = if client.is_empty() {
                    query("clientId")
                } else {
                    client
                };
                if client.is_empty() {
                    "admin/app-built-in".into()
                } else {
                    client
                }
            } else {
                reference
            };
            generation.set(generation.get() + 1);
            let version = generation.get();
            let generation = generation.clone();
            apply_branding(token, "null");
            let _ = tasks.spawn(async move {
                if let Ok(response) = app
                    .request(
                        "GET",
                        &format!(
                            "/api/auth/branding?application={}",
                            query_component(&reference)
                        ),
                        None,
                    )
                    .await
                {
                    if generation.get() == version {
                        apply_branding(token, &response["data"].to_string());
                    }
                }
            });
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (scope, app, application);
}
