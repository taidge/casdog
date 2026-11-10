use crate::{AppState, api, ui::*};
use glory::prelude::*;
use serde_json::{Value, json};
pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let rows = scope.cage(Vec::<Value>::new());
        let application = scope.cage(String::new());
        let scopes = scope.cage("openid profile".to_string());
        let refresh = scope.cage(0_u64);
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let owner = scope.clone();
        scope.effect(move || {
            let _ = refresh.get();
            let _ = owner.spawn(async move {
                match app.request("GET", "/api/consents", None).await {
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
                    let path = format!("/api/consents/{}", query_component(&id));
                    async move {
                        app.request("DELETE", &path, None).await?;
                        refresh.set(refresh.get() + 1);
                        Ok("Consent revoked.".into())
                    }
                })
                .build(scope)
            })
        });
        stack((
            heading("Application consents"),
            list,
            field(scope, "Application", application),
            field(scope, "Scopes", scopes),
            action(scope, "Grant consent", busy, message, move || async move {
                app.request(
                    "POST",
                    "/api/consents",
                    Some(json!({
                        "application": application.get(),
                        "scopes": scopes.get().split_whitespace().collect::<Vec<_>>(),
                    })),
                )
                .await?;
                refresh.set(refresh.get() + 1);
                Ok("Consent granted.".into())
            }),
            notice(message),
        ))
        .build(scope)
    }))
}
