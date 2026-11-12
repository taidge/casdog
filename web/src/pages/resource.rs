use crate::{AppState, api, resources::ResourceConfig, ui::*};
use glory::prelude::*;
use serde_json::Value;
pub fn page(app: AppState, config: ResourceConfig) -> Element {
    boxed(widget(move |scope| {
        let items = scope.cage(Vec::<Value>::new());
        let filter = scope.cage(String::new());
        let selected = scope.cage(None::<String>);
        let editor = scope.cage(config.template.to_string());
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let refresh = scope.cage(0_u64);
        let owner = scope.clone();
        scope.effect(move || {
            let _ = refresh.get();
            let _ = app.api_base.get();
            let _ = app.token.get();
            let _ = owner.spawn(async move {
                match app.request("GET", config.endpoint, None).await {
                    Ok(value) => items.set(api::extract_collection(value)),
                    Err(error) => message.set(error),
                }
            });
        });
        let visible = scope.bond(move || {
            items.get().into_iter().filter(|v| api::filter_matches(v, &filter.get().to_lowercase())).collect::<Vec<_>>()
        });
        let list = each(visible).key(|v| api::item_id(v).unwrap_or_else(|| v.to_string())).children(move |row| {
            widget(move |scope| {
                let value = row.value;
                let button =
                    sapid::button().label(scope.bond(move || api::item_title(&value.get()))).on_press(move || {
                        let data = value.get();
                        selected.set(api::item_id(&data));
                        editor.set(api::pretty_json(&data));
                        message.set(String::new());
                    });
                stack((button, text().content_fn(move || api::item_subtitle(&value.get())))).build(scope)
            })
        });
        stack((
            heading(config.label),
            label(config.description),
            field(scope, "Filter resources", filter),
            list,
            sapid::button().label("New resource").on_press(move || {
                selected.set(None);
                editor.set(config.template.to_string());
            }),
            crate::components::resource_form::form(config, editor, message),
            action(scope, "Save resource", busy, message, move || async move {
                let value: Value = serde_json::from_str(&editor.get()).map_err(|e| e.to_string())?;
                if !value.is_object() {
                    return Err("Resource must be a JSON object.".into());
                }
                let id = selected.get();
                let path = id
                    .as_ref()
                    .map(|id| format!("{}/{}", config.endpoint, query_component(id)))
                    .unwrap_or_else(|| config.endpoint.into());
                app.request(
                    if id.is_some() {
                        "PUT"
                    } else {
                        "POST"
                    },
                    &path,
                    Some(value),
                )
                .await?;
                refresh.set(refresh.get() + 1);
                Ok("Resource saved.".into())
            }),
            action(scope, "Delete selected resource", busy, message, move || async move {
                let id = selected.get().ok_or("Select a resource first")?;
                app.request("DELETE", &format!("{}/{}", config.endpoint, query_component(&id)), None).await?;
                selected.set(None);
                editor.set(config.template.into());
                refresh.set(refresh.get() + 1);
                Ok("Resource deleted.".into())
            }),
            when(scope.bond(move || config.slug == "syncers"), move || widget(move |scope| {
                action(scope,"Run selected syncer",busy,message,move ||async move {
                    let id=selected.get().ok_or("Select a syncer first.")?;
                    let result=app.request("POST",&format!("/api/syncers/{}/run",query_component(&id)),None).await?;
                    refresh.set(refresh.get()+1);
                    Ok(format!("Synchronization completed. Updated: {}. Disabled: {}.",result["recordsSynced"].as_u64().unwrap_or(0),result["recordsForbidden"].as_u64().unwrap_or(0)))
                }).build(scope)
            })),
            notice(message),
        ))
        .build(scope)
    }))
}
