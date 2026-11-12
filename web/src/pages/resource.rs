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
        let fresh_url = scope.cage(String::new());
        let clear_primary = scope.cage(false);
        let clear_secondary = scope.cage(false);
        let clear_content = scope.cage(false);
        let clear_metadata = scope.cage(false);
        let clear_headers = scope.cage(false);
        let network_status = scope.cage(String::new());
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
            items
                .get()
                .into_iter()
                .filter(|v| api::filter_matches(v, &filter.get().to_lowercase()))
                .collect::<Vec<_>>()
        });
        let list = each(visible)
            .key(|v| api::item_id(v).unwrap_or_else(|| v.to_string()))
            .children(move |row| {
                widget(move |scope| {
                    let value = row.value;
                    let button = sapid::button()
                        .label(scope.bond(move || api::item_title(&value.get())))
                        .on_press(move || {
                            let data = value.get();
                            selected.set(api::item_id(&data));
                            editor.set(api::pretty_json(&data));
                            message.set(String::new());
                            fresh_url.set(String::new());
                            clear_primary.set(false);
                            clear_secondary.set(false);
                            clear_content.set(false);
                            clear_metadata.set(false);
                            clear_headers.set(false);
                            network_status.set(String::new());
                        });
                    stack((
                        button,
                        text().content_fn(move || api::item_subtitle(&value.get())),
                    ))
                    .build(scope)
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
                clear_primary.set(false); clear_secondary.set(false); clear_content.set(false); clear_metadata.set(false);clear_headers.set(false);network_status.set(String::new());
            }),
            crate::components::resource_form::form(config, editor, message),
            stack((
            when(scope.bond(move || config.slug == "providers" && selected.get().is_some()), move || widget(move |scope| {
                stack((
                    label("Credential removal applies only when Save resource succeeds. Type a replacement in the relevant field to rotate a credential."),
                    sapid::checkbox().label("Clear saved client secret").checked(clear_primary).on_checked_change(move |value| clear_primary.set(value)),
                    when(scope.bond(move || serde_json::from_str::<Value>(&editor.get()).ok().is_some_and(|v|v["category"]!="Email")), move || widget(move |scope| {
                        sapid::checkbox().label("Clear saved secondary client secret").checked(clear_secondary).on_checked_change(move |value| clear_secondary.set(value)).build(scope)
                    })),
                    when(scope.bond(move || serde_json::from_str::<Value>(&editor.get()).ok().is_some_and(|v|v["type"]=="WeChat")), move || widget(move |scope| {
                        sapid::checkbox().label("Clear saved WeChat private key").checked(clear_content).on_checked_change(move |value| clear_content.set(value)).build(scope)
                    })),
                    sapid::checkbox().label("Clear all saved metadata").checked(clear_metadata).on_checked_change(move |value| clear_metadata.set(value)),
                    sapid::checkbox().label("Clear all saved HTTP headers").checked(clear_headers).on_checked_change(move |value| clear_headers.set(value)),
                )).build(scope)
            })),
            when(scope.bond(move || config.slug=="providers" && selected.get().is_some() && app.account.get().is_some_and(|account|account.owner=="built-in" && account.is_admin) && serde_json::from_str::<Value>(&editor.get()).ok().is_some_and(|value|crate::components::resource_form::supports_network_approval(&value))), move || widget(move |scope| {
                stack((
                    label("Private provider endpoints require explicit review by a global administrator. Approve only trusted internal endpoints after reviewing the effective credentials and transport configuration. Saving a changed configuration requires reviewing it again."),
                    action(scope,"Load private provider approval",busy,message,move || async move {
                        let id=selected.get().ok_or("Select a saved provider first.")?;
                        let value=app.request("GET",&format!("/api/providers/{}/network-approval",query_component(&id)),None).await?;
                        network_status.set(if value["allow_private"]==true {"Private provider endpoints are approved for the saved configuration."} else if value["stale"]==true {"The saved provider configuration changed. Review its endpoints before approving again."} else {"Private provider endpoints are not approved for the saved configuration."}.into());
                        Ok(String::new())
                    }),
                    action(scope,"Approve private provider endpoints",busy,message,move || async move {
                        let id=selected.get().ok_or("Select a saved provider first.")?;
                        app.request("POST",&format!("/api/providers/{}/network-approval",query_component(&id)),Some(serde_json::json!({"allow_private":true}))).await?;
                        network_status.set("Private provider endpoints are approved for the saved configuration.".into());
                        Ok("Private provider endpoints approved.".into())
                    }),
                    action(scope,"Revoke private provider approval",busy,message,move || async move {
                        let id=selected.get().ok_or("Select a saved provider first.")?;
                        app.request("DELETE",&format!("/api/providers/{}/network-approval",query_component(&id)),None).await?;
                        network_status.set("Private provider endpoints are not approved for the saved configuration.".into());
                        Ok("Private provider endpoint approval revoked.".into())
                    }),
                    notice(network_status),
                )).build(scope)
            })),
            when(scope.bond(move || config.slug=="syncers" && selected.get().is_some() && app.account.get().is_some_and(|account|account.owner=="built-in" && account.is_admin) && serde_json::from_str::<Value>(&editor.get()).ok().is_some_and(|value|matches!(value["type"].as_str(),Some("Azure AD"|"Google Workspace")))),move||widget(move|scope| {
                stack((
                    label("Private cloud-directory endpoints require explicit review by a global administrator. Review both token and directory API endpoints; changed credentials or options require approval again."),
                    action(scope,"Load directory network approval",busy,message,move||async move {
                        let id=selected.get().ok_or("Select a saved cloud directory first.")?;
                        let value=app.request("GET",&format!("/api/syncers/{}/network-approval",query_component(&id)),None).await?;
                        let status=if value["allow_private"]==true {"Private directory endpoints are approved for the saved configuration."}else if value["stale"]==true {"The saved directory configuration changed. Review its endpoints before approving again."}else{"Private directory endpoints are not approved for the saved configuration."};
                        let targets=value["target_origins"].as_array().map(|values|values.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default();
                        network_status.set(format!("{status} Targets: {targets}"));
                        Ok(String::new())
                    }),
                    action(scope,"Approve private directory endpoints",busy,message,move||async move {
                        let id=selected.get().ok_or("Select a saved cloud directory first.")?;
                        app.request("POST",&format!("/api/syncers/{}/network-approval",query_component(&id)),Some(serde_json::json!({"allow_private":true}))).await?;
                        network_status.set("Private directory endpoints are approved for the saved configuration.".into());
                        Ok("Private directory endpoints approved.".into())
                    }),
                    action(scope,"Revoke directory network approval",busy,message,move||async move {
                        let id=selected.get().ok_or("Select a saved cloud directory first.")?;
                        app.request("DELETE",&format!("/api/syncers/{}/network-approval",query_component(&id)),None).await?;
                        network_status.set("Private directory endpoints are not approved for the saved configuration.".into());
                        Ok("Private directory network approval revoked.".into())
                    }),
                    notice(network_status),
                )).build(scope)
            })),
            )),
            action(scope, "Save resource", busy, message, move || async move {
                let mut value: Value =
                    serde_json::from_str(&editor.get()).map_err(|e| e.to_string())?;
                if !value.is_object() {
                    return Err("Resource must be a JSON object.".into());
                }
                let id = selected.get();
                if config.slug == "providers" && id.is_some() {
                    for (field, clear, protected) in [
                        ("client_secret", clear_primary.get(), true),
                        ("client_secret2", clear_secondary.get(), value["category"] != "Email"),
                        ("content", clear_content.get(), value["type"] == "WeChat"),
                    ] {
                        if protected {
                            if clear { value[field] = serde_json::json!(""); }
                            else if value[field].as_str().is_none_or(|s|s.is_empty() || s=="***") {
                                value.as_object_mut().unwrap().remove(field);
                            }
                        }
                    }
                    if clear_headers.get() { value["http_headers"] = serde_json::json!(""); }
                    if clear_metadata.get() { value["metadata"] = serde_json::json!(""); }
                    else if value["metadata"].as_str().is_some_and(|s|s.is_empty()) { value.as_object_mut().unwrap().remove("metadata"); }
                }
                let path = id
                    .as_ref()
                    .map(|id| format!("{}/{}", config.endpoint, query_component(id)))
                    .unwrap_or_else(|| config.endpoint.into());
                let saved = app.request(
                    if id.is_some() { "PUT" } else { "POST" },
                    &path,
                    Some(value),
                )
                .await?;
                if config.slug == "providers" || config.slug == "organizations" {
                    let mut cleaned: Value = if config.slug == "providers" && saved.get("id").is_some() {
                        saved
                    } else { serde_json::from_str(&editor.get()).map_err(|e| e.to_string())? };
                    if config.slug == "providers" {
                        for field in ["client_secret", "client_secret2", "content"] {
                            let sensitive=field=="client_secret" || (field=="client_secret2" && cleaned["category"]!="Email") || (field=="content" && cleaned["type"]=="WeChat");
                            if sensitive && cleaned[field].as_str().is_some_and(|v|!v.is_empty()) {cleaned[field]=serde_json::json!("***");}
                        }
                        clear_primary.set(false);clear_secondary.set(false);clear_content.set(false);clear_metadata.set(false);clear_headers.set(false);network_status.set(String::new());
                    }
                    if config.slug == "organizations"
                        && cleaned["kerberos_keytab"]
                            .as_str()
                            .is_some_and(|s| !s.is_empty())
                    {
                        cleaned["kerberos_keytab"] = serde_json::json!("***");
                    }
                    editor.set(api::pretty_json(&cleaned));
                }
                refresh.set(refresh.get() + 1);
                Ok("Resource saved.".into())
            }),
            action(
                scope,
                "Delete selected resource",
                busy,
                message,
                move || async move {
                    let id = selected.get().ok_or("Select a resource first")?;
                    app.request(
                        "DELETE",
                        &format!("{}/{}", config.endpoint, query_component(&id)),
                        None,
                    )
                    .await?;
                    selected.set(None);
                    editor.set(config.template.into());
                    refresh.set(refresh.get() + 1);
                    Ok("Resource deleted.".into())
                },
            ),
            when(scope.bond(move || config.slug == "syncers"), move || {
                widget(move |scope| {
                    action(
                        scope,
                        "Run selected syncer",
                        busy,
                        message,
                        move || async move {
                            let id = selected.get().ok_or("Select a syncer first.")?;
                            let result = app
                                .request(
                                    "POST",
                                    &format!("/api/syncers/{}/run", query_component(&id)),
                                    None,
                                )
                                .await?;
                            refresh.set(refresh.get() + 1);
                            Ok(format!(
                                "Synchronization completed. Updated: {}. Disabled: {}.",
                                result["recordsSynced"].as_u64().unwrap_or(0),
                                result["recordsForbidden"].as_u64().unwrap_or(0)
                            ))
                        },
                    )
                    .build(scope)
                })
            }),
            when(scope.bond(move || config.slug == "resources"), move || {
                widget(move |scope| {
                    stack((
                        action(
                            scope,
                            "Get fresh resource URL",
                            busy,
                            message,
                            move || async move {
                                let id = selected.get().ok_or("Select a resource first.")?;
                                let value = app
                                    .request(
                                        "GET",
                                        &format!("/api/resource-url/{}", query_component(&id)),
                                        None,
                                    )
                                    .await?;
                                fresh_url.set(
                                    value["url"]
                                        .as_str()
                                        .ok_or("Resource URL missing")?
                                        .to_string(),
                                );
                                Ok(format!(
                                    "Resource access: {}. Expiry: {}.",
                                    value["access"].as_str().unwrap_or("unknown"),
                                    value["expires_at"]
                                        .as_str()
                                        .unwrap_or("public or authenticated proxy")
                                ))
                            },
                        ),
                        text().content_fn(move || fresh_url.get()),
                        action(
                            scope,
                            "Download selected resource",
                            busy,
                            message,
                            move || async move {
                                let id = selected.get().ok_or("Select a resource first.")?;
                                let value: Value = serde_json::from_str(&editor.get())
                                    .map_err(|_| "Select a valid resource")?;
                                api::download_resource(
                                    &api::build_url(
                                        &app.api_base.get(),
                                        &format!("/api/download-resource/{}", query_component(&id)),
                                    ),
                                    app.token.get().as_deref(),
                                    value["file_name"]
                                        .as_str()
                                        .or_else(|| value["name"].as_str())
                                        .unwrap_or("download"),
                                )
                                .await?;
                                Ok("Resource download started.".into())
                            },
                        ),
                    ))
                    .build(scope)
                })
            }),
            notice(message),
        ))
        .build(scope)
    }))
}
