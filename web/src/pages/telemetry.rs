use crate::{AppState, api, ui::*};
use glory::prelude::*;
use serde_json::{Value, json};

pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        stack((
            heading("Telemetry receivers"),
            when(
                scope.bond(move || {
                    app.token.get().is_none() || !app.account.get().is_some_and(|a| a.is_admin)
                }),
                || label("Sign in as an administrator to approve telemetry receivers."),
            ),
            when(
                scope.bond(move || {
                    app.token.get().is_some() && app.account.get().is_some_and(|a| a.is_admin)
                }),
                move || editor(app),
            ),
        ))
        .build(scope)
    }))
}
fn editor(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let items = scope.cage(Vec::<Value>::new());
        let provider = scope.cage(String::new());
        let application = scope.cage(String::new());
        let mode = scope.cage("token".to_string());
        let sources = scope.cage(String::new());
        let enabled = scope.cage("true".to_string());
        let selected = scope.cage(None::<String>);
        let secret = scope.cage(String::new());
        let revealed = scope.cage(false);
        let revision = scope.cage(0u64);
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let tasks = scope.clone();
        scope.effect(move || {
            let version = revision.get();
            let _ = tasks.spawn(async move {
                match app.request("GET", "/api/telemetry/receivers", None).await {
                    Ok(value) if revision.get() == version => {
                        items.set(api::extract_collection(value))
                    }
                    Err(error) => message.set(error),
                    _ => {}
                }
            });
        });
        let rows = each(items).key(|item| item.to_string()).seed(move |item| {
            widget(move |scope| {
                let item = item.clone();
                let id = item["id"].as_str().unwrap_or_default().to_string();
                let revoke = id.clone();
                let revoked_provider = item["provider"].as_str().unwrap_or_default().to_string();
                stack((
                    label(&format!(
                        "Receiver {id} · {} · {}",
                        item["organization"].as_str().unwrap_or(""),
                        if item["enabled"] == true {
                            "Enabled"
                        } else {
                            "Disabled"
                        }
                    )),
                    action(
                        scope,
                        &format!("Configure receiver {id}"),
                        busy,
                        message,
                        move || {
                            let item = item.clone();
                            async move {
                                provider.set(item["provider"].as_str().unwrap_or_default().into());
                                application
                                    .set(item["application"].as_str().unwrap_or_default().into());
                                mode.set(item["authMode"].as_str().unwrap_or("token").into());
                                enabled.set(
                                    if item["enabled"] == true {
                                        "true"
                                    } else {
                                        "false"
                                    }
                                    .into(),
                                );
                                sources.set(
                                    item["allowedSources"]
                                        .as_array()
                                        .map(|values| {
                                            values
                                                .iter()
                                                .filter_map(Value::as_str)
                                                .collect::<Vec<_>>()
                                                .join("\n")
                                        })
                                        .unwrap_or_default(),
                                );
                                selected.set(Some(provider.get()));
                                secret.set(String::new());
                                revealed.set(false);
                                Ok(String::new())
                            }
                        },
                    ),
                    action(
                        scope,
                        &format!("Revoke receiver {revoke}"),
                        busy,
                        message,
                        move || {
                            let id = revoke.clone();
                            let revoked_provider = revoked_provider.clone();
                            async move {
                                app.request(
                                    "DELETE",
                                    &format!("/api/telemetry/receivers/{}", query_component(&id)),
                                    None,
                                )
                                .await?;
                                secret.set(String::new());
                                revealed.set(false);
                                if selected.get().as_deref() == Some(revoked_provider.as_str()) {
                                    enabled.set("false".into());
                                }
                                revision.set(revision.get() + 1);
                                Ok("Receiver revoked.".into())
                            }
                        },
                    ),
                ))
                .build(scope)
            })
        });
        stack((
            label("Approve an OpenClaw Log/Agent provider and its application. Exporters use OTLP/HTTP protobuf at /api/v1/traces, /api/v1/metrics and /api/v1/logs; /v1 paths are also supported."),
            action(scope,"New receiver",busy,message,move ||async move {provider.set(String::new());application.set(String::new());sources.set(String::new());mode.set("token".into());enabled.set("true".into());selected.set(None);secret.set(String::new());revealed.set(false);Ok(String::new())}),
            field(scope,"OpenClaw log provider ID or owner/name",provider),field(scope,"Receiver application ID or owner/name",application),
            select(scope,"Exporter authentication",mode,vec![("token".into(),"Bearer token".into()),("source_ip".into(),"Approved direct source IP".into())]),
            field(scope,"Allowed direct source CIDRs (comma separated)",sources),label("Source IP approval uses the direct connection address. Forwarded headers do not identify an exporter."),
            select(scope,"Receiver state",enabled,vec![("true".into(),"Enabled".into()),("false".into(),"Disabled".into())]),
            stack((
                action(scope,"Save receiver",busy,message,move ||save(app,provider,application,mode,sources,enabled,selected,secret,revealed,revision,false)),
                action(scope,"Rotate exporter token",busy,message,move ||save(app,provider,application,mode,sources,enabled,selected,secret,revealed,revision,true)),
            )),
            when(scope.bond(move ||!secret.get().is_empty()),move ||widget(move |scope| {
                stack((label("Store this exporter token now. It is shown only once."),
                    sapid::password_input().name("Exporter token").value(secret).readonly(true).visible(revealed).on_visibility_change(move |value|revealed.set(value)).visibility_labels("Show exporter token","Hide exporter token"),
                )).build(scope)
            })),rows,notice(message),
        )).build(scope)
    }))
}
async fn save(
    app: AppState,
    provider: Cage<String>,
    application: Cage<String>,
    mode: Cage<String>,
    sources: Cage<String>,
    enabled: Cage<String>,
    selected: Cage<Option<String>>,
    secret: Cage<String>,
    revealed: Cage<bool>,
    revision: Cage<u64>,
    rotate: bool,
) -> std::result::Result<String, String> {
    if rotate && mode.get() != "token" {
        return Err("Choose Bearer token authentication before rotating an exporter token.".into());
    }
    if provider.get().trim().is_empty() || application.get().trim().is_empty() {
        return Err("Enter the provider and application.".into());
    }
    if selected
        .get()
        .is_some_and(|current| current != provider.get())
    {
        return Err("Use New receiver to approve another provider.".into());
    }
    secret.set(String::new());
    revealed.set(false);
    let response=app.request("POST","/api/telemetry/receivers",Some(json!({"provider":provider.get(),"application":application.get(),"authMode":mode.get(),"allowedSources":sources.get().split([',','\n']).map(str::trim).filter(|value|!value.is_empty()).collect::<Vec<_>>(),"enabled":enabled.get()=="true","rotate":rotate}))).await?;
    let data = &response["data"];
    provider.set(data["provider"].as_str().unwrap_or_default().into());
    application.set(data["application"].as_str().unwrap_or_default().into());
    selected.set(Some(provider.get()));
    secret.set(data["token"].as_str().unwrap_or_default().into());
    revision.set(revision.get() + 1);
    Ok(if rotate {
        "Exporter token rotated."
    } else {
        "Receiver saved."
    }
    .into())
}
