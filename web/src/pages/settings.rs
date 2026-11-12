use crate::{AppState, ui::*};
use glory::prelude::*;
use serde_json::json;

pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        stack((
            heading("Site settings"),
            when(
                scope.bond(move || {
                    !app.account
                        .get()
                        .is_some_and(|a| a.is_admin && a.owner == "built-in")
                }),
                || label("Sign in as a global administrator to manage site settings."),
            ),
            when(
                scope.bond(move || {
                    app.token.get().is_some()
                        && app
                            .account
                            .get()
                            .is_some_and(|a| a.is_admin && a.owner == "built-in")
                }),
                move || editor(app),
            ),
        ))
        .build(scope)
    }))
}
fn editor(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let retention = scope.cage("0".to_string());
        let open = scope.cage("0".to_string());
        let idle = scope.cage("0".to_string());
        let lifetime = scope.cage("0".to_string());
        let loaded = scope.cage(false);
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        stack((
            action(scope,"Load site settings",busy,message,move ||async move {
                let response=app.request("GET","/api/get-setting",None).await?;let data=&response["data"];
                retention.set(data["recordRetentionDays"].as_i64().unwrap_or_default().to_string());open.set(data["dbMaxOpenConns"].as_i64().unwrap_or_default().to_string());idle.set(data["dbMaxIdleConns"].as_i64().unwrap_or_default().to_string());lifetime.set(data["dbConnMaxLifetime"].as_i64().unwrap_or_default().to_string());loaded.set(true);Ok("Site settings loaded.".into())
            }),
            label("Audit retention applies to organizations without their own retention period. Zero keeps records indefinitely. Expired records are removed automatically."),
            field(scope,"Audit retention days",retention),
            label("Connection pool settings can be saved here; runtime application is still pending."),
            field(scope,"Saved maximum open connections",open),field(scope,"Saved maximum idle connections",idle),field(scope,"Saved connection lifetime (seconds)",lifetime),
            action(scope,"Save site settings",busy,message,move ||async move {
                if !loaded.get() {return Err("Load current settings before editing.".into());}
                let parse=|value:String|value.parse::<i64>().map_err(|_|"Enter whole non-negative settings values.".to_string());
                let value=json!({"recordRetentionDays":parse(retention.get())?,"dbMaxOpenConns":parse(open.get())?,"dbMaxIdleConns":parse(idle.get())?,"dbConnMaxLifetime":parse(lifetime.get())?});
                let response=app.request("POST","/api/update-setting",Some(value)).await?;
                if response["recordRetentionApplied"]!=true {return Err("The server did not confirm the retention policy.".into());}
                Ok("Audit retention saved and active for the next cleanup. Pool settings remain pending.".into())
            }),notice(message),
        )).build(scope)
    }))
}
