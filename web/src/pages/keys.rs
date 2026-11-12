use crate::{AppState, api, ui::*};
use glory::prelude::*;
use serde_json::{Value, json};

#[derive(Clone, Copy)]
struct Draft {
    name: Cage<String>,
    kind: Cage<String>,
    user: Cage<String>,
    application: Cage<String>,
    expiry: Cage<String>,
    state: Cage<String>,
    access: Cage<String>,
    secret: Cage<String>,
    selected: Cage<Option<(String, String)>>,
    revealed: Cage<bool>,
}
impl Draft {
    fn load(self, value: Value) {
        let text = |key: &str| value[key].as_str().unwrap_or_default().to_string();
        self.name.set(text("name"));
        self.kind.set(text("type"));
        self.user.set(text("user"));
        self.application.set(text("application"));
        self.expiry.set(text("expireTime"));
        self.state.set(text("state"));
        self.access.set(text("accessKey"));
        self.secret.set(text("accessSecret"));
        self.selected.set(Some((text("owner"), text("name"))));
        self.revealed.set(false);
    }
    fn clear(self, username: String) {
        self.name.set(String::new());
        self.kind.set("User".into());
        self.user.set(username);
        self.application.set(String::new());
        self.expiry.set(String::new());
        self.state.set("Active".into());
        self.access.set(String::new());
        self.secret.set(String::new());
        self.selected.set(None);
        self.revealed.set(false);
    }
}

pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        stack((
            heading("API keys"),
            when(
                scope.bond(move || {
                    app.token.get().is_none() || !app.account.get().is_some_and(|a| a.is_admin)
                }),
                || label("Sign in as a tenant administrator to manage API keys."),
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
        let owner = scope.cage(app.account.get().map(|a| a.owner).unwrap_or_default());
        let draft = Draft {
            name: scope.cage(String::new()),
            kind: scope.cage("User".into()),
            user: scope.cage(String::new()),
            application: scope.cage(String::new()),
            expiry: scope.cage(String::new()),
            state: scope.cage("Active".into()),
            access: scope.cage(String::new()),
            secret: scope.cage(String::new()),
            selected: scope.cage(None),
            revealed: scope.cage(false),
        };
        let reviewed_application = scope.cage(String::new());
        let items = scope.cage(Vec::<Value>::new());
        let revision = scope.cage(0u64);
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        scope.effect(move || {
            let namespace = owner.get();
            draft.clear(
                app.account
                    .get()
                    .filter(|a| a.owner == namespace)
                    .map(|a| a.name)
                    .unwrap_or_default(),
            );
        });
        let tasks = scope.clone();
        scope.effect(move || {
            let _ = revision.get();
            let namespace = owner.get();
            items.set(Vec::new());
            if namespace.trim().is_empty() {
                return;
            }
            let _ = tasks.spawn(async move {
                let result = app
                    .request(
                        "GET",
                        &format!("/api/get-keys?owner={}", query_component(&namespace)),
                        None,
                    )
                    .await;
                if owner.get() != namespace {
                    return;
                }
                match result {
                    Ok(value) => items.set(api::extract_collection(value)),
                    Err(error) => message.set(error),
                }
            });
        });
        let rows = each(items)
            .key(|item| format!("{}/{}", item["owner"], item["name"]))
            .seed(move |item| {
                widget(move |scope| {
                    let namespace = item["owner"].as_str().unwrap_or_default().to_string();
                    let name = item["name"].as_str().unwrap_or_default().to_string();
                    let title = format!("Edit API key {namespace}/{name}");
                    action(scope, &title, busy, message, move || {
                        let namespace = namespace.clone();
                        let name = name.clone();
                        async move {
                            let response = app
                                .request(
                                    "GET",
                                    &format!(
                                        "/api/get-key?id={}",
                                        query_component(&format!("{namespace}/{name}"))
                                    ),
                                    None,
                                )
                                .await?;
                            if owner.get() != namespace {
                                return Ok(String::new());
                            }
                            if !response["data"].is_object() {
                                return Err("API key was removed. Refresh the list.".into());
                            }
                            draft.load(response["data"].clone());
                            Ok(String::new())
                        }
                    })
                    .build(scope)
                })
            });
        stack((
            label("Bind credentials to a user or application. Disable or delete a key to revoke access."),
            field(scope, "Key owner", owner),
            action(scope, "Refresh API keys", busy, message, move || async move { revision.set(revision.get()+1); Ok(String::new()) }),
            rows,
            action(scope, "New API key", busy, message, move || async move {
                draft.clear(app.account.get().filter(|a| a.owner==owner.get()).map(|a| a.name).unwrap_or_default());
                Ok(String::new())
            }),
            stack((field(scope, "Key name", draft.name),
            sapid::native_select("key-type").name("Key type").value(scope.bond(move || Some(draft.kind.get())))
                .options(["User", "Application", "Organization", "General"].into_iter().map(|v|sapid::select_option(v,v)))
                .on_value_change(move |value| { let next=value.unwrap_or_else(||"User".into()); if next=="Application" { draft.user.set(String::new()); } draft.kind.set(next); }),
            field(scope, "Bound user", draft.user),
            field(scope, "Bound application", draft.application),
            field(scope, "Expires at (RFC3339, optional)", draft.expiry),
            select(scope, "Key state", draft.state, vec![("Active".into(),"Active".into()),("Inactive".into(),"Inactive".into())]))),
            action(scope, "Save API key", busy, message, move || async move {
                let namespace=owner.get();
                let name=draft.name.get();
                if namespace.trim().is_empty() || name.trim().is_empty() { return Err("Enter a key owner and name.".into()); }
                let selected=draft.selected.get();
                if selected.as_ref().is_some_and(|id| id != &(namespace.clone(),name.clone())) { return Err("Use New API key to create a different identity.".into()); }
                let route=if selected.is_some() { "/api/update-key" } else { "/api/add-key" };
                let response=app.request("POST", route, Some(json!({
                    "owner":namespace,"name":name,"type":draft.kind.get(),"organization":namespace,
                    "user":draft.user.get(),"application":draft.application.get(),"expireTime":draft.expiry.get(),"state":draft.state.get()
                }))).await?;
                if response["data"] != true { return Err("API key was not saved.".into()); }
                let key=app.request("GET", &format!("/api/get-key?id={}",query_component(&format!("{namespace}/{name}"))),None).await?;
                if owner.get()==namespace && key["data"].is_object() { draft.load(key["data"].clone()); }
                revision.set(revision.get()+1);
                Ok("API key saved.".into())
            }),
            when(scope.bond(move || draft.selected.get().is_some()), move || widget(move |scope| {
                stack((
                    label("Access key"), sapid::text_field().name("Access key").value(draft.access).readonly(true),
                    label("Access secret"), sapid::password_input().name("Access secret").value(draft.secret).readonly(true)
                        .visible(draft.revealed).on_visibility_change(move |shown|draft.revealed.set(shown))
                        .visibility_labels("Show access secret", "Hide access secret"),
                    action(scope, "Delete API key", busy, message, move || async move {
                        let (namespace,name)=draft.selected.get().ok_or("Select an API key first.")?;
                        let result=app.request("POST", "/api/delete-key",Some(json!({"owner":namespace,"name":name}))).await?;
                        if result["data"]!=true { return Err("API key was already removed.".into()); }
                        draft.clear(String::new()); revision.set(revision.get()+1);
                        Ok("API key deleted.".into())
                    }),
                )).build(scope)
            })),
            stack((
                heading("Review application credentials"),
                label("Trust a reviewed static application to act as its organization administrator. Dynamic clients cannot receive this authority."),
                field(scope, "Reviewed application ID or owner/name", reviewed_application),
                action(scope, "Trust static application", busy, message, move || async move {
                    if reviewed_application.get().trim().is_empty() { return Err("Enter the reviewed application identity.".into()); }
                    app.request("POST","/api/trust-application-credentials",Some(json!({"application":reviewed_application.get()}))).await?;
                    Ok("Static application credentials trusted.".into())
                }),
            )),
            notice(message),
        )).build(scope)
    }))
}
