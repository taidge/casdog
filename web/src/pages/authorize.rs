use crate::{AppState, api, ui::*};
use glory::prelude::*;
use serde_json::{Value, json};
pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let client = scope.cage(query("client_id"));
        let redirect_uri = scope.cage(query("redirect_uri"));
        let scopes = scope.cage({
            let v = query("scope");
            if v.is_empty() {
                "openid profile".into()
            } else {
                v
            }
        });
        let info = scope.cage(String::new());
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let owner = scope.clone();
        scope.effect(move || {
            let cid = client.get();
            if cid.is_empty() {
                return;
            }
            let _ = owner.spawn(async move {
                match app.request("GET", &format!("/api/applications?client_id={}", query_component(&cid)), None).await
                {
                    Ok(v) => info.set(api::pretty_json(&v)),
                    Err(e) => message.set(e),
                }
            });
        });
        let mut controls: Vec<Element> = vec![
            boxed(heading("Authorize application")),
            boxed(field(scope, "Client ID", client)),
            boxed(field(scope, "Redirect URI", redirect_uri)),
            boxed(field(scope, "Scopes", scopes)),
            boxed(notice(info)),
        ];
        for (approved, title) in [(true, "Allow access"), (false, "Deny access")] {
            controls.push(boxed(action(scope, title, busy, message, move || async move {
                let response_type = query("response_type");
                let response_type = if response_type.is_empty() {
                    "code".to_string()
                } else {
                    response_type
                };
                let payload = json!({
                    "client_id": client.get(),
                    "redirect_uri": redirect_uri.get(),
                    "response_type": response_type,
                    "scope": scopes.get(),
                    "state": query("state"),
                    "approved": approved,
                    "nonce": query("nonce"),
                    "code_challenge": query("code_challenge"),
                    "code_challenge_method": query("code_challenge_method"),
                });

                let value = app.request("POST", "/api/login/oauth/authorize", Some(payload)).await?;
                if let Some(target) =
                    value.get("redirect_uri").or_else(|| value.get("redirect")).and_then(Value::as_str)
                {
                    redirect(target)?;
                } else if !approved {
                    let uri = redirect_uri.get();
                    redirect(&format!(
                        "{uri}{}error=access_denied&state={}",
                        if uri.contains('?') {
                            '&'
                        } else {
                            '?'
                        },
                        query_component(&query("state"))
                    ))?;
                } else {
                    return Err("Authorization response did not include a redirect URL.".into());
                }
                Ok(String::new())
            })));
        }
        controls.push(boxed(notice(message)));
        stack(controls).build(scope)
    }))
}
