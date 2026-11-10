use crate::{AppState, api, ui::*};
use glory::prelude::*;
use serde_json::{Value, json};
pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let code = scope.cage(query("user_code"));
        let verified = scope.cage(json!({}));
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let mut controls: Vec<Element> = vec![
            boxed(heading("Device authorization")),
            boxed(field(scope, "User code", code)),
            boxed(action(scope, "Verify user code", busy, message, move || async move {
                let value = app
                    .request(
                        "POST",
                        "/api/login/oauth/device/verify",
                        Some(json!({
                            "user_code": code.get().trim().to_uppercase(),
                        })),
                    )
                    .await?;
                if value["device_code"].as_str().is_none_or(str::is_empty) {
                    return Err("Invalid or expired user code.".into());
                }
                verified.set(value);
                Ok("Review the application before approving access.".into())
            })),
            boxed(text().content_fn(move || api::pretty_json(&verified.get()))),
        ];
        for (approved, title) in [(true, "Approve device"), (false, "Deny device")] {
            controls.push(boxed(action(scope, title, busy, message, move || async move {
                let value = verified.get();
                let device = value["device_code"].as_str().ok_or("Verify a user code first")?;
                app.request(
                    "POST",
                    "/api/login/oauth/device/authorize",
                    Some(json!({
                        "device_code": device,
                        "approved": approved,
                    })),
                )
                .await?;
                verified.set(Value::Null);
                code.set(String::new());
                Ok(if approved {
                    "Device approved."
                } else {
                    "Device denied."
                }
                .into())
            })));
        }
        controls.push(boxed(notice(message)));
        stack(controls).build(scope)
    }))
}
