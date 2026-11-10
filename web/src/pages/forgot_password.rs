use crate::{AppState, ui::*};
use glory::prelude::*;
use serde_json::json;
pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let org = scope.cage("built-in".to_string());
        let email = scope.cage(String::new());
        let application = scope.cage(query("application"));
        let request_id = scope.cage(String::new());
        let code = scope.cage(String::new());
        let pass = scope.cage(String::new());
        let confirm = scope.cage(String::new());
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        stack((
            heading("Recover password"),
            field(scope, "Organization", org),
            field(scope, "Email", email),
            field(scope, "Application", application),
            action(scope, "Send reset code", busy, message, move || async move {
                let value = app
                    .request(
                        "POST",
                        "/api/request-password-reset",
                        Some(json!({
                            "organization": org.get(),
                            "email": email.get(),
                            "application": if application.get().is_empty() { None } else { Some(application.get()) },
                        })),
                    )
                    .await?;

                request_id.set(value["requestId"].as_str().ok_or("Recovery request ID missing")?.to_string());
                Ok("If this account can recover its password, a reset code will be sent to its email address.".into())
            }),
            when(scope.bond(move || !request_id.get().is_empty()), move || {
                widget(move |scope| {
                    stack((
                        field(scope, "Reset code", code),
                        password("New password", pass),
                        password("Confirm new password", confirm),
                        action(scope, "Reset password", busy, message, move || async move {
                            if pass.get() != confirm.get() {
                                return Err("Passwords do not match.".into());
                            }
                            app.request(
                                "POST",
                                "/api/reset-password",
                                Some(json!({
                                    "organization": org.get(),
                                    "email": email.get(),
                                    "application": if application.get().is_empty() { None } else { Some(application.get()) },
                                    "requestId": request_id.get(),
                                    "code": code.get().trim(),
                                    "new_password": pass.get(),
                                })),
                            )
                            .await?;

                            pass.set(String::new());
                            confirm.set(String::new());
                            code.set(String::new());
                            request_id.set(String::new());
                            Ok("Password reset. Sign in with your new password.".into())
                        }),
                    ))
                    .build(scope)
                })
            }),
            notice(message),
            sapid::button().label("Back to sign in").on_press(move || app.navigate("login-page")),
        ))
        .build(scope)
    }))
}
