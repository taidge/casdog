use crate::{AppState, ui::*};
use glory::prelude::*;
use serde_json::json;
pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let org = scope.cage("built-in".to_string());
        let name = scope.cage(String::new());
        let display = scope.cage(String::new());
        let email = scope.cage(String::new());
        let phone = scope.cage(String::new());
        let pass = scope.cage(String::new());
        let confirm = scope.cage(String::new());
        let application = scope.cage(query("application"));
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let fields: Vec<Element> = vec![
            boxed(field(scope, "Organization", org)),
            boxed(field(scope, "Username", name)),
            boxed(field(scope, "Display name", display)),
            boxed(field(scope, "Email", email)),
            boxed(field(scope, "Phone", phone)),
            boxed(field(scope, "Application", application)),
            boxed(password("Password", pass)),
            boxed(password("Confirm password", confirm)),
        ];
        stack((
            heading("Create account"),
            stack(fields),
            notice(message),
            action(scope, "Sign up", busy, message, move || async move {
                if name.get().trim().is_empty() || pass.get().is_empty() {
                    return Err("Enter a username and password.".into());
                }
                if pass.get() != confirm.get() {
                    return Err("Passwords do not match.".into());
                }
                app.request(
                    "POST",
                    "/api/signup",
                    Some(json!({
                        "owner": org.get(),
                        "name": name.get(),
                        "display_name": display.get(),
                        "email": email.get(),
                        "phone": phone.get(),
                        "password": pass.get(),
                        "application": if application.get().is_empty() { None } else { Some(application.get()) },
                    })),
                )
                .await?;

                pass.set(String::new());
                confirm.set(String::new());
                app.navigate("login-page");
                Ok("Account created.".into())
            }),
            sapid::button().label("Back to sign in").on_press(move || app.navigate("login-page")),
        ))
        .build(scope)
    }))
}
