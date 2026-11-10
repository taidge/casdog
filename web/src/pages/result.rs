use crate::{AppState, ui::*};
use glory::prelude::*;
pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let error = query("error");
        let title = if error.is_empty() {
            "Action completed"
        } else {
            "Action failed"
        };
        let details = if error.is_empty() {
            query("message")
        } else {
            format!("{} {}", error, query("error_description"))
        };
        stack((
            heading(title),
            label(&details),
            sapid::button().label("Back to dashboard").on_press(move || app.navigate("dashboard")),
        ))
        .build(scope)
    }))
}
