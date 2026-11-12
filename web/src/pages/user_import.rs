use crate::{AppState, api, ui::*};
use glory::{
    prelude::*,
    render::{FileConfig, FileInfo, FileRead},
};
use sapid::FileController;
use serde_json::Value;
use std::result::Result;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

const MAX_BYTES: usize = 8 * 1024 * 1024;
type Completion = Box<dyn FnOnce(Result<Value, String>)>;

fn backup_users(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > MAX_BYTES {
        return Err("The JSON backup exceeds 8 MiB.".into());
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "Select a valid JSON backup.".to_string())?;
    let rows = value
        .as_array()
        .or_else(|| value.get("users").and_then(Value::as_array))
        .ok_or("The backup must contain a users array.")?;
    if rows.is_empty() || rows.len() > 1000 || rows.iter().any(|row| !row.is_object()) {
        return Err("Select a backup containing between 1 and 1000 user records.".into());
    }
    // Send only users, excluding unrelated provider secrets in a full init_data dump.
    Ok(Value::Array(rows.clone()))
}

fn finish(done: &Rc<RefCell<Option<Completion>>>, result: Result<Value, String>) {
    if let Some(callback) = done.borrow_mut().take() {
        callback(result);
    }
}

fn read_chunk(
    controller: FileController,
    file: FileInfo,
    offset: u64,
    bytes: Rc<RefCell<Vec<u8>>>,
    done: Rc<RefCell<Option<Completion>>>,
) {
    if offset == file.size {
        let result = backup_users(&bytes.borrow());
        finish(&done, result);
        return;
    }
    let length = (file.size - offset).min(65536) as u32;
    let request = FileRead {
        file: file.token,
        offset,
        length,
    };
    let next_controller = controller.clone();
    let next_done = done.clone();
    let result = controller.read(request, move |result| match result {
        Ok(chunk) if chunk.len() == length as usize => {
            bytes.borrow_mut().extend_from_slice(&chunk);
            read_chunk(
                next_controller,
                file,
                offset + u64::from(length),
                bytes,
                next_done,
            );
        }
        _ => finish(
            &next_done,
            Err("The selected backup could not be read. Select it again.".into()),
        ),
    });
    if result.is_err() {
        finish(
            &done,
            Err("File reading is unavailable. Select the backup again.".into()),
        );
    }
}

pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        stack((
            heading("Restore users and MFA"),
            when(
                scope.bond(move || {
                    !app.account.get().is_some_and(|a| a.is_admin) || app.token.get().is_none()
                }),
                || label("Sign in as a tenant administrator to restore users."),
            ),
            when(
                scope.bond(move || {
                    app.account.get().is_some_and(|a| a.is_admin) && app.token.get().is_some()
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
        let backup = scope.cage(None::<Value>);
        let confirmed = scope.cage(false);
        let busy = scope.cage(false);
        let submitting = scope.cage(false);
        let message = scope.cage(String::new());
        let report = scope.cage(Value::Null);
        let controller = scope.cage(None::<FileController>);
        let serial = Rc::new(Cell::new(0u64));
        let selection_serial = serial.clone();
        scope.effect(move || {
            let _ = owner.get();
            confirmed.set(false);
        });
        let picker = sapid::file_input().name("Casdoor JSON backup").label("Choose JSON backup")
            .enabled(scope.bond(move || !submitting.get()))
            .configuration(FileConfig { max_file_bytes: MAX_BYTES as u64, max_total_bytes: MAX_BYTES as u64, ..Default::default() })
            .controller_ref(controller).previews(false).show_attachments(true)
            .on_files(move |files| {
                selection_serial.set(selection_serial.get() + 1);
                let version = selection_serial.get();
                backup.set(None);confirmed.set(false);busy.set(false);report.set(Value::Null);message.set(String::new());
                let Some(file) = files.into_iter().next() else { busy.set(false); return; };
                if file.size == 0 || file.size > MAX_BYTES as u64 {message.set("Choose a nonempty JSON backup of at most 8 MiB.".into());return;}
                let Some(current) = controller.get() else {message.set("The file picker is not ready. Select the backup again.".into());return;};
                busy.set(true);
                let serial = selection_serial.clone();
                let done: Completion = Box::new(move |result| {
                    if serial.get() != version { return; }
                    busy.set(false);
                    match result { Ok(value) => {backup.set(Some(value));message.set("Backup read locally. Review the target and account summary before restoring.".into());}, Err(error) => message.set(error) }
                });
                read_chunk(current, file, 0, Rc::new(RefCell::new(Vec::new())), Rc::new(RefCell::new(Some(done))));
            });
        stack((
            label("Use a current, unmasked Casdoor JSON backup. This creates new accounts and restores supported MFA credentials. Existing accounts are never overwritten."),
            stack((label("Target organization"),sapid::text_field().name("Target organization").value(owner).on_value_change(move |value|owner.set(value)).enabled(scope.bond(move || !busy.get())))),
            picker,
            text().content_fn(move || {
                let Some(value)=backup.get() else {return "No backup ready.".into();};
                let rows=value.as_array().expect("validated user array");
                let names=rows.iter().take(5).filter_map(|r|r["name"].as_str()).collect::<Vec<_>>().join(", ");
                format!("Ready to restore {} accounts. First accounts: {}",rows.len(),names)
            }),
            label("Keep this file private. MFA secrets and recovery codes are not shown here or stored in browser storage. Restored authenticators may need a fresh code after up to 60 seconds; unused recovery codes can be used immediately."),
            sapid::checkbox().label("I am restoring a current, unmasked backup with MFA credentials").checked(confirmed).on_checked_change(move |value| confirmed.set(value)),
            action(scope,"Restore users and MFA",busy,message,move || async move {
                if !confirmed.get() {return Err("Confirm that this is a trusted, current MFA backup.".into());}
                if owner.get().trim().is_empty() {return Err("Choose the target organization.".into());}
                let value=backup.get().ok_or("Choose and review a backup first.")?;
                submitting.set(true);
                let response=app.request("POST",&format!("/api/upload-users-with-mfa?owner={}",query_component(&owner.get())),Some(value)).await;
                submitting.set(false);
                let result=response?;
                let failed=result["failed"].as_u64().ok_or("Invalid restore report.")?;
                let created=result["created"].as_u64().ok_or("Invalid restore report.")?;
                report.set(result);confirmed.set(false);
                if failed>0 {return Err("Restore rejected. No accounts were created; review the errors below.".into());}
                backup.set(None);
                if let Some(current)=controller.get() {let _=current.clear();}
                Ok(format!("Restored {created} accounts with their supported MFA credentials."))
            }),
            sapid::button().label("Clear backup").enabled(scope.bond(move || !submitting.get())).on_press(move || {
                serial.set(serial.get()+1);backup.set(None);confirmed.set(false);busy.set(false);report.set(Value::Null);message.set(String::new());
                if let Some(current)=controller.get() {let _=current.clear();}
            }),
            text().content_fn(move || if report.get().is_null() {String::new()} else {api::pretty_json(&report.get())}),
            notice(message),
        )).build(scope)
    }))
}
