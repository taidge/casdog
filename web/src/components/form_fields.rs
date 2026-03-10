use dioxus::prelude::*;

// ---------------------------------------------------------------------------
// TextField
// ---------------------------------------------------------------------------

#[component]
pub fn TextField(
    label: String,
    value: String,
    #[props(default)] placeholder: String,
    #[props(default)] disabled: bool,
    #[props(default)] required: bool,
    oninput: EventHandler<String>,
) -> Element {
    rsx! {
        div { class: "form-field",
            label { class: "form-label",
                "{label}"
                if required {
                    span { class: "form-required", " *" }
                }
            }
            input {
                class: "text-input",
                r#type: "text",
                placeholder: "{placeholder}",
                value: "{value}",
                disabled,
                oninput: move |evt| oninput.call(evt.value()),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TextArea
// ---------------------------------------------------------------------------

#[component]
pub fn TextArea(
    label: String,
    value: String,
    #[props(default)] placeholder: String,
    #[props(default)] disabled: bool,
    #[props(default)] required: bool,
    #[props(default = 4)] rows: u32,
    oninput: EventHandler<String>,
) -> Element {
    rsx! {
        div { class: "form-field",
            label { class: "form-label",
                "{label}"
                if required {
                    span { class: "form-required", " *" }
                }
            }
            textarea {
                class: "text-input form-textarea",
                placeholder: "{placeholder}",
                value: "{value}",
                rows: "{rows}",
                disabled,
                oninput: move |evt| oninput.call(evt.value()),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SelectField
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct SelectOption {
    pub value: String,
    pub label: String,
}

#[component]
pub fn SelectField(
    label: String,
    value: String,
    options: Vec<SelectOption>,
    #[props(default)] disabled: bool,
    #[props(default)] required: bool,
    onchange: EventHandler<String>,
) -> Element {
    rsx! {
        div { class: "form-field",
            label { class: "form-label",
                "{label}"
                if required {
                    span { class: "form-required", " *" }
                }
            }
            select {
                class: "text-input form-select",
                value: "{value}",
                disabled,
                onchange: move |evt: Event<FormData>| onchange.call(evt.value()),
                {options.iter().map(|opt| {
                    let v = opt.value.clone();
                    let l = opt.label.clone();
                    let selected = v == value;
                    rsx! {
                        option {
                            value: "{v}",
                            selected,
                            "{l}"
                        }
                    }
                })}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ToggleField
// ---------------------------------------------------------------------------

#[component]
pub fn ToggleField(
    label: String,
    checked: bool,
    #[props(default)] disabled: bool,
    onchange: EventHandler<bool>,
) -> Element {
    rsx! {
        div { class: "form-field form-field-toggle",
            label { class: "form-label", "{label}" }
            div {
                class: if checked { "toggle-track toggle-on" } else { "toggle-track" },
                onclick: move |_| {
                    if !disabled {
                        onchange.call(!checked);
                    }
                },
                div { class: "toggle-thumb" }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NumberField
// ---------------------------------------------------------------------------

#[component]
pub fn NumberField(
    label: String,
    value: f64,
    #[props(default)] placeholder: String,
    #[props(default)] disabled: bool,
    #[props(default)] required: bool,
    #[props(default)] min: Option<f64>,
    #[props(default)] max: Option<f64>,
    #[props(default)] step: Option<f64>,
    oninput: EventHandler<f64>,
) -> Element {
    let display_value = if value == value.floor() {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    };

    rsx! {
        div { class: "form-field",
            label { class: "form-label",
                "{label}"
                if required {
                    span { class: "form-required", " *" }
                }
            }
            input {
                class: "text-input",
                r#type: "number",
                placeholder: "{placeholder}",
                value: "{display_value}",
                disabled,
                min: if let Some(m) = min { format!("{m}") } else { String::new() },
                max: if let Some(m) = max { format!("{m}") } else { String::new() },
                step: if let Some(s) = step { format!("{s}") } else { "any".to_string() },
                oninput: move |evt: Event<FormData>| {
                    if let Ok(n) = evt.value().parse::<f64>() {
                        oninput.call(n);
                    }
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JsonField
// ---------------------------------------------------------------------------

#[component]
pub fn JsonField(
    label: String,
    value: String,
    #[props(default)] disabled: bool,
    #[props(default)] required: bool,
    #[props(default = 8)] rows: u32,
    oninput: EventHandler<String>,
) -> Element {
    let is_valid = serde_json::from_str::<serde_json::Value>(&value).is_ok() || value.is_empty();

    rsx! {
        div { class: "form-field",
            label { class: "form-label",
                "{label}"
                if required {
                    span { class: "form-required", " *" }
                }
            }
            textarea {
                class: if is_valid { "text-input form-textarea form-json" } else { "text-input form-textarea form-json json-invalid-border" },
                rows: "{rows}",
                value: "{value}",
                disabled,
                oninput: move |evt| oninput.call(evt.value()),
            }
            if !value.is_empty() {
                div {
                    class: if is_valid { "form-json-status json-valid" } else { "form-json-status json-invalid" },
                    if is_valid { "Valid JSON" } else { "Invalid JSON" }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PasswordField
// ---------------------------------------------------------------------------

#[component]
pub fn PasswordField(
    label: String,
    value: String,
    #[props(default)] placeholder: String,
    #[props(default)] disabled: bool,
    #[props(default)] required: bool,
    oninput: EventHandler<String>,
) -> Element {
    let mut visible = use_signal(|| false);

    rsx! {
        div { class: "form-field",
            label { class: "form-label",
                "{label}"
                if required {
                    span { class: "form-required", " *" }
                }
            }
            div { class: "password-wrapper",
                input {
                    class: "text-input password-input",
                    r#type: if visible() { "text" } else { "password" },
                    placeholder: "{placeholder}",
                    value: "{value}",
                    disabled,
                    oninput: move |evt| oninput.call(evt.value()),
                }
                button {
                    class: "password-toggle ghost-button",
                    r#type: "button",
                    onclick: move |_| visible.set(!visible()),
                    if visible() { "Hide" } else { "Show" }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TagsField
// ---------------------------------------------------------------------------

#[component]
pub fn TagsField(
    label: String,
    tags: Vec<String>,
    #[props(default)] placeholder: String,
    #[props(default)] disabled: bool,
    onchange: EventHandler<Vec<String>>,
) -> Element {
    let mut input_value = use_signal(String::new);

    rsx! {
        div { class: "form-field",
            label { class: "form-label", "{label}" }
            div { class: "tags-container",
                {tags.iter().enumerate().map(|(idx, tag)| {
                    let tag_display = tag.clone();
                    let tags_clone = tags.clone();
                    rsx! {
                        span { class: "tag-chip", key: "{idx}-{tag_display}",
                            "{tag_display}"
                            button {
                                class: "tag-remove",
                                r#type: "button",
                                disabled,
                                onclick: move |_| {
                                    let mut new_tags = tags_clone.clone();
                                    new_tags.remove(idx);
                                    onchange.call(new_tags);
                                },
                                "x"
                            }
                        }
                    }
                })}
            }
            input {
                class: "text-input",
                placeholder: if placeholder.is_empty() { "Press Enter to add a tag".to_string() } else { placeholder.clone() },
                value: "{input_value}",
                disabled,
                oninput: move |evt| input_value.set(evt.value()),
                onkeypress: move |evt: KeyboardEvent| {
                    if evt.key() == Key::Enter {
                        let val = input_value().trim().to_string();
                        if !val.is_empty() {
                            let mut new_tags = tags.clone();
                            new_tags.push(val);
                            onchange.call(new_tags);
                            input_value.set(String::new());
                        }
                    }
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Inline CSS for form field components
// ---------------------------------------------------------------------------

pub const FORM_FIELDS_CSS: &str = r#"
.form-field {
  display: grid;
  gap: 6px;
  margin-bottom: 16px;
}

.form-field-toggle {
  display: flex;
  align-items: center;
  gap: 12px;
}

.form-label {
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: var(--text);
}

.form-required {
  color: var(--danger);
}

.form-textarea {
  min-height: 80px;
  resize: vertical;
  font-family: inherit;
}

.form-json {
  font-family: "IBM Plex Mono", Consolas, monospace;
  font-size: 13px;
  line-height: 1.5;
}

.json-invalid-border {
  border-color: var(--danger) !important;
}

.form-json-status {
  font-size: 12px;
  padding: 4px 8px;
  border-radius: 8px;
  display: inline-block;
  width: fit-content;
}

.json-valid {
  background: rgba(35, 123, 86, 0.1);
  color: var(--success);
}

.json-invalid {
  background: rgba(166, 54, 54, 0.1);
  color: var(--danger);
}

.form-select {
  appearance: auto;
  cursor: pointer;
}

.toggle-track {
  width: 44px;
  height: 24px;
  border-radius: 12px;
  background: rgba(16, 37, 61, 0.18);
  position: relative;
  cursor: pointer;
  transition: background 200ms ease;
  flex-shrink: 0;
}

.toggle-track.toggle-on {
  background: var(--success);
}

.toggle-thumb {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: #fff;
  position: absolute;
  top: 3px;
  left: 3px;
  transition: transform 200ms ease;
  box-shadow: 0 1px 3px rgba(0,0,0,0.2);
}

.toggle-on .toggle-thumb {
  transform: translateX(20px);
}

.password-wrapper {
  display: flex;
  gap: 8px;
  align-items: stretch;
}

.password-input {
  flex: 1;
}

.password-toggle {
  padding: 8px 12px !important;
  white-space: nowrap;
  font-size: 13px;
}

.tags-container {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.tag-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  border-radius: 12px;
  background: var(--surface-soft);
  font-size: 13px;
  color: var(--text);
}

.tag-remove {
  background: none;
  border: none;
  cursor: pointer;
  color: var(--text-soft);
  font-size: 13px;
  padding: 0 2px;
  line-height: 1;
}

.tag-remove:hover {
  color: var(--danger);
}
"#;
