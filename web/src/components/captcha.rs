use dioxus::prelude::*;

/// Simple CAPTCHA widget that displays a server-generated challenge and
/// collects the user's answer. The parent component supplies the captcha
/// image/text URL and receives the verified result.
///
/// Flow:
///  1. On mount (and on refresh), fetch a captcha challenge from the API.
///  2. Display the challenge image (or fallback text).
///  3. User enters the code; parent is notified via `on_verified`.

pub const CAPTCHA_CSS: &str = r#"
.captcha-widget {
  display: grid;
  gap: 12px;
  padding: 16px;
  border: 1px solid var(--line);
  border-radius: 18px;
  background: var(--surface);
}

.captcha-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.captcha-header h4 {
  margin: 0;
  font-size: 15px;
}

.captcha-display {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 64px;
  padding: 12px;
  border-radius: 14px;
  background: rgba(16, 37, 61, 0.04);
  user-select: none;
}

.captcha-display img {
  max-height: 64px;
  border-radius: 8px;
}

.captcha-text-challenge {
  font-family: "IBM Plex Mono", Consolas, monospace;
  font-size: 28px;
  letter-spacing: 0.3em;
  color: var(--text);
  text-decoration: line-through;
  font-style: italic;
}

.captcha-input-row {
  display: flex;
  gap: 8px;
  align-items: stretch;
}

.captcha-input-row input {
  flex: 1;
}

.captcha-message {
  font-size: 13px;
  padding: 6px 10px;
  border-radius: 10px;
}

.captcha-message.ok {
  background: rgba(35, 123, 86, 0.1);
  color: var(--success);
}

.captcha-message.fail {
  background: rgba(166, 54, 54, 0.1);
  color: var(--danger);
}
"#;

#[derive(Debug, Clone, PartialEq)]
pub enum CaptchaMode {
    /// Use an image URL returned by the server.
    Image,
    /// Use a text-based challenge (fallback when image is unavailable).
    Text,
}

impl Default for CaptchaMode {
    fn default() -> Self {
        CaptchaMode::Text
    }
}

/// CaptchaWidget props.
///
/// * `api_base` / `token` - for fetching the challenge from the server.
/// * `captcha_url` - optional override URL; if empty, uses `/api/captcha`.
/// * `on_verified` - called with (captcha_token, user_answer) when the user submits.
#[component]
pub fn CaptchaWidget(
    api_base: Signal<String>,
    token: Signal<Option<String>>,
    #[props(default)] captcha_url: String,
    on_verified: EventHandler<(String, String)>,
) -> Element {
    let mut captcha_id = use_signal(String::new);
    let mut challenge_image = use_signal(String::new);
    let mut challenge_text = use_signal(String::new);
    let mut mode = use_signal(|| CaptchaMode::Text);
    let mut user_input = use_signal(String::new);
    let mut loading = use_signal(|| false);
    let mut message = use_signal(|| None::<(bool, String)>);
    let mut refresh_count = use_signal(|| 0_u64);

    // Fetch captcha challenge
    {
        let api_base_val = api_base();
        let token_val = token();
        let url_override = captcha_url.clone();
        let _nonce = refresh_count();

        use_effect(move || {
            let api_base_val = api_base_val.clone();
            let token_val = token_val.clone();
            let url_override = url_override.clone();

            spawn(async move {
                loading.set(true);
                message.set(None);
                user_input.set(String::new());

                let endpoint = if url_override.is_empty() {
                    "/api/captcha"
                } else {
                    &url_override
                };
                let url = crate::api::build_url(&api_base_val, endpoint);

                match crate::api::request_json("GET", &url, token_val.as_deref(), None).await {
                    Ok(value) => {
                        // Server may return { captchaId, captchaImage } or { id, text }
                        let id = value
                            .get("captchaId")
                            .or_else(|| value.get("id"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        captcha_id.set(id);

                        if let Some(img) = value
                            .get("captchaImage")
                            .or_else(|| value.get("image"))
                            .and_then(|v| v.as_str())
                        {
                            challenge_image.set(img.to_string());
                            challenge_text.set(String::new());
                            mode.set(CaptchaMode::Image);
                        } else if let Some(text) = value
                            .get("captchaText")
                            .or_else(|| value.get("text"))
                            .and_then(|v| v.as_str())
                        {
                            challenge_text.set(text.to_string());
                            challenge_image.set(String::new());
                            mode.set(CaptchaMode::Text);
                        } else {
                            // Generate a local pseudo-challenge for demonstration
                            challenge_text.set(generate_local_challenge());
                            mode.set(CaptchaMode::Text);
                        }
                    }
                    Err(_) => {
                        // Fallback: generate a local text challenge
                        captcha_id.set("local".to_string());
                        challenge_text.set(generate_local_challenge());
                        mode.set(CaptchaMode::Text);
                    }
                }

                loading.set(false);
            });
        });
    }

    rsx! {
        style { "{CAPTCHA_CSS}" }

        div { class: "captcha-widget",
            div { class: "captcha-header",
                h4 { "Verification" }
                button {
                    class: "ghost-button",
                    r#type: "button",
                    disabled: loading(),
                    onclick: move |_| refresh_count.set(refresh_count() + 1),
                    "New code"
                }
            }

            div { class: "captcha-display",
                if loading() {
                    span { "Loading..." }
                } else {
                    match mode() {
                        CaptchaMode::Image => {
                            let src = challenge_image();
                            rsx! {
                                if src.starts_with("data:") || src.starts_with("http") {
                                    img { src: "{src}", alt: "CAPTCHA" }
                                } else {
                                    // Treat as base64 PNG
                                    img { src: "data:image/png;base64,{src}", alt: "CAPTCHA" }
                                }
                            }
                        }
                        CaptchaMode::Text => {
                            rsx! {
                                span { class: "captcha-text-challenge", "{challenge_text}" }
                            }
                        }
                    }
                }
            }

            div { class: "captcha-input-row",
                input {
                    class: "text-input",
                    r#type: "text",
                    placeholder: "Enter the code above",
                    value: "{user_input}",
                    disabled: loading(),
                    oninput: move |evt| user_input.set(evt.value()),
                    onkeypress: move |evt: KeyboardEvent| {
                        if evt.key() == Key::Enter {
                            let answer = user_input().trim().to_string();
                            let id = captcha_id();
                            if !answer.is_empty() {
                                on_verified.call((id, answer));
                            }
                        }
                    },
                }
                button {
                    class: "primary-button",
                    r#type: "button",
                    disabled: loading() || user_input().trim().is_empty(),
                    onclick: move |_| {
                        let answer = user_input().trim().to_string();
                        let id = captcha_id();
                        if !answer.is_empty() {
                            on_verified.call((id, answer));
                        }
                    },
                    "Verify"
                }
            }

            if let Some((ok, msg)) = message() {
                div {
                    class: if ok { "captcha-message ok" } else { "captcha-message fail" },
                    "{msg}"
                }
            }
        }
    }
}

/// Generate a simple local text challenge (6 alphanumeric characters).
/// This is a fallback when the server captcha endpoint is not available.
fn generate_local_challenge() -> String {
    // Use a simple deterministic-looking string since we don't have `rand` in WASM.
    // In production the server would provide the challenge.
    let now = now_millis();
    let chars = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut result = String::with_capacity(6);
    let mut seed = now as u64;
    for _ in 0..6 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let idx = ((seed >> 33) as usize) % chars.len();
        result.push(chars[idx] as char);
    }
    result
}

/// Get a simple hash-like seed value from the current timestamp.
/// We avoid external JS interop; instead use a monotonic counter
/// seeded from a known constant so the CAPTCHA varies each refresh.
fn now_millis() -> f64 {
    // In a WASM context without direct js_sys, we use gloo_net's
    // internal time or a static counter. For simplicity, use a
    // thread-local counter incremented on each call to provide
    // variation between refreshes.
    use std::cell::Cell;
    thread_local! {
        static COUNTER: Cell<u64> = const { Cell::new(1) };
    }
    COUNTER.with(|c| {
        let val = c.get();
        c.set(val.wrapping_add(7919)); // prime step for variation
        val as f64
    })
}
