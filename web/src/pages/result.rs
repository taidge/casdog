use dioxus::prelude::*;
use serde_json::Value;

const RESULT_PAGE_CSS: &str = r#"
.result-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
}

.result-box {
  width: 100%;
  max-width: 480px;
  padding: 40px;
  border: 1px solid var(--line);
  border-radius: 28px;
  background: var(--surface);
  box-shadow: var(--shadow);
  backdrop-filter: blur(18px);
  text-align: center;
  animation: fade-up 320ms ease;
}

.result-icon {
  width: 72px;
  height: 72px;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 36px;
  margin-bottom: 20px;
}

.result-icon.success-icon {
  background: rgba(35, 123, 86, 0.12);
  color: var(--success);
}

.result-icon.failure-icon {
  background: rgba(166, 54, 54, 0.1);
  color: var(--danger);
}

.result-box h2 {
  margin: 0 0 12px;
  font-size: 28px;
  font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
}

.result-box .result-subtitle {
  margin: 0 0 24px;
  color: var(--text-soft);
  line-height: 1.5;
}

.result-details {
  text-align: left;
  margin: 0 0 24px;
  padding: 16px 20px;
  border-radius: 16px;
  background: var(--surface-soft);
}

.result-detail-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
  border-bottom: 1px solid var(--line);
}

.result-detail-row:last-child {
  border-bottom: none;
}

.result-detail-label {
  font-size: 13px;
  color: var(--text-soft);
  font-weight: 600;
  letter-spacing: 0.04em;
}

.result-detail-value {
  font-size: 14px;
  color: var(--text);
  font-family: "IBM Plex Mono", Consolas, monospace;
  word-break: break-all;
}

.result-actions {
  display: flex;
  gap: 12px;
  justify-content: center;
}
"#;

/// Detail row for the result page.
#[derive(Debug, Clone, PartialEq)]
pub struct ResultDetail {
    pub label: String,
    pub value: String,
}

/// Payment/action result page showing success or failure with transaction details.
///
/// Props:
/// * `success` - Whether the action succeeded.
/// * `title` - Optional override for the title (defaults to "Action completed" / "Action failed").
/// * `subtitle` - Optional subtitle / description.
/// * `details` - List of key-value pairs to display.
/// * `raw_response` - Optional raw JSON response to show additional info from.
/// * `on_back` - Called when the "Back to home" button is clicked.
/// * `on_retry` - Called when the "Try again" button is clicked (only shown on failure).
#[component]
pub fn ResultPage(
    #[props(default = true)] success: bool,
    #[props(default)] title: String,
    #[props(default)] subtitle: String,
    #[props(default)] details: Vec<ResultDetail>,
    #[props(default)] raw_response: Option<Value>,
    on_back: EventHandler<()>,
    #[props(default)] on_retry: Option<EventHandler<()>>,
) -> Element {
    let display_title = if title.is_empty() {
        if success {
            "Action completed".to_string()
        } else {
            "Action failed".to_string()
        }
    } else {
        title
    };

    let display_subtitle = if subtitle.is_empty() {
        if success {
            "The operation was completed successfully.".to_string()
        } else {
            "Something went wrong. Please check the details below.".to_string()
        }
    } else {
        subtitle
    };

    // Extract additional details from raw_response if provided
    let mut all_details = details.clone();
    if let Some(ref resp) = raw_response {
        if let Some(obj) = resp.as_object() {
            for (key, value) in obj {
                let display_key = match key.as_str() {
                    "transaction_id" | "transactionId" => "Transaction ID",
                    "amount" => "Amount",
                    "currency" => "Currency",
                    "provider" => "Provider",
                    "order_id" | "orderId" => "Order ID",
                    "status" => "Status",
                    "message" | "msg" => "Message",
                    "created_time" | "createdTime" => "Created",
                    _ => continue,
                };

                let display_value = match value {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => continue,
                };

                // Only add if not already in the details list
                if !all_details.iter().any(|d| d.label == display_key) {
                    all_details.push(ResultDetail {
                        label: display_key.to_string(),
                        value: display_value,
                    });
                }
            }
        }
    }

    rsx! {
        style { "{RESULT_PAGE_CSS}" }

        div { class: "result-page",
            div { class: "result-box",
                // Icon
                div {
                    class: if success { "result-icon success-icon" } else { "result-icon failure-icon" },
                    if success { "+" } else { "!" }
                }

                h2 { "{display_title}" }
                p { class: "result-subtitle", "{display_subtitle}" }

                // Details
                if !all_details.is_empty() {
                    div { class: "result-details",
                        {all_details.iter().map(|detail| {
                            rsx! {
                                div { class: "result-detail-row", key: "{detail.label}",
                                    span { class: "result-detail-label", "{detail.label}" }
                                    span { class: "result-detail-value", "{detail.value}" }
                                }
                            }
                        })}
                    }
                }

                // Actions
                div { class: "result-actions",
                    button {
                        class: "primary-button",
                        onclick: move |_| on_back.call(()),
                        "Back to home"
                    }
                    if !success {
                        if let Some(retry) = &on_retry {
                            button {
                                class: "ghost-button",
                                onclick: move |_| retry.call(()),
                                "Try again"
                            }
                        }
                    }
                }
            }
        }
    }
}
