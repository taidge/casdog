use dioxus::prelude::*;

/// A simple QR code renderer that generates an HTML table from QR data.
///
/// This component can work in two modes:
/// 1. `data_url` is provided: renders an `<img>` tag directly.
/// 2. `matrix` is provided: renders a table of black/white cells.
///
/// For TOTP setup, the server typically returns an `otpauth://` URI or a
/// base64-encoded PNG. This component handles both.

pub const QR_CODE_CSS: &str = r#"
.qr-container {
  display: inline-flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  padding: 20px;
  border: 1px solid var(--line);
  border-radius: 18px;
  background: #fff;
}

.qr-container img {
  image-rendering: pixelated;
  border-radius: 4px;
}

.qr-table {
  border-collapse: collapse;
  border: 4px solid #fff;
}

.qr-table td {
  width: 6px;
  height: 6px;
  padding: 0;
}

.qr-cell-dark {
  background: #10253d;
}

.qr-cell-light {
  background: #fff;
}

.qr-label {
  font-size: 12px;
  color: var(--text-soft);
  text-align: center;
  word-break: break-all;
  max-width: 280px;
}

.qr-fallback {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 200px;
  height: 200px;
  background: var(--surface-soft);
  border-radius: 14px;
  color: var(--text-soft);
  font-size: 14px;
  text-align: center;
  padding: 16px;
}
"#;

/// QR code display component.
///
/// Props:
/// * `data_url` - A data URI (e.g. `data:image/png;base64,...`) or HTTP URL to
///   a QR code image.
/// * `matrix` - A 2D boolean matrix where `true` = dark module. Used for
///   rendering an HTML-table-based QR code when no image is available.
/// * `label` - Optional text shown below the QR code (e.g. the `otpauth://` URI).
/// * `size` - Width/height in pixels for the image mode. Default 200.
#[component]
pub fn QrCode(
    #[props(default)] data_url: String,
    #[props(default)] matrix: Vec<Vec<bool>>,
    #[props(default)] label: String,
    #[props(default = 200)] size: u32,
) -> Element {
    let has_image = !data_url.is_empty();
    let has_matrix = !matrix.is_empty();

    rsx! {
        style { "{QR_CODE_CSS}" }

        div { class: "qr-container",
            if has_image {
                img {
                    src: "{data_url}",
                    width: "{size}",
                    height: "{size}",
                    alt: "QR Code",
                }
            } else if has_matrix {
                {render_matrix_table(&matrix)}
            } else {
                div { class: "qr-fallback",
                    "QR code not available. Use the setup key below instead."
                }
            }

            if !label.is_empty() {
                p { class: "qr-label", "{label}" }
            }
        }
    }
}

fn render_matrix_table(matrix: &[Vec<bool>]) -> Element {
    rsx! {
        table { class: "qr-table",
            {matrix.iter().enumerate().map(|(row_idx, row)| {
                rsx! {
                    tr { key: "qr-row-{row_idx}",
                        {row.iter().enumerate().map(|(col_idx, &dark)| {
                            rsx! {
                                td {
                                    key: "qr-cell-{row_idx}-{col_idx}",
                                    class: if dark { "qr-cell-dark" } else { "qr-cell-light" },
                                }
                            }
                        })}
                    }
                }
            })}
        }
    }
}

/// Helper: Build a QR code image component from a base64-encoded PNG string.
#[component]
pub fn QrCodeFromBase64(
    base64_png: String,
    #[props(default)] label: String,
    #[props(default = 200)] size: u32,
) -> Element {
    let data_url = if base64_png.starts_with("data:") {
        base64_png.clone()
    } else {
        format!("data:image/png;base64,{base64_png}")
    };

    rsx! {
        QrCode {
            data_url,
            label,
            size,
        }
    }
}
