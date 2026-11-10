use crate::ui::query_component;
use glory::prelude::*;
pub fn code(scope: &Scope, uri: Cage<String>) -> impl Widget {
    glory::ui::image()
        .source(scope.bond(move || image_source(&uri.get())))
        .alt("Authenticator setup QR code")
        .class("qr-image")
}
fn image_source(value: &str) -> String {
    if !value.starts_with("otpauth://") {
        return value.to_string();
    }
    let Some(matrix) = qr_matrix(value) else {
        return String::new();
    };
    let width = matrix.len();
    let mut path = String::new();
    for (y, row) in matrix.iter().enumerate() {
        let mut x = 0;
        while x < row.len() {
            if !row[x] {
                x += 1;
                continue;
            }
            let start = x;
            while x < row.len() && row[x] {
                x += 1;
            }
            path.push_str(&format!("M{start} {y}h{}v1H{start}z", x - start));
        }
    }
    let svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {width}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="white"/><path d="{path}" fill="black"/></svg>"#
    );
    format!("data:image/svg+xml,{}", query_component(&svg))
}
fn qr_matrix(value: &str) -> Option<Vec<Vec<bool>>> {
    let qr = qrcode::QrCode::new(value.as_bytes()).ok()?;
    let width = qr.width();
    let mut matrix = vec![vec![false; width + 8]; width + 8];
    for y in 0..width {
        for x in 0..width {
            matrix[y + 4][x + 4] = qr[(x, y)] == qrcode::Color::Dark;
        }
    }
    Some(matrix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_setup_is_encoded_locally_with_a_quiet_zone() {
        let matrix = qr_matrix("otpauth://totp/Casdog:alice?secret=JBSWY3DPEHPK3PXP&issuer=Casdog").unwrap();
        assert!(matrix.len() > 21);
        assert!(matrix.iter().all(|row| row.len() == matrix.len()));
        assert!(matrix[..4].iter().flatten().all(|cell| !cell));
        assert!(matrix.iter().all(|row| row[..4].iter().all(|cell| !cell)));
        assert!(matrix.iter().flatten().any(|cell| *cell));
    }
}
