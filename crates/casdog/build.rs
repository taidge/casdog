fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let manifest_path = std::path::Path::new(&manifest_dir);

    // Search candidates in order:
    // 1. Dioxus configured dist directory
    // 2. Dioxus default target output
    // 3. cargo package:     target/package/casdog-0.1.0/ -> ../../../web/dist
    // 4. cargo install:     local web-dist/ bundled in published crate
    let candidates = [
        manifest_path.join("../../web/dist"),
        manifest_path.join("../../web/target/dx/casdog-web/debug/web/public"),
        manifest_path.join("../../web/target/dx/casdog-web/release/web/public"),
        manifest_path.join("../../../web/dist"),
        manifest_path.join("web-dist"),
    ];

    let dist_path = candidates
        .iter()
        .find(|p| p.exists())
        .map(|p| p.canonicalize().unwrap())
        .unwrap_or_else(|| {
            let fallback_dir = std::path::Path::new(&out_dir).join("casdog-web-fallback");
            std::fs::create_dir_all(&fallback_dir).unwrap();
            std::fs::write(
                fallback_dir.join("index.html"),
                r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Casdog</title>
    <style>
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background: linear-gradient(135deg, #132238, #243b53 55%, #d9c7a1);
        color: #f7f4ed;
        font-family: "Segoe UI", sans-serif;
      }
      main {
        width: min(720px, calc(100vw - 32px));
        padding: 32px;
        border-radius: 24px;
        background: rgba(13, 20, 33, 0.78);
        box-shadow: 0 28px 80px rgba(0, 0, 0, 0.35);
      }
      h1 { margin-top: 0; }
      p { line-height: 1.5; color: #d6d3cb; }
      code {
        padding: 2px 6px;
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.12);
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Casdog frontend is not bundled yet</h1>
      <p>
        Build the Dioxus app in <code>web/</code> to replace this fallback page.
        The backend still starts and serves API routes normally.
      </p>
    </main>
  </body>
</html>"#,
            )
            .unwrap();
            fallback_dir
        });

    println!("cargo:rustc-env=CASDOG_WEB_DIST={}", dist_path.display());
    println!("cargo:rerun-if-changed=../../web/dist");
    println!("cargo:rerun-if-changed=../../web/src");
    println!("cargo:rerun-if-changed=../../web/Cargo.toml");
    println!("cargo:rerun-if-changed=web-dist");
}
