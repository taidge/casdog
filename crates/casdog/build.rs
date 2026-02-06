fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = std::path::Path::new(&manifest_dir);

    // Search candidates in order:
    // 1. Workspace build:   crates/casdog/  -> ../../web/dist
    // 2. cargo package:     target/package/casdog-0.1.0/ -> ../../../web/dist
    // 3. cargo install:     local web-dist/ bundled in published crate
    let candidates = [
        manifest_path.join("../../web/dist"),
        manifest_path.join("../../../web/dist"),
        manifest_path.join("web-dist"),
    ];

    let dist_path = candidates
        .iter()
        .find(|p| p.exists())
        .map(|p| p.canonicalize().unwrap())
        .unwrap_or_else(|| {
            panic!(
                "web dist not found. Checked:\n  {}\n\
                 For cargo publish, copy web assets first: cp -r web/dist crates/casdog/web-dist",
                candidates
                    .iter()
                    .map(|p| format!("{:?}", p))
                    .collect::<Vec<_>>()
                    .join("\n  ")
            );
        });

    println!("cargo:rustc-env=CASDOG_WEB_DIST={}", dist_path.display());
    println!("cargo:rerun-if-changed=../../web/dist");
    println!("cargo:rerun-if-changed=web-dist");
}
