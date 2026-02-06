fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = std::path::Path::new(&manifest_dir);

    // Workspace-relative path (normal development build)
    let workspace_dist = manifest_path.join("../../web/dist");
    // Crate-local path (cargo publish package)
    let local_dist = manifest_path.join("web-dist");

    let dist_path = if workspace_dist.exists() {
        workspace_dist.canonicalize().unwrap()
    } else if local_dist.exists() {
        local_dist.canonicalize().unwrap()
    } else {
        panic!(
            "web dist not found at {:?} or {:?}",
            workspace_dist, local_dist
        );
    };

    println!("cargo:rustc-env=CASDOG_WEB_DIST={}", dist_path.display());
    println!("cargo:rerun-if-changed=../../web/dist");
    println!("cargo:rerun-if-changed=web-dist");
}
