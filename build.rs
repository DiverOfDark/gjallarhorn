// rust-embed needs web/dist to exist at compile time. Create a stub when the
// frontend hasn't been built yet so `cargo build` works on a fresh checkout.
fn main() {
    let dist = std::path::Path::new("web/dist");
    if !dist.join("index.html").exists() {
        std::fs::create_dir_all(dist).unwrap();
        std::fs::write(dist.join("index.html"), "<!doctype html><p>Frontend not built. Run <code>npm run build</code> in web/ and rebuild.</p>").unwrap();
    }
    println!("cargo:rerun-if-changed=web/dist");
}
