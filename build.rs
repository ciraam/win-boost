use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=app.admin.manifest");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    if target_os == "windows" && target_env == "msvc" {
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let manifest_file = if env::var("CARGO_FEATURE_UAC_ADMIN").is_ok() {
            manifest_dir.join("app.admin.manifest")
        } else {
            manifest_dir.join("app.manifest")
        };

        // Embarque le manifeste Windows natif (DPI awareness, compatibilité Win10/11 et niveau UAC)
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
            manifest_file.display()
        );
    }
}
