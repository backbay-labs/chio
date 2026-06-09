//! UniFFI scaffolding generator.
//!
//! Runs at build time to read `src/chio_kernel_mobile.udl` and emit the
//! `extern "C"` shim that `include_scaffolding!` slots into the crate.
//! The generated code is written into `$OUT_DIR`; Cargo's normal build
//! tree invalidation handles re-running this script whenever the UDL
//! changes.
//!
//! The single `unwrap()` below is the standard Cargo `build.rs`
//! convention: scaffolding failure is a compile-time error we want
//! the compiler to surface loudly rather than a runtime branch. The
//! workspace `clippy::unwrap_used = "deny"` lint exempts build scripts
//! per Cargo idiom.

#[allow(clippy::unwrap_used)]
fn main() {
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_ROOT");
    println!("cargo:rerun-if-env-changed=CARGO_NDK_ANDROID_PLATFORM");

    if std::env::var("CARGO_CFG_TARGET_OS").ok().as_deref() == Some("android")
        && std::env::var_os("ANDROID_NDK_HOME").is_none()
        && std::env::var_os("ANDROID_NDK_ROOT").is_none()
        && std::env::var_os("CARGO_NDK_ANDROID_PLATFORM").is_none()
    {
        println!(
            "cargo:warning=chio-kernel-mobile Android builds require a real NDK toolchain; use cargo ndk or set ANDROID_NDK_HOME/ANDROID_NDK_ROOT."
        );
    }

    uniffi::generate_scaffolding("src/chio_kernel_mobile.udl").unwrap();
}
