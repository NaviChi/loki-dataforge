fn main() {
    if std::env::var("CARGO_FEATURE_GUI").is_ok() {
        tauri_build::build();
    }
}
