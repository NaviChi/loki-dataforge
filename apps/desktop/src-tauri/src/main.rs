#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    #[cfg(feature = "cli")]
    {
        if loki_data_forge_cli::should_run_cli(&args) {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let _ = runtime.block_on(loki_data_forge_cli::run_args(args))?;
            return Ok(());
        }
    }

    #[cfg(feature = "gui")]
    {
        ensure_frontend_assets()?;

        tracing_subscriber::fmt()
            .with_env_filter("info")
            .without_time()
            .try_init()
            .ok();

        tauri::Builder::default()
            .plugin(tauri_plugin_fs::init())
            .plugin(tauri_plugin_dialog::init())
            .manage(loki_data_forge_gui::GuiState::default())
            .invoke_handler(tauri::generate_handler![
                loki_data_forge_gui::scan_command,
                loki_data_forge_gui::mount_container_command,
                loki_data_forge_gui::recover_command,
                loki_data_forge_gui::preview_bytes_command,
                loki_data_forge_gui::detect_raid_command,
                loki_data_forge_gui::browse_input_locations_command,
                loki_data_forge_gui::browse_output_location_command,
                loki_data_forge_gui::prompt_missing_raid_dialog_command
            ])
            .run(tauri::generate_context!())
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        return Ok(());
    }

    #[allow(unreachable_code)]
    {
        eprintln!(
            "loki-data-forge was built without GUI support. Rebuild with --features gui or run CLI subcommands."
        );
        Ok(())
    }
}

#[cfg(feature = "gui")]
fn ensure_frontend_assets() -> Result<()> {
    let dist_index = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../dist")
        .join("index.html");

    if !dist_index.exists() {
        anyhow::bail!(
            "Missing frontend assets at {}. Run `cd apps/desktop && npm install && npm run build` first.",
            dist_index.display()
        );
    }

    Ok(())
}
