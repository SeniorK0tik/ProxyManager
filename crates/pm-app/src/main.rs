// No console window in release builds on Windows.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::sync::Arc;

use eframe::egui;
use pm_app::controller::Controller;
use pm_app::paths::{self, Args};
use pm_app::ui::{AppOptions, ProxyManagerApp};
use pm_app::{icon, native_platform};
use pm_core::config::Config;
use pm_core::logbuf::LogBuffer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

fn init_logging(logs: &Arc<LogBuffer>) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let filter = || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let (file_layer, guard) = match std::fs::create_dir_all(paths::log_dir()) {
        Ok(()) => {
            let appender = tracing_appender::rolling::daily(paths::log_dir(), "proxy-manager.log");
            let (writer, guard) = tracing_appender::non_blocking(appender);
            let layer = fmt::layer()
                .with_ansi(false)
                .with_writer(writer)
                .with_filter(filter());
            (Some(layer), Some(guard))
        }
        Err(_) => (None, None),
    };
    tracing_subscriber::registry()
        .with(file_layer)
        .with(logs.layer().with_filter(EnvFilter::new(
            "info,pm_core=debug,pm_windows=debug,pm_app=debug",
        )))
        .init();
    guard
}

fn main() -> anyhow::Result<()> {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    #[cfg(windows)]
    let elevated = pm_windows::elevation::is_elevated();
    #[cfg(not(windows))]
    let elevated = true;

    // WinDivert requires administrator rights: offer to restart elevated.
    #[cfg(windows)]
    if !elevated && !args.no_elevate {
        let exe = std::env::current_exe()?;
        if pm_windows::elevation::relaunch_elevated(&exe, &args.to_command_line()).is_ok() {
            return Ok(());
        }
    }

    let logs = LogBuffer::new(5000);
    let _guard = init_logging(&logs);
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        elevated,
        "Proxy Manager starting"
    );

    let config_path = args
        .config
        .clone()
        .unwrap_or_else(paths::default_config_file);
    let config = match Config::load_or_default(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!(path = %config_path.display(), error = %e, "config could not be read, using defaults");
            Config::default()
        }
    };
    let controller = Controller::new(native_platform(), config, Some(config_path))?;

    let icon = egui::IconData {
        rgba: icon::icon_rgba(64, true),
        width: 64,
        height: 64,
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(format!("Proxy Manager {}", env!("CARGO_PKG_VERSION")))
            .with_inner_size([1040.0, 700.0])
            .with_min_inner_size([760.0, 480.0])
            .with_icon(icon),
        ..Default::default()
    };
    let opts = AppOptions {
        start: args.start,
        minimized: args.minimized,
        elevated,
        tray: true,
    };
    eframe::run_native(
        "Proxy Manager",
        options,
        Box::new(move |cc| Ok(Box::new(ProxyManagerApp::new(cc, controller, logs, opts)))),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {e}"))
}
