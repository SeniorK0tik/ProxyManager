//! Proxy Manager application: controller, platform glue and the egui front-end.

pub mod controller;
pub mod icon;
pub mod model;
pub mod paths;
pub mod platform;
pub mod processes;
#[cfg(test)]
mod testing;
#[cfg(windows)]
pub mod tray;
pub mod ui;

use std::sync::Arc;

use platform::Platform;

/// The interception backend for the current OS.
pub fn native_platform() -> Arc<dyn Platform> {
    #[cfg(windows)]
    return Arc::new(platform::WindowsPlatform::new(paths::windivert_dir()));
    #[cfg(not(windows))]
    Arc::new(platform::UnsupportedPlatform)
}
