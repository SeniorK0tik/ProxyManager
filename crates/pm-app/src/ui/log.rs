use eframe::egui::{self, Color32, RichText};
use tracing::Level;

use super::{ProxyManagerApp, RED, YELLOW, open_folder};
use crate::paths;

fn level_color(level: Level) -> Color32 {
    match level {
        Level::ERROR => RED,
        Level::WARN => YELLOW,
        Level::INFO => Color32::GRAY,
        _ => Color32::DARK_GRAY,
    }
}

impl ProxyManagerApp {
    pub(super) fn log_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Уровень:");
            egui::ComboBox::from_id_salt("log_level")
                .selected_text(self.log_level.as_str())
                .show_ui(ui, |ui| {
                    for level in [Level::ERROR, Level::WARN, Level::INFO, Level::DEBUG] {
                        ui.selectable_value(&mut self.log_level, level, level.as_str());
                    }
                });
            if ui.button("Очистить").clicked() {
                self.logs.clear();
            }
            if ui.button("📂 Папка логов").clicked() {
                open_folder(&paths::log_dir());
            }
        });
        ui.separator();
        let lines = self.logs.lines();
        let max = self.log_level;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                // Level ordering in `tracing`: ERROR is the "smallest" verbosity.
                for line in lines.iter().filter(|l| l.level <= max) {
                    let text = format!(
                        "{} {:5} {}",
                        line.time.format("%H:%M:%S"),
                        line.level.as_str(),
                        line.message
                    );
                    ui.label(
                        RichText::new(text)
                            .monospace()
                            .color(level_color(line.level)),
                    );
                }
            });
    }
}
