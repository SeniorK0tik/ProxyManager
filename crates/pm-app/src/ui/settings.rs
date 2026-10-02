use eframe::egui::{self, RichText};

use super::{ProxyManagerApp, RED, action_combo, open_folder};
use crate::{model, paths};

impl ProxyManagerApp {
    pub(super) fn settings_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.label(RichText::new("Маршрутизация").strong());
            ui.horizontal(|ui| {
                ui.label("Приложения без правила:");
                let cfg = self.draft.clone();
                action_combo(ui, "settings_default_action", &cfg, &mut self.draft.general.default_action);
            });
            let g = &mut self.draft.general;
            ui.checkbox(&mut g.block_udp, "Блокировать UDP у проксируемых приложений").on_hover_text(
                "UDP через прокси не передаётся. Блокировка не даёт трафику уйти напрямую; \
                 браузеры при этом переключаются с QUIC на TCP.",
            );
            ui.checkbox(&mut g.allow_dns, "Всегда пропускать DNS (UDP порт 53)");
            ui.horizontal(|ui| {
                ui.label("Таймаут подключения к прокси, с:");
                ui.add(egui::DragValue::new(&mut g.connect_timeout_secs).range(1..=300));
            });

            ui.add_space(10.0);
            ui.label(RichText::new("Запуск").strong());
            ui.checkbox(&mut g.autostart, "Включать проксирование при запуске программы");
            ui.checkbox(&mut g.close_to_tray, "Закрытие окна сворачивает в трей");
            #[cfg(windows)]
            if let Some(mut enabled) = self.autorun {
                let resp = ui.checkbox(&mut enabled, "Запускать при входе в Windows (с правами администратора)");
                if resp.changed() {
                    let result = std::env::current_exe()
                        .and_then(|exe| pm_windows::autorun::set_enabled(&exe, enabled));
                    match result {
                        Ok(()) => self.autorun = Some(enabled),
                        Err(e) => self.notify(format!("Не удалось изменить автозапуск: {e}"), true),
                    }
                }
            }

            ui.add_space(10.0);
            ui.label(RichText::new("Исключения").strong());
            ui.weak("Адреса и подсети, трафик к которым никогда не идёт через прокси (по одной в строке).");
            let resp = ui.add(
                egui::TextEdit::multiline(&mut self.bypass_text)
                    .code_editor()
                    .desired_rows(8)
                    .desired_width(320.0),
            );
            if resp.changed() {
                match model::parse_bypass(&self.bypass_text) {
                    Ok(nets) => {
                        self.draft.general.bypass = nets;
                        self.bypass_error = None;
                    }
                    Err(e) => self.bypass_error = Some(e),
                }
            }
            if let Some(err) = &self.bypass_error {
                ui.colored_label(RED, err);
            }
            if ui.button("Вернуть стандартный список").clicked() {
                self.draft.general.bypass = pm_core::config::default_bypass();
                self.bypass_text = model::bypass_to_text(&self.draft.general.bypass);
                self.bypass_error = None;
            }

            ui.add_space(10.0);
            ui.label(RichText::new("Файлы").strong());
            if let Some(path) = self.ctl.config_path() {
                ui.monospace(path.display().to_string());
            }
            if ui.button("📂 Открыть папку настроек").clicked() {
                open_folder(&paths::config_dir());
            }
        });
    }
}
