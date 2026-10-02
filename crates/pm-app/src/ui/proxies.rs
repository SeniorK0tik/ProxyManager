use eframe::egui::{self, RichText};
use pm_core::config::ProxyKind;

use super::{Check, GREEN, ProxyManagerApp, RED, edit_optional};
use crate::model;

impl ProxyManagerApp {
    pub(super) fn proxies_tab(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("proxy_list")
            .resizable(true)
            .default_size(240.0)
            .show(ui, |ui| self.proxy_list(ui));
        egui::CentralPanel::default().show(ui, |ui| match self.proxy_sel {
            Some(i) if i < self.draft.proxies.len() => self.proxy_editor(ui, i),
            _ => {
                ui.weak("Добавьте прокси-сервер, чтобы направлять через него трафик приложений.");
            }
        });
    }

    fn proxy_list(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("➕ Добавить").clicked() {
                let proxy = model::new_proxy(&self.draft);
                self.draft.proxies.push(proxy);
                self.proxy_sel = Some(self.draft.proxies.len() - 1);
            }
            if let Some(i) = self.proxy_sel.filter(|&i| i < self.draft.proxies.len()) {
                let usage = self.draft.proxy_usage(&self.draft.proxies[i].name);
                let resp = ui
                    .add_enabled(usage.is_empty(), egui::Button::new("🗑"))
                    .on_hover_text("Удалить прокси")
                    .on_disabled_hover_text(format!("Используется: {}", usage.join(", ")));
                if resp.clicked() {
                    self.draft.proxies.remove(i);
                    self.proxy_sel = (!self.draft.proxies.is_empty())
                        .then(|| i.min(self.draft.proxies.len() - 1));
                }
            }
        });
        ui.separator();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (i, p) in self.draft.proxies.iter().enumerate() {
                    let text = format!("{}\n{} {}", p.name, p.kind.label(), p.endpoint());
                    if ui
                        .selectable_label(self.proxy_sel == Some(i), text)
                        .clicked()
                    {
                        self.proxy_sel = Some(i);
                    }
                }
            });
    }

    fn proxy_editor(&mut self, ui: &mut egui::Ui, i: usize) {
        let old_name = self.draft.proxies[i].name.clone();
        let mut name = old_name.clone();
        let show_password = self.show_password;
        egui::Grid::new("proxy_form")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Название:");
                ui.text_edit_singleline(&mut name);
                ui.end_row();

                let p = &mut self.draft.proxies[i];
                ui.label("Тип:");
                egui::ComboBox::from_id_salt("proxy_kind")
                    .selected_text(p.kind.label())
                    .show_ui(ui, |ui| {
                        for kind in ProxyKind::ALL {
                            ui.selectable_value(&mut p.kind, kind, kind.label());
                        }
                    });
                ui.end_row();

                ui.label("Сервер:");
                ui.add(egui::TextEdit::singleline(&mut p.host).hint_text("адрес или домен"));
                ui.end_row();

                ui.label("Порт:");
                ui.add(egui::DragValue::new(&mut p.port).range(1..=65535));
                ui.end_row();

                ui.label("Логин:");
                edit_optional(ui, &mut p.username, false, "без авторизации");
                ui.end_row();

                ui.label("Пароль:");
                ui.horizontal(|ui| {
                    edit_optional(ui, &mut p.password, !show_password, "");
                    ui.checkbox(&mut self.show_password, "показать");
                });
                ui.end_row();
            });
        if name != old_name {
            model::rename_proxy(&mut self.draft, &old_name, &name);
            if let Some(check) = self.checks.remove(&old_name) {
                self.checks.insert(name.clone(), check);
            }
        }

        ui.add_space(10.0);
        let profile = self.draft.proxies[i].clone();
        ui.horizontal(|ui| {
            let running = matches!(self.checks.get(&profile.name), Some(Check::Running(_)));
            let resp = ui
                .add_enabled(
                    !running && !profile.host.trim().is_empty(),
                    egui::Button::new("🔍 Проверить"),
                )
                .on_hover_text(format!(
                    "Открыть туннель через прокси к {} и выполнить HTTP-запрос",
                    pm_core::proxy::CHECK_HOST
                ));
            if resp.clicked() {
                let handle = self.ctl.spawn_check(profile.clone());
                self.checks
                    .insert(profile.name.clone(), Check::Running(handle));
            }
            match self.checks.get(&profile.name) {
                Some(Check::Running(_)) => {
                    ui.spinner();
                    ui.label("проверка…");
                }
                Some(Check::Done(Ok(r))) => {
                    ui.colored_label(
                        GREEN,
                        format!(
                            "✔ работает: туннель за {} мс, ответ за {} мс ({})",
                            r.connect_time.as_millis(),
                            r.total_time.as_millis(),
                            r.status_line
                        ),
                    );
                }
                Some(Check::Done(Err(e))) => {
                    ui.colored_label(RED, format!("✖ {e}"));
                }
                None => {}
            }
        });

        let usage = self.draft.proxy_usage(&profile.name);
        ui.add_space(8.0);
        if usage.is_empty() {
            ui.weak("Пока не используется ни в одном правиле.");
        } else {
            ui.label(RichText::new(format!("Используется: {}", usage.join(", "))).weak());
        }
    }
}
