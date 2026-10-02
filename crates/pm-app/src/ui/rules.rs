use eframe::egui::{self, RichText};

use super::{ProxyManagerApp, Tab, action_combo};
use crate::model;

impl ProxyManagerApp {
    pub(super) fn rules_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Остальные приложения:");
            let cfg = self.draft.clone();
            action_combo(
                ui,
                "default_action",
                &cfg,
                &mut self.draft.general.default_action,
            );
        });
        ui.weak("Правила проверяются сверху вниз, срабатывает первое подходящее.");
        ui.separator();

        egui::Panel::left("rule_list")
            .resizable(true)
            .default_size(260.0)
            .show(ui, |ui| self.rule_list(ui));
        egui::CentralPanel::default().show(ui, |ui| match self.rule_sel {
            Some(i) if i < self.draft.rules.len() => self.rule_editor(ui, i),
            _ => {
                ui.weak("Выберите правило слева или создайте новое.");
            }
        });
    }

    fn rule_list(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("➕ Добавить").clicked() {
                let rule = model::new_rule(&self.draft, Vec::new());
                self.draft.rules.push(rule);
                self.rule_sel = Some(self.draft.rules.len() - 1);
            }
            let sel = self.rule_sel.filter(|&i| i < self.draft.rules.len());
            if ui
                .add_enabled(sel.is_some(), egui::Button::new("⬆"))
                .clicked()
                && let Some(i) = sel
            {
                self.rule_sel = model::move_item(&mut self.draft.rules, i, true).or(sel);
            }
            if ui
                .add_enabled(sel.is_some(), egui::Button::new("⬇"))
                .clicked()
                && let Some(i) = sel
            {
                self.rule_sel = model::move_item(&mut self.draft.rules, i, false).or(sel);
            }
            if ui
                .add_enabled(sel.is_some(), egui::Button::new("🗑"))
                .on_hover_text("Удалить правило")
                .clicked()
                && let Some(i) = sel
            {
                self.draft.rules.remove(i);
                self.rule_sel =
                    (!self.draft.rules.is_empty()).then(|| i.min(self.draft.rules.len() - 1));
            }
        });
        ui.separator();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for i in 0..self.draft.rules.len() {
                    ui.horizontal(|ui| {
                        let rule = &mut self.draft.rules[i];
                        ui.checkbox(&mut rule.enabled, "").on_hover_text("Включено");
                        let text = format!("{}\n{}", rule.name, model::action_label(&rule.action));
                        let label = if rule.enabled {
                            RichText::new(text)
                        } else {
                            RichText::new(text).weak()
                        };
                        if ui
                            .selectable_label(self.rule_sel == Some(i), label)
                            .clicked()
                        {
                            self.rule_sel = Some(i);
                        }
                    });
                }
            });
    }

    fn rule_editor(&mut self, ui: &mut egui::Ui, i: usize) {
        let cfg = self.draft.clone();
        let rule = &mut self.draft.rules[i];
        egui::Grid::new("rule_form")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Название:");
                ui.text_edit_singleline(&mut rule.name);
                ui.end_row();
                ui.label("Включено:");
                ui.checkbox(&mut rule.enabled, "");
                ui.end_row();
                ui.label("Действие:");
                action_combo(ui, "rule_action", &cfg, &mut rule.action);
                ui.end_row();
            });

        ui.add_space(8.0);
        ui.label(RichText::new("Приложения").strong());
        let mut remove = None;
        for (j, app) in rule.apps.iter().enumerate() {
            ui.horizontal(|ui| {
                if ui.small_button("✖").on_hover_text("Убрать").clicked() {
                    remove = Some(j);
                }
                ui.monospace(app);
            });
        }
        if let Some(j) = remove {
            rule.apps.remove(j);
        }
        if rule.apps.is_empty() {
            ui.weak("Пока пусто — добавьте хотя бы одно приложение.");
        }

        ui.add_space(6.0);
        let mut add_now = false;
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.app_input)
                    .hint_text("chrome.exe, C:\\путь\\app.exe или *\\Telegram\\*.exe")
                    .desired_width(360.0),
            );
            add_now |= resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            add_now |= ui.button("Добавить").clicked();
        });
        if add_now {
            let input = std::mem::take(&mut self.app_input);
            model::add_app(&mut self.draft.rules[i], &input);
        }
        ui.horizontal(|ui| {
            #[cfg(windows)]
            if ui.button("📂 Выбрать .exe…").clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .add_filter("Программы", &["exe"])
                    .pick_file()
            {
                model::add_app(&mut self.draft.rules[i], &path.to_string_lossy());
            }
            if ui.button("📋 Из запущенных…").clicked() {
                self.proc_target = Some(i);
                self.tab = Tab::Processes;
            }
        });
        ui.add_space(6.0);
        ui.weak(
            "Имя файла (chrome.exe) совпадает с программой в любой папке. Полный путь — только с конкретным файлом. \
             Символ * заменяет любую последовательность, ? — один символ. Регистр не важен.",
        );
    }
}
