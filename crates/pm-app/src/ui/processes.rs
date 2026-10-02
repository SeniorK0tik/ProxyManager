use eframe::egui::{self, RichText};

use super::{ProxyManagerApp, Tab};
use crate::{model, processes};

impl ProxyManagerApp {
    pub(super) fn processes_tab(&mut self, ui: &mut egui::Ui) {
        if self.processes.is_empty() {
            self.processes = processes::snapshot();
        }
        self.proc_target = self.proc_target.filter(|&i| i < self.draft.rules.len());

        ui.horizontal(|ui| {
            if ui.button("🔄 Обновить").clicked() {
                self.processes = processes::snapshot();
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.proc_filter)
                    .hint_text("поиск по имени или пути"),
            );
            ui.separator();
            ui.label("Добавлять в:");
            let selected = match self.proc_target {
                Some(i) => self.draft.rules[i].name.clone(),
                None => "новое правило".to_string(),
            };
            egui::ComboBox::from_id_salt("proc_target")
                .selected_text(selected)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.proc_target, None, "новое правило");
                    for (i, r) in self.draft.rules.iter().enumerate() {
                        ui.selectable_value(&mut self.proc_target, Some(i), &r.name);
                    }
                });
        });
        ui.weak("«По имени» — любая копия программы, «По пути» — только этот файл.");
        ui.separator();

        let mut add: Option<String> = None;
        let visible = processes::filter(&self.processes, &self.proc_filter);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("processes")
                    .striped(true)
                    .num_columns(4)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("Программа").strong());
                        ui.label(RichText::new("PID").strong());
                        ui.label(RichText::new("Путь").strong());
                        ui.label("");
                        ui.end_row();
                        for entry in visible {
                            ui.label(&entry.name);
                            let pids: Vec<String> =
                                entry.pids.iter().take(3).map(u32::to_string).collect();
                            let more = if entry.pids.len() > 3 {
                                format!(" +{}", entry.pids.len() - 3)
                            } else {
                                String::new()
                            };
                            ui.label(format!("{}{more}", pids.join(", ")));
                            ui.label(RichText::new(entry.path.as_deref().unwrap_or("—")).weak());
                            ui.horizontal(|ui| {
                                if ui.small_button("По имени").clicked() {
                                    add = Some(entry.name.clone());
                                }
                                if entry.path.is_some() && ui.small_button("По пути").clicked()
                                {
                                    add = Some(entry.pattern().to_string());
                                }
                            });
                            ui.end_row();
                        }
                    });
            });

        if let Some(app) = add {
            let rule_index = match self.proc_target {
                Some(i) => {
                    model::add_app(&mut self.draft.rules[i], &app);
                    i
                }
                None => {
                    let rule = model::new_rule(&self.draft, vec![app.clone()]);
                    self.draft.rules.push(rule);
                    self.draft.rules.len() - 1
                }
            };
            self.rule_sel = Some(rule_index);
            self.proc_target = Some(rule_index);
            let name = self.draft.rules[rule_index].name.clone();
            self.notify(
                format!("«{app}» добавлено в правило «{name}». Нажмите «Применить»."),
                false,
            );
            if self.draft.rules[rule_index].apps.len() == 1 {
                self.tab = Tab::Rules;
            }
        }
    }
}
