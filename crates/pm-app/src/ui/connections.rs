use eframe::egui::{self, RichText};
use pm_core::rules::file_name;
use pm_core::tracker::{ConnSnapshot, ConnStatus};

use super::{GREEN, ProxyManagerApp, RED};
use crate::model;

fn table(ui: &mut egui::Ui, id: &str, rows: &[ConnSnapshot]) {
    egui::Grid::new(id)
        .striped(true)
        .num_columns(8)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            for title in [
                "Процесс",
                "PID",
                "Назначение",
                "Прокси",
                "Правило",
                "Статус",
                "↑ / ↓",
                "Время",
            ] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for c in rows {
                let process = c.meta.process.as_deref().map_or("?", file_name);
                ui.label(process)
                    .on_hover_text(c.meta.process.as_deref().unwrap_or("неизвестно"));
                ui.label(c.meta.pid.map_or("—".to_string(), |p| p.to_string()));
                ui.monospace(c.meta.target.to_string());
                ui.label(c.meta.proxy.as_ref());
                ui.label(c.meta.rule.as_deref().unwrap_or("по умолчанию"));
                match &c.status {
                    ConnStatus::Failed(reason) => {
                        ui.colored_label(RED, "ошибка").on_hover_text(reason);
                    }
                    ConnStatus::Open => {
                        ui.colored_label(GREEN, c.status.label());
                    }
                    other => {
                        ui.label(other.label());
                    }
                }
                ui.label(format!(
                    "{} / {}",
                    model::format_bytes(c.up),
                    model::format_bytes(c.down)
                ));
                ui.label(model::format_duration(c.duration));
                ui.end_row();
            }
        });
}

impl ProxyManagerApp {
    pub(super) fn connections_tab(&mut self, ui: &mut egui::Ui) {
        let snap = self.ctl.tracker().snapshot();
        let status = self.ctl.status();
        ui.horizontal(|ui| {
            ui.label(format!(
                "Активных: {} · всего: {} · ошибок: {} · отправлено {} · получено {} · записей NAT: {}",
                snap.active.len(),
                snap.total_connections,
                snap.failed_connections,
                model::format_bytes(snap.total_up),
                model::format_bytes(snap.total_down),
                status.nat_entries,
            ));
            if ui.button("Очистить историю").clicked() {
                self.ctl.tracker().clear_history();
            }
        });
        ui.separator();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::CollapsingHeader::new(format!("Активные ({})", snap.active.len()))
                    .default_open(true)
                    .show(ui, |ui| {
                        if snap.active.is_empty() {
                            ui.weak("Нет активных соединений через прокси.");
                        } else {
                            table(ui, "active", &snap.active);
                        }
                    });
                egui::CollapsingHeader::new(format!("Завершённые ({})", snap.recent.len()))
                    .default_open(true)
                    .show(ui, |ui| {
                        if snap.recent.is_empty() {
                            ui.weak("Пока пусто.");
                        } else {
                            table(ui, "recent", &snap.recent);
                        }
                    });
            });
    }
}
