//! egui front-end.

mod connections;
mod log;
mod processes;
mod proxies;
mod rules;
mod settings;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use pm_core::config::Config;
use pm_core::logbuf::LogBuffer;
use pm_core::proxy::{CheckReport, ProxyError};
use tokio::task::JoinHandle;
use tracing::Level;

use crate::controller::{ApplyError, Controller};
use crate::model;
use crate::processes::ProcessEntry;

const NOTICE_TTL: Duration = Duration::from_secs(8);
const GREEN: Color32 = Color32::from_rgb(46, 160, 67);
const RED: Color32 = Color32::from_rgb(220, 70, 60);
const YELLOW: Color32 = Color32::from_rgb(210, 160, 30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Rules,
    Proxies,
    Processes,
    Connections,
    Log,
    Settings,
}

impl Tab {
    const ALL: [Tab; 6] = [
        Tab::Rules,
        Tab::Proxies,
        Tab::Processes,
        Tab::Connections,
        Tab::Log,
        Tab::Settings,
    ];

    fn title(self) -> &'static str {
        match self {
            Tab::Rules => "Правила",
            Tab::Proxies => "Прокси",
            Tab::Processes => "Процессы",
            Tab::Connections => "Соединения",
            Tab::Log => "Журнал",
            Tab::Settings => "Настройки",
        }
    }
}

enum Check {
    Running(JoinHandle<Result<CheckReport, ProxyError>>),
    Done(Result<CheckReport, String>),
}

struct Notice {
    text: String,
    error: bool,
    at: Instant,
}

/// Start-up options from the command line.
#[derive(Debug, Clone, Copy, Default)]
pub struct AppOptions {
    pub start: bool,
    pub minimized: bool,
    pub elevated: bool,
    /// Create the tray icon (disabled in headless tests).
    pub tray: bool,
}

pub struct ProxyManagerApp {
    ctl: Controller,
    draft: Config,
    bypass_text: String,
    bypass_error: Option<String>,
    errors: Vec<String>,
    notice: Option<Notice>,
    tab: Tab,
    rule_sel: Option<usize>,
    proxy_sel: Option<usize>,
    app_input: String,
    processes: Vec<ProcessEntry>,
    proc_filter: String,
    /// Rule to add processes to; `None` creates a new rule.
    proc_target: Option<usize>,
    checks: HashMap<String, Check>,
    logs: Arc<LogBuffer>,
    log_level: Level,
    show_password: bool,
    elevated: bool,
    /// Launch-at-login state (Windows only).
    #[cfg_attr(not(windows), allow(dead_code))]
    autorun: Option<bool>,
    quitting: bool,
    #[cfg(windows)]
    tray: Option<crate::tray::Tray>,
}

impl ProxyManagerApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        ctl: Controller,
        logs: Arc<LogBuffer>,
        opts: AppOptions,
    ) -> Self {
        Self::with_context(&cc.egui_ctx, ctl, logs, opts)
    }

    /// Creates the app for a given egui context (also used by headless UI tests).
    pub fn with_context(
        ctx: &egui::Context,
        ctl: Controller,
        logs: Arc<LogBuffer>,
        opts: AppOptions,
    ) -> Self {
        let draft = ctl.config().clone();
        let errors = ctl
            .config_errors()
            .iter()
            .map(ToString::to_string)
            .collect();
        let mut app = Self {
            bypass_text: model::bypass_to_text(&draft.general.bypass),
            draft,
            ctl,
            bypass_error: None,
            errors,
            notice: None,
            tab: Tab::Rules,
            rule_sel: None,
            proxy_sel: None,
            app_input: String::new(),
            processes: Vec::new(),
            proc_filter: String::new(),
            proc_target: None,
            checks: HashMap::new(),
            logs,
            log_level: Level::INFO,
            show_password: false,
            elevated: opts.elevated,
            autorun: None,
            quitting: false,
            #[cfg(windows)]
            tray: None,
        };
        app.rule_sel = (!app.draft.rules.is_empty()).then_some(0);
        app.proxy_sel = (!app.draft.proxies.is_empty()).then_some(0);

        #[cfg(windows)]
        {
            app.autorun = Some(pm_windows::autorun::is_enabled());
            if opts.tray {
                match crate::tray::Tray::new(ctx.clone()) {
                    Ok(tray) => app.tray = Some(tray),
                    Err(e) => tracing::warn!(error = %e, "tray icon unavailable"),
                }
            }
        }
        if opts.start || app.draft.general.autostart {
            app.start();
        }
        if opts.minimized && app.has_tray() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        app
    }

    fn has_tray(&self) -> bool {
        #[cfg(windows)]
        return self.tray.is_some();
        #[cfg(not(windows))]
        false
    }

    fn notify(&mut self, text: impl Into<String>, error: bool) {
        self.notice = Some(Notice {
            text: text.into(),
            error,
            at: Instant::now(),
        });
    }

    fn dirty(&self) -> bool {
        &self.draft != self.ctl.config()
    }

    fn start(&mut self) {
        match self.ctl.start() {
            Ok(()) => self.notify("Проксирование запущено", false),
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "failed to start");
                self.notify(format!("Не удалось запустить: {e:#}"), true);
            }
        }
    }

    fn toggle(&mut self) {
        if self.ctl.is_running() {
            self.ctl.stop();
            self.notify("Проксирование остановлено", false);
        } else {
            self.start();
        }
    }

    fn apply(&mut self) {
        if let Some(err) = &self.bypass_error {
            let msg = format!("Исправьте список исключений: {err}");
            self.notify(msg, true);
            return;
        }
        match self.ctl.apply(self.draft.clone()) {
            Ok(()) => {
                self.errors.clear();
                self.notify("Настройки применены и сохранены", false);
            }
            Err(ApplyError::Invalid(errors)) => {
                self.errors = errors.iter().map(ToString::to_string).collect();
                self.notify("В настройках есть ошибки — см. список выше", true);
            }
            Err(e @ ApplyError::Save(_)) => {
                self.errors.clear();
                self.notify(e.to_string(), true);
            }
        }
    }

    fn revert(&mut self) {
        self.draft = self.ctl.config().clone();
        self.bypass_text = model::bypass_to_text(&self.draft.general.bypass);
        self.bypass_error = None;
        self.errors.clear();
        self.rule_sel = self.rule_sel.filter(|&i| i < self.draft.rules.len());
        self.proxy_sel = self.proxy_sel.filter(|&i| i < self.draft.proxies.len());
    }

    fn poll_checks(&mut self) {
        let finished: Vec<String> = self
            .checks
            .iter()
            .filter(|(_, c)| matches!(c, Check::Running(h) if h.is_finished()))
            .map(|(k, _)| k.clone())
            .collect();
        for name in finished {
            if let Some(Check::Running(handle)) = self.checks.remove(&name) {
                let result = match self.ctl.join(handle) {
                    Some(Ok(report)) => Ok(report),
                    Some(Err(e)) => Err(e.to_string()),
                    None => Err("проверка прервана".to_string()),
                };
                self.checks.insert(name, Check::Done(result));
            }
        }
    }

    #[cfg(windows)]
    fn show_window(ctx: &egui::Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    /// Background work for a frame: tray commands, close requests, finished checks, repaint scheduling.
    pub fn tick(&mut self, ctx: &egui::Context) {
        #[cfg(windows)]
        {
            let commands = self.tray.as_ref().map(|t| t.poll()).unwrap_or_default();
            for cmd in commands {
                match cmd {
                    crate::tray::TrayCommand::Show => Self::show_window(ctx),
                    crate::tray::TrayCommand::Toggle => self.toggle(),
                    crate::tray::TrayCommand::Quit => {
                        self.quitting = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
            let running = self.ctl.is_running();
            if let Some(tray) = &mut self.tray {
                tray.set_running(running);
            }
        }

        if ctx.input(|i| i.viewport().close_requested())
            && !self.quitting
            && self.draft.general.close_to_tray
            && self.has_tray()
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        self.poll_checks();
        let busy =
            self.ctl.is_running() || self.checks.values().any(|c| matches!(c, Check::Running(_)));
        if busy
            || self
                .notice
                .as_ref()
                .is_some_and(|n| n.at.elapsed() < NOTICE_TTL)
        {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }

    /// Draws the whole window.
    pub fn draw(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("header").show(ui, |ui| self.header(ui));
        egui::Panel::bottom("footer").show(ui, |ui| self.footer(ui));
        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Rules => self.rules_tab(ui),
            Tab::Proxies => self.proxies_tab(ui),
            Tab::Processes => self.processes_tab(ui),
            Tab::Connections => self.connections_tab(ui),
            Tab::Log => self.log_tab(ui),
            Tab::Settings => self.settings_tab(ui),
        });
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        let status = self.ctl.status();
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let (text, color) = if status.running {
                ("● Работает", GREEN)
            } else {
                ("○ Остановлен", Color32::GRAY)
            };
            ui.label(RichText::new(text).size(18.0).strong().color(color));
            let label = if status.running {
                "Остановить"
            } else {
                "Запустить"
            };
            if ui
                .add(egui::Button::new(RichText::new(label).size(16.0)))
                .clicked()
            {
                self.toggle();
            }
            if let (Some(port), Some(uptime)) = (status.relay_port, status.uptime) {
                ui.separator();
                ui.label(format!(
                    "relay :{port} · {} · перенаправлено {} · заблокировано TCP {} / UDP {}",
                    model::format_duration(uptime),
                    status.engine.redirected,
                    status.engine.blocked_tcp,
                    status.engine.blocked_udp
                ));
            }
        });

        if !self.elevated && cfg!(windows) {
            ui.horizontal(|ui| {
                ui.colored_label(YELLOW, "⚠ Программа запущена без прав администратора — перехват трафика не запустится.");
                #[cfg(windows)]
                if ui.button("Перезапустить от имени администратора").clicked()
                    && let Ok(exe) = std::env::current_exe()
                {
                    match pm_windows::elevation::relaunch_elevated(&exe, "") {
                        Ok(()) => {
                            self.quitting = true;
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        Err(e) => self.notify(format!("Не удалось перезапуститься: {e}"), true),
                    }
                }
            });
        }

        if self.dirty() {
            ui.horizontal(|ui| {
                ui.colored_label(YELLOW, "Есть неприменённые изменения");
                if ui.button("Применить").clicked() {
                    self.apply();
                }
                if ui.button("Отменить").clicked() {
                    self.revert();
                }
            });
        }
        for e in &self.errors {
            ui.colored_label(RED, format!("• {e}"));
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            for tab in Tab::ALL {
                ui.selectable_value(&mut self.tab, tab, RichText::new(tab.title()).size(15.0));
            }
        });
        ui.add_space(2.0);
    }

    fn footer(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| match &self.notice {
            Some(n) if n.at.elapsed() < NOTICE_TTL => {
                ui.colored_label(if n.error { RED } else { GREEN }, &n.text);
            }
            _ => {
                let path = self.ctl.config_path().map(Path::display);
                ui.weak(match path {
                    Some(p) => format!("Конфиг: {p}"),
                    None => "Конфиг не сохраняется".to_string(),
                });
            }
        });
    }
}

impl eframe::App for ProxyManagerApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.tick(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.ctl.stop();
    }
}

/// Opens a folder in the system file manager.
fn open_folder(path: &Path) {
    let _ = std::fs::create_dir_all(path);
    let program = if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    if let Err(e) = std::process::Command::new(program).arg(path).spawn() {
        tracing::warn!(error = %e, path = %path.display(), "cannot open folder");
    }
}

/// Edits an optional string; an empty field means `None`.
fn edit_optional(
    ui: &mut egui::Ui,
    value: &mut Option<String>,
    password: bool,
    hint: &str,
) -> bool {
    let mut text = value.clone().unwrap_or_default();
    let changed = ui
        .add(
            egui::TextEdit::singleline(&mut text)
                .password(password)
                .hint_text(hint),
        )
        .changed();
    if changed {
        *value = (!text.is_empty()).then_some(text);
    }
    changed
}

/// Drop-down with all available actions.
fn action_combo(ui: &mut egui::Ui, id: &str, cfg: &Config, action: &mut pm_core::config::Action) {
    let choices = model::action_choices(cfg);
    egui::ComboBox::from_id_salt(id)
        .width(260.0)
        .selected_text(model::action_label(action))
        .show_ui(ui, |ui| {
            for choice in choices {
                let label = model::action_label(&choice);
                ui.selectable_value(action, choice, label);
            }
        });
}
